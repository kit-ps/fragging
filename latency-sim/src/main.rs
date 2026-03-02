use std::{
    collections::hash_map::Entry,
    io,
    sync::{LazyLock, Mutex, MutexGuard},
};

use eyre::{Result, bail};
use rand::{
    Rng, SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};
use rand_distr::Exp;
use rustc_hash::{FxHashMap, FxHashSet};

pub type NodeId = u64;
pub type UserId = u64;
pub type Timestamp = u64;

#[derive(Debug, Clone)]
pub struct Message {
    pub id: u64,
    pub sending_time: Timestamp,
    pub recipient: UserId,
    pub sender: UserId,
    pub fragment_set: u64,
    pub fragment_size: u32,
    pub fragment_index: u32,
    pub ack: Box<Packet>,
}

#[derive(Debug, Clone)]
pub struct Ack {
    pub message_id: u64,
    pub recipient: UserId,
}

#[derive(Debug, Clone)]
pub struct PendingAck {
    pub deadline: Timestamp,
    pub id: u64,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub destination: NodeId,
    pub delay: Timestamp,
    pub content: Content,
}

impl Packet {
    pub fn total_delay(&self) -> Timestamp {
        self.delay + match &self.content {
            Content::Packet(p) => p.total_delay(),
            _ => 0,
        }
    }

    pub fn message(&self) -> &Message {
        match &self.content {
            Content::Packet(p) => p.message(),
            Content::Message(m) => m,
            _ => panic!(),
        }
    }

    pub fn message_mut(&mut self) -> &mut Message {
        match &mut self.content {
            Content::Packet(p) => p.message_mut(),
            Content::Message(m) => m,
            _ => panic!(),
        }
    }

    pub fn message_id(&self) -> u64 {
        self.message().id
    }
}

#[derive(Debug, Clone)]
pub enum Content {
    Message(Box<Message>),
    Ack(Box<Ack>),
    Packet(Box<Packet>),
}

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub ingress: Vec<(Timestamp, Packet)>,
}

impl Node {
    pub fn new() -> Node {
        Node {
            ingress: Vec::new(),
        }
    }

    pub fn insert(&mut self, timestamp: Timestamp, packet: Packet) {
        let idx = self
            .ingress
            .partition_point(|x| x.0 <= timestamp);
        self.ingress.insert(idx, (timestamp, packet));
    }

    pub fn next(&self) -> Option<Timestamp> {
        self.ingress.first().map(|x| x.0)
    }

    pub fn pop(&mut self) -> Option<Packet> {
        Some(self.ingress.remove(0).1)
    }
}

#[derive(Debug, Clone)]
pub enum UserEvent {
    Message(Message),
    Egress(Packet),
    AckTimeout(u64),
    SendMessage(u32),
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub events: Vec<(Timestamp, UserEvent)>,
    pub fragments: FxHashMap<u64, FxHashSet<u32>>,
    pub t_first: FxHashMap<u64, Timestamp>,
    pub original_messages: FxHashMap<u64, Message>,
    pub drop_chance: f32,
}

impl User {
    pub fn new() -> User {
        Default::default()
    }

    pub fn insert(&mut self, timestamp: Timestamp, event: UserEvent) {
        let idx = self.events.partition_point(|x| x.0 <= timestamp);
        self.events.insert(idx, (timestamp, event))
    }

    pub fn next(&self) -> Option<Timestamp> {
        self.events.first().map(|x| x.0)
    }

    pub fn pop(&mut self) -> Option<UserEvent> {
        Some(self.events.remove(0).1)
    }

    pub fn mark_fragment(&mut self, set: u64, index: u32) {
        self.fragments.entry(set).or_default().insert(index);
    }

    pub fn fragment_set_size(&self, set: u64) -> u32 {
        self.fragments
            .get(&set)
            .map(|s| s.len() as u32)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy)]
enum Next {
    Node(NodeId),
    User(UserId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStrategy {
    PerFragment,
    WholeMessage,
}

#[derive(Debug, Clone)]
pub struct Simulation {
    pub timestamp: Timestamp,
    pub ack_strat: AckStrategy,
    pub config: Config,
    pub nodes: FxHashMap<NodeId, Node>,
    pub users: FxHashMap<UserId, User>,
    pub delivery_times: Vec<Timestamp>,
    pub first_to_last: Vec<Timestamp>,
    pub next_message_id: u64,
    pub next_fragment_set: u64,
    pub packet_count: u64,
    pub rng: StdRng,
}

impl Simulation {
    pub fn new(ack_strat: AckStrategy, config: Config, seed: [u8; 32]) -> Simulation {
        Simulation {
            timestamp: 0,
            ack_strat,
            config,
            nodes: Default::default(),
            users: Default::default(),
            delivery_times: Default::default(),
            first_to_last: Default::default(),
            next_message_id: 0,
            next_fragment_set: 0,
            packet_count: 0,
            rng: StdRng::from_seed(seed),
        }
    }

    pub fn add_node(&mut self) -> NodeId {
        let next_id = self.nodes.keys().max().map(|x| x + 1).unwrap_or(0);
        self.nodes.insert(next_id, Node::new());
        next_id
    }

    pub fn add_user(&mut self) -> UserId {
        let next_id = self.users.keys().max().map(|x| x + 1).unwrap_or(0);
        self.users.insert(next_id, User::new());
        next_id
    }

    fn next(&self) -> Option<Next> {
        let next_node = self
            .nodes
            .iter()
            .flat_map(|(&node_id, node)| node.next().map(|t| (node_id, t)))
            .min_by_key(|x| x.1);
        let next_user = self
            .users
            .iter()
            .flat_map(|(&user_id, user)| user.next().map(|t| (user_id, t)))
            .min_by_key(|x| x.1);

        match (next_node, next_user) {
            (Some(a), Some(b)) if a.1 < b.1 => Some(Next::Node(a.0)),
            (_, Some(b)) => Some(Next::User(b.0)),
            (Some(a), None) => Some(Next::Node(a.0)),
            (None, None) => None,
        }
    }

    pub fn step(&mut self) -> Result<()> {
        let Some(next) = self.next() else {
            bail!("No more events");
        };

        match next {
            Next::Node(node_id) => {
                let node = self.nodes.get_mut(&node_id).unwrap();
                let timestamp = node.next().unwrap();
                if timestamp < self.timestamp {
                    bail!("Next event is in the past: {:?}", node.pop());
                }
                self.timestamp = timestamp;
                let packet = node.pop().unwrap();
                let inner = packet.content;
                match inner {
                    Content::Message(msg) => {
                        let user = self.users.get_mut(&msg.recipient).unwrap();
                        user.insert(self.timestamp, UserEvent::Message(*msg));
                    }
                    Content::Ack(ack) => {
                        let user = self.users.get_mut(&ack.recipient).unwrap();
                        user.events.retain(|(_, e)| !matches!(e, UserEvent::AckTimeout(id) if *id == ack.message_id));
                    }
                    Content::Packet(pack) => {
                        let node = self.nodes.get_mut(&pack.destination).unwrap();
                        node.insert(self.timestamp + pack.delay, *pack);
                    }
                }
            }

            Next::User(user_id) => {
                let user = self.users.get_mut(&user_id).unwrap();
                let timestamp = user.next().unwrap();
                if timestamp < self.timestamp {
                    bail!("Next event is in the past");
                }
                self.timestamp = timestamp;
                let event = user.pop().unwrap();
                match event {
                    UserEvent::Message(m) => {
                        user.t_first.entry(m.fragment_set).or_insert(self.timestamp);
                        let ack = m.ack;
                        if self.ack_strat == AckStrategy::PerFragment {
                            self.nodes.get_mut(&ack.destination).unwrap().insert(self.timestamp + ack.delay, *ack.clone());
                            self.packet_count += 1;
                        }
                        user.mark_fragment(m.fragment_set, m.fragment_index);
                        if user.fragment_set_size(m.fragment_set) == m.fragment_size {
                            let delivery_time = self.timestamp - m.sending_time;
                            let ftl = self.timestamp - user.t_first[&m.fragment_set];
                            self.delivery_times.push(delivery_time);
                            self.first_to_last.push(ftl);
                            if self.ack_strat == AckStrategy::WholeMessage {
                                self.nodes.get_mut(&ack.destination).unwrap().insert(self.timestamp + ack.delay, *ack);
                                self.packet_count += 1;
                            }
                        }
                    }
                    UserEvent::Egress(packet) => {
                        let node = self.nodes.get_mut(&packet.destination).unwrap();
                        match self.ack_strat {
                            AckStrategy::PerFragment => {
                                let total_delay = packet.total_delay();
                                let timeout = (total_delay as f32 * self.config.ack_multiplier) as u32 + self.config.ack_addition;
                                let user = self.users.get_mut(&user_id).unwrap();
                                user.insert(self.timestamp + timeout as u64, UserEvent::AckTimeout(packet.message_id()));
                                let message = packet.message();
                                user.original_messages.insert(message.id, message.clone());
                            },
                            AckStrategy::WholeMessage => {
                                let total_delay = packet.total_delay();
                                let timeout = (total_delay as f32 * self.config.ack_multiplier) as u32 + self.config.ack_addition;
                                let message = packet.message();
                                match user.original_messages.entry(message.fragment_set) {
                                    Entry::Occupied(_) => {},
                                    Entry::Vacant(v) => {
                                        v.insert(message.clone());
                                        user.insert(self.timestamp + timeout as u64, UserEvent::AckTimeout(message.fragment_set))
                                    },
                                }
                            },
                        }
                        if self.rng.random::<f32>() >= self.users[&user_id].drop_chance {
                            node.insert(self.timestamp + packet.delay, packet);
                        }
                        self.packet_count += 1;
                    }
                    UserEvent::SendMessage(num_frags) => {
                        let packets = self.build_messages(user_id, 1, num_frags);
                        let user = self.users.get_mut(&user_id).unwrap();
                        for packet in packets {
                            user.insert(self.timestamp, UserEvent::Egress(packet));
                        }
                    }
                    UserEvent::AckTimeout(id) => {
                        match self.ack_strat {
                            AckStrategy::PerFragment => {
                                let mut message = user.original_messages.remove(&id).unwrap();
                                message.id = self.next_message_id;
                                self.next_message_id += 1;
                                let ack = Ack {
                                    recipient: user_id,
                                    message_id: message.id,
                                };
                                *message.ack = self.build_packet(Content::Ack(Box::new(ack)));
                                let packet = self.build_packet(Content::Message(Box::new(message)));
                                self.users.get_mut(&user_id).unwrap().insert(self.timestamp, UserEvent::Egress(packet));
                            }
                            AckStrategy::WholeMessage => {
                                let message = user.original_messages.remove(&id).unwrap();
                                // Clear out the old waiting fragments
                                self.users.get_mut(&message.recipient).unwrap().fragments.remove(&message.fragment_set);

                                let packets = self.build_messages(message.sender, message.recipient, message.fragment_size);
                                for mut packet in packets {
                                    packet.message_mut().sending_time = message.sending_time;
                                    self.users.get_mut(&user_id).unwrap().insert(self.timestamp, UserEvent::Egress(packet));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn build_messages(&mut self, sender: UserId, recipient: UserId, num_frags: u32) -> Vec<Packet> {
        let mut packets = Vec::with_capacity(num_frags as usize);

        let fragment_set = self.next_fragment_set;
        self.next_fragment_set += 1;

        for frag in 0..num_frags {
            let id = self.next_message_id;
            self.next_message_id += 1;

            let ack = match self.ack_strat {
                AckStrategy::PerFragment => Ack {
                    recipient: sender,
                    message_id: id,
                },
                AckStrategy::WholeMessage => Ack {
                    recipient: sender,
                    message_id: fragment_set,
                },
            };
            let ack = self.build_packet(Content::Ack(Box::new(ack)));

            let message = Message {
                id,
                recipient,
                sender,
                sending_time: self.timestamp,
                fragment_set,
                fragment_index: frag,
                fragment_size: num_frags,
                ack: Box::new(ack),
            };

            let packet = self.build_packet(Content::Message(Box::new(message)));

            packets.push(packet);
        }

        packets
    }

    pub fn build_packet_with_delays(&mut self, content: Content, mut delays: Vec<Timestamp>) -> Packet {
        let mut c = content;
        let distr_nodes = Uniform::new(0, self.nodes.keys().max().unwrap_or(&0) + 1).unwrap();

        for _ in 0..(self.config.num_hops - 1) {
            let node = distr_nodes.sample(&mut self.rng);
            let delay = delays.pop().unwrap();
            let packet = Packet {
                destination: node,
                delay,
                content: c,
            };
            c = Content::Packet(Box::new(packet));
        }

        let node = distr_nodes.sample(&mut self.rng);
        let delay = delays[0] as Timestamp;
        Packet {
            destination: node,
            delay,
            content: c,
        }
    }

    pub fn build_packet(&mut self, content: Content) -> Packet {
        let delays = self.draw_delays(self.config.num_hops as usize);
        self.build_packet_with_delays(content, delays)
    }

    pub fn draw_delays(&mut self, num: usize) -> Vec<Timestamp> {
        let distr_delay = Exp::new(1.0 / (self.config.delay_per_hop as f32)).unwrap();

        (0..num)
            .map(|_| distr_delay.sample(&mut self.rng) as Timestamp)
            .collect::<Vec<_>>()

    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub delay_per_hop: u32,
    pub num_hops: u32,
    pub ack_addition: u32,
    pub ack_multiplier: f32,
}

fn main() -> Result<()> {
    let mut wtr = csv::Writer::from_writer(io::stdout());
    wtr.write_record(["num_frags", "drop_chance", "ack_strat", "dt_avg", "dt_25", "dt_50", "dt_75", "ftl_avg", "ftl_25", "ftl_50", "ftl_75", "packet_count"])?;

    let wtr = &Mutex::new(wtr);

    rayon::scope_fifo(|s| {
        for num_frags in [2, 3, 4, 5, 6, 7, 8] {
            for drop in [
                0.00,
                0.05,
                0.10,
                0.15,
                0.20,
                0.25,
                0.30,
                0.35,
                0.40,
                0.45,
                0.50,
                0.55,
                0.60,
                0.65,
                0.70,
                //0.75,
                //0.80,
                //0.85,
                //0.90,
                //0.95,
            ] {
                for strat in [AckStrategy::PerFragment, AckStrategy::WholeMessage] {
                    s.spawn_fifo(move |_| {
                        let stats = run(strat, drop, num_frags);
                        let mut wtr = wtr.lock().unwrap();
                        wtr.write_record([
                            num_frags.to_string(),
                            drop.to_string(),
                            format!("{strat:?}"),
                            stats.dt_avg.to_string(),
                            stats.dt_25.to_string(),
                            stats.dt_50.to_string(),
                            stats.dt_75.to_string(),
                            stats.ftl_avg.to_string(),
                            stats.ftl_25.to_string(),
                            stats.ftl_50.to_string(),
                            stats.ftl_75.to_string(),
                            stats.packet_count.to_string(),
                        ]).unwrap();
                        wtr.flush().unwrap();
                    });
                }
            }
        }

        for num_frags in [10, 20, 30, 40, 50] {
            for drop in [0.00, 0.05, 0.10] {
                for strat in [AckStrategy::PerFragment, AckStrategy::WholeMessage] {
                    s.spawn_fifo(move |_| {
                        let stats = run(strat, drop, num_frags);
                        let mut wtr = wtr.lock().unwrap();
                        wtr.write_record([
                            num_frags.to_string(),
                            drop.to_string(),
                            format!("{strat:?}"),
                            stats.dt_avg.to_string(),
                            stats.dt_25.to_string(),
                            stats.dt_50.to_string(),
                            stats.dt_75.to_string(),
                            stats.ftl_avg.to_string(),
                            stats.ftl_25.to_string(),
                            stats.ftl_50.to_string(),
                            stats.ftl_75.to_string(),
                            stats.packet_count.to_string(),
                        ]).unwrap();
                        wtr.flush().unwrap();
                    });
                }
            }
        }

        for num_frags in 1..128 {
            for drop in [0.01, 0.001] {
                for strat in [AckStrategy::PerFragment, AckStrategy::WholeMessage] {
                    s.spawn_fifo(move |_| {
                        let stats = run(strat, drop, num_frags);
                        let mut wtr = wtr.lock().unwrap();
                        wtr.write_record([
                            num_frags.to_string(),
                            drop.to_string(),
                            format!("{strat:?}"),
                            stats.dt_avg.to_string(),
                            stats.dt_25.to_string(),
                            stats.dt_50.to_string(),
                            stats.dt_75.to_string(),
                            stats.ftl_avg.to_string(),
                            stats.ftl_25.to_string(),
                            stats.ftl_50.to_string(),
                            stats.ftl_75.to_string(),
                            stats.packet_count.to_string(),
                        ]).unwrap();
                        wtr.flush().unwrap();
                    });
                }
            }
        }
    });


    Ok(())
}

#[derive(Debug, Clone)]
pub struct Stats {
    pub dt_avg: f32,
    pub dt_25: f32,
    pub dt_50: f32,
    pub dt_75: f32,
    pub ftl_avg: f32,
    pub ftl_25: f32,
    pub ftl_50: f32,
    pub ftl_75: f32,
    pub packet_count: u64,
}

fn run(ack_strat: AckStrategy, drop_chance: f32, num_frags: u32) -> Stats {
    let config = Config {
        delay_per_hop: 50,
        num_hops: 3,
        ack_addition: 1_500,
        ack_multiplier: 1.5,
    };

    let mut sim = Simulation::new(ack_strat, config, rand::rng().random());
    sim.add_node();
    sim.add_node();
    sim.add_node();

    sim.add_user();
    sim.users.get_mut(&0).unwrap().drop_chance = drop_chance;
    sim.add_user();

    for _ in 0..1000 {
        sim.users.get_mut(&0).unwrap().insert(0, UserEvent::SendMessage(num_frags));
    }

    while sim.step().is_ok() {}

    let mut delivery_times: Vec<f32> = sim.delivery_times.into_iter().map(|x| x as f32).collect();
    let mut ftl: Vec<f32> = sim.first_to_last.into_iter().map(|x| x as f32).collect();

    Stats {
        dt_avg: average(&delivery_times),
        dt_25: quantile(&mut delivery_times, 0.25),
        dt_50: quantile(&mut delivery_times, 0.50),
        dt_75: quantile(&mut delivery_times, 0.75),
        ftl_avg: average(&ftl),
        ftl_25: quantile(&mut ftl, 0.25),
        ftl_50: quantile(&mut ftl, 0.50),
        ftl_75: quantile(&mut ftl, 0.75),
        packet_count: sim.packet_count,
    }
}

fn quantile(data: &mut [f32], n: f32) -> f32 {
    data.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = (data.len() as f32 * n) as usize;
    data[idx]
}

fn average(data: &[f32]) -> f32 {
    data.iter().sum::<f32>() / data.len() as f32
}
