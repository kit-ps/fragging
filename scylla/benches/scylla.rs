use criterion::{BatchSize, criterion_group, criterion_main};
use criterion_cputime::CpuTime;
use scylla::{Scylla, Node, ProcessedOnion};

const PATH_LENGTHS: &[u32] = &[1, 2, 3, 4, 5];
const PAYLOAD_SIZES: &[usize] = &[128, 256, 512, 1024];
const FRAGMENT_COUNTS: &[usize] = &[1, 2, 5, 10];

type Criterion<W = CpuTime> = criterion::Criterion<W>;

fn creation(c: &mut Criterion) {
    for &length in PATH_LENGTHS {
        let (_, node) = Node::random(rand::rng());
        let path = vec![node.clone(); length as usize];
        for &payload_size in PAYLOAD_SIZES {
            let scylla = Scylla::new(5, payload_size as u32);
            for &fragment_count in FRAGMENT_COUNTS {
                let paths = vec![path.clone(); fragment_count];
                let mut fragments = Vec::new();
                fragments.push(vec![1u8; payload_size - 4 * 16]);
                for i in 1..fragment_count {
                    fragments.push(vec![i as u8 + 1; payload_size]);
                }
                c.bench_function(
                    &format!("Scylla::create_onions({length}, {payload_size}, {fragment_count})"),
                    |b| {
                        b.iter_batched_ref(
                            || (),
                            |_| {
                                scylla
                                    .create_onions(&paths, &[0; 32], fragments.clone())
                                    .unwrap()
                            },
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
        let scylla = Scylla::new(5, 1024);
        let surb_meta = &[27; 51];
        c.bench_function(&format!("Scylla::create_surb({length})"), |b| {
            b.iter(|| scylla.create_surb(&path, surb_meta));
        });
    }
}

fn processing(c: &mut Criterion) {
    let (private_key, node) = Node::random(rand::rng());
    for &payload_size in PAYLOAD_SIZES {
        let scylla = Scylla::new(5, payload_size as u32);

        let fragments = vec![vec![0u8; payload_size - 4 * 16]];
        let onion = &scylla
            .create_onions(&[&[node, node]], &[0; 32], fragments.clone())
            .unwrap()[0];

        c.bench_function(
            &format!("Scylla::process(Flag::Relay, {payload_size})"),
            |b| {
                b.iter_batched_ref(
                    || (),
                    |_| scylla.process(&private_key, onion).unwrap(),
                    BatchSize::SmallInput,
                );
            },
        );

        let ProcessedOnion::Relay { onion, .. } = scylla.process(&private_key, onion).unwrap()
        else {
            unreachable!()
        };

        c.bench_function(
            &format!("Scylla::process(Flag::Fragment, {payload_size})"),
            |b| {
                b.iter_batched_ref(
                    || (),
                    |_| scylla.process(&private_key, &onion).unwrap(),
                    BatchSize::SmallInput,
                );
            },
        );

        let meta = &[1; 51];
        let (_secrets, surb) = scylla.create_surb(&[node], meta);
        let mut onion = Vec::from(surb);
        onion.extend(vec![2; payload_size]);

        assert!(matches!(
            scylla.process(&private_key, &onion),
            Ok(ProcessedOnion::Reply { .. })
        ));

        c.bench_function(
            &format!("Scylla::process(Flag::Deliver, {payload_size})"),
            |b| {
                b.iter_batched_ref(
                    || (),
                    |_| scylla.process(&private_key, &onion).unwrap(),
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn defrag(c: &mut Criterion) {
    let (private_key, node) = Node::random(rand::rng());
    let path = vec![node.clone()];
    for &payload_size in PAYLOAD_SIZES {
        let scylla = Scylla::new(5, payload_size as u32);
        for &fragment_count in FRAGMENT_COUNTS {
            let paths = vec![path.clone(); fragment_count];
            let mut fragments = Vec::new();
            fragments.push(vec![1u8; payload_size - 4 * 16]);
            for i in 1..fragment_count {
                fragments.push(vec![i as u8 + 1; payload_size]);
            }
            let onions = scylla.create_onions(&paths, &[4; 32], fragments).unwrap();
            assert_eq!(onions.len(), fragment_count);
            let mut onions = onions
                .into_iter()
                .map(|o| scylla.process(&private_key, &o).unwrap())
                .map(|p| {
                    if let ProcessedOnion::Fragment { index, data, .. } = p {
                        (index, data)
                    } else {
                        unreachable!();
                    }
                })
                .collect::<Vec<_>>();
            onions.sort_by_key(|o| o.0);
            let onions = onions.into_iter().map(|x| x.1).collect::<Vec<_>>();
            c.bench_function(
                &format!("Scylla::defrag({payload_size}, {fragment_count})"),
                |b| {
                    b.iter_batched_ref(
                        || (),
                        |_| scylla.defrag(&onions).unwrap(),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = scylla;
    config = Criterion::default()
        .with_measurement(CpuTime);
    targets = creation, processing, defrag
}
criterion_main!(scylla);
