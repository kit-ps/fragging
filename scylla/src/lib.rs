//! Prototype implementation of Scylla, the mix format with fragmentation.
use std::io::Write;

use blake2::VarBlake2b;
use chacha::ChaCha;
use lioness::Lioness;
use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY,
};
use hkdf::Hkdf;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, digest::FixedOutput};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};
use thiserror::Error;

const KAPPA: usize = 16;
const PI_KEY_SIZE: usize = 192;
const ALPHA_LEN: usize = 32;

// These sizes are adjusted to be compatible with Nym:
// https://github.com/nymtech/sphinx/blob/develop/src/constants.rs
// NODE_ADDRESS_LENGTH + DELAY_LENGTH + VERSION_LENGTH
// No need for the flag byte, we also have that in Scylla
const PER_HOP_META_LENGTH: usize = 32 + 8 + 3;
// DESTINATION_ADDRESS_LENGTH
const FINAL_HOP_META_LENGTH: usize = 32;
// DESTINATION_ADDRESS_LENGTH + IDENTIFIER + VERSION_LENGTH
const REPLY_META_LENGTH: usize = 32 + 16 + 3;

pub type Address = [u8; 32];
pub type PerHopMeta = [u8; PER_HOP_META_LENGTH];
pub type FinalHopMeta = [u8; FINAL_HOP_META_LENGTH];
pub type ReplyMeta = [u8; REPLY_META_LENGTH];

#[derive(Error, Debug)]
pub enum Error {
    #[error("fragments are of wrong size")]
    InvalidFragmentSize,
    #[error("wrong number of paths given")]
    InvalidPathCount,
    #[error("integrity check failed")]
    MacMismatch,
    #[error("an invalid header flag has been sent")]
    InvalidHeaderFlag,
    #[error("fragment set is incomplete")]
    MissingFragments,
    #[error("the paths don't end at the same node")]
    DivergingPaths,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub address: Address,
    pub public_key: EdwardsPoint,
}

impl Node {
    pub fn from_private_key(address: Address, private_key: &Scalar) -> Self {
        let public_key = ED25519_BASEPOINT_TABLE * private_key;
        Self {
            address,
            public_key,
        }
    }

    pub fn random<R: Rng>(mut rng: R) -> (Scalar, Node) {
        let private_key = Scalar::from_bytes_mod_order_wide(&rng.random());
        let address = rng.random();
        (private_key, Self::from_private_key(address, &private_key))
    }
}

#[derive(Debug, Clone)]
pub enum ProcessedOnion {
    Relay {
        meta: PerHopMeta,
        onion: Vec<u8>,
    },
    Fragment {
        set_id: u128,
        index: u128,
        data: Vec<u8>,
    },
    Reply {
        meta: ReplyMeta,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Flag {
    Deliver = 0xf0,
    Relay = 0xf1,
    Fragment = 0xf2,
}

fn xor<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: A, b: B) -> Vec<u8> {
    a.as_ref()
        .into_iter()
        .zip(b.as_ref().into_iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn concat<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: A, b: B) -> Vec<u8> {
    a.as_ref()
        .into_iter()
        .chain(b.as_ref().into_iter())
        .copied()
        .collect()
}

// +-----------+ +---+
// |     m     | | r |
// +-----------+ +---+
//       |         |
//      (+)<---G---+  (SHAKE for variable output length)
//       |         |
//       +---H--->(+) (SHA256 truncated)
//       |         |
//       V         V
// +-----------+ +---+
// |     s     | | t |
// +-----------+ +---+
pub fn aont<R: Rng, A: AsRef<[u8]>>(mut rng: R, fragments: &[A]) -> Vec<Vec<u8>> {
    let randomness: [u8; KAPPA] = rng.random();
    let message_length: usize = fragments.iter().map(|x| x.as_ref().len()).sum();

    let mut mask_gen = Shake128::default();
    mask_gen.update(&randomness);
    let mask = mask_gen.finalize_boxed(message_length);
    let mut new_fragments = vec![];
    let mut used_length = 0usize;

    let mut r_mask_gen = Sha256::default();

    for fragment in fragments {
        let fragment = xor(fragment, &mask[used_length..]);
        used_length += fragment.len();
        r_mask_gen.update(&fragment);
        new_fragments.push(fragment);
    }

    let t = xor(randomness, r_mask_gen.finalize_fixed());

    new_fragments[0] = concat(t, &new_fragments[0]);

    new_fragments
}

pub fn aont_inv<A: AsRef<[u8]>>(fragments: &[A]) -> Result<Vec<Vec<u8>>> {
    let mut r_mask_gen = Sha256::default();
    let mut new_fragments = vec![];
    for fragment in fragments {
        new_fragments.push(fragment.as_ref().to_vec());
    }

    let t = new_fragments[0].drain(..KAPPA).collect::<Vec<_>>();

    for fragment in &new_fragments {
        r_mask_gen.update(&fragment);
    }

    let randomness = xor(t, r_mask_gen.finalize_fixed());
    let mut mask_gen = Shake128::default();
    mask_gen.update(&randomness);
    let message_length: usize = fragments.iter().map(|x| x.as_ref().len()).sum::<usize>() - KAPPA;
    let mask = mask_gen.finalize_boxed(message_length);
    let mut used_length = 0usize;

    for fragment in &mut new_fragments {
        *fragment = xor(&fragment, &mask[used_length..]);
        used_length += fragment.len();
    }

    Ok(new_fragments)
}

fn h_b(a: &EdwardsPoint, b: &EdwardsPoint) -> Scalar {
    let mut hasher = Sha512::default();
    hasher.update(b"h_b");
    hasher.update(&a.compress().0);
    hasher.update(&b.compress().0);
    Scalar::from_hash(hasher)
}

fn h_rho(a: &EdwardsPoint) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(b"h_rho");
    hasher.update(&a.compress().0);
    hasher.finalize_fixed().into()
}

fn rho(key: [u8; 32], output: &mut [u8]) {
    let mut rng = ChaCha20Rng::from_seed(key);
    rng.fill_bytes(output);
}

fn h_mu(a: &EdwardsPoint) -> [u8; KAPPA] {
    let mut hasher = Sha256::default();
    hasher.update(b"h_mu");
    hasher.update(&a.compress().0);
    hasher.finalize_fixed()[..KAPPA].try_into().unwrap()
}

fn mu<A: AsRef<[u8]>>(key: &[u8; KAPPA], data: A) -> [u8; KAPPA] {
    let mut hasher = Sha256::default();
    hasher.update(b"mu");
    hasher.update(key);
    hasher.update(data.as_ref());
    hasher.finalize_fixed()[..KAPPA].try_into().unwrap()
}

fn h_pi(a: &EdwardsPoint) -> [u8; PI_KEY_SIZE] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"h_pi"), &a.compress().0);
    let mut output = [0u8; PI_KEY_SIZE];
    hkdf.expand(&[], &mut output).unwrap();
    output
}

fn pi(key: [u8; PI_KEY_SIZE], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let cipher = Lioness::<VarBlake2b, ChaCha>::new_raw(&key);
    let mut output = Vec::from(data);
    cipher.encrypt(&mut output).unwrap();
    output
}

fn pi_inv(key: [u8; PI_KEY_SIZE], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let cipher = Lioness::<VarBlake2b, ChaCha>::new_raw(&key);
    let mut output = Vec::from(data);
    cipher.decrypt(&mut output).unwrap();
    output
}

#[derive(Debug, Clone)]
pub struct Scylla {
    max_path_length: u32,
    payload_size: u32,
}

impl Scylla {
    const BYTES_PER_HOP: usize = PER_HOP_META_LENGTH + KAPPA + 1;

    pub fn new(max_path_length: u32, payload_size: u32) -> Self {
        Scylla {
            max_path_length,
            payload_size,
        }
    }

    pub fn create_onions<A: AsRef<[Node]>>(
        &self,
        paths: &[A],
        destination: &FinalHopMeta,
        mut fragments: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>> {
        if fragments.len() != paths.len() {
            return Err(Error::InvalidPathCount);
        }
        if fragments.is_empty() {
            return Ok(Vec::new());
        }
        if fragments[0].len() + 2*KAPPA + FINAL_HOP_META_LENGTH != self.payload_size as usize {
            return Err(Error::InvalidFragmentSize);
        }
        for fragment in &fragments[1..] {
            if fragment.len() != self.payload_size as usize {
                return Err(Error::InvalidFragmentSize);
            }
        }
        for path in &paths[1..] {
            if path.as_ref().last() != paths[0].as_ref().last() {
                return Err(Error::DivergingPaths);
            }
        }

        let mut rng = rand::rng();

        let auth_bytes = [0u8; KAPPA];
        let mut first_fragment = vec![];
        first_fragment.extend(auth_bytes);
        first_fragment.extend(destination);
        first_fragment.extend(&fragments[0]);
        fragments[0] = first_fragment;

        let transformed = aont(&mut rng, &fragments);

        for fragment in &transformed {
            assert_eq!(fragment.len(), self.payload_size as usize);
        }

        let frag_set_id: [u8; KAPPA] = rng.random();

        let onions = paths
            .iter()
            .zip(transformed.iter())
            .enumerate()
            .map(|(i, (path, payload))| {
                let mut final_info = [0u8; REPLY_META_LENGTH + 1];
                final_info[0] = Flag::Fragment as u8;
                final_info[KAPPA + 1 - usize::BITS as usize / 8..KAPPA + 1]
                    .copy_from_slice(&i.to_be_bytes());
                final_info[KAPPA + 1..2 * KAPPA + 1].copy_from_slice(&frag_set_id);
                self.wrap(path.as_ref(), &final_info, payload).1
            })
            .collect();

        Ok(onions)
    }

    fn wrap(
        &self,
        path: &[Node],
        final_info: &[u8; REPLY_META_LENGTH + 1],
        payload: &[u8],
    ) -> (Vec<EdwardsPoint>, Vec<u8>) {
        let mut rng = rand::rng();
        let secret = Scalar::from_bytes_mod_order_wide(&rng.random());

        let mut shared_secrets = vec![];

        let mut factor = secret;
        let mut alpha = ED25519_BASEPOINT_TABLE * &factor;
        let alpha_zero = alpha;

        for node in path {
            let shared_secret = node.public_key * factor;
            shared_secrets.push(shared_secret);
            let blinding = h_b(&alpha, &shared_secret);
            alpha = alpha * blinding;
            factor = factor * blinding;
        }

        let header_length = self.header_length() as usize;
        let mut filler_string: Vec<u8> = vec![];
        for (i, secret) in shared_secrets[..shared_secrets.len() - 1]
            .iter()
            .enumerate()
        {
            let extended = concat(&filler_string, &[0; Self::BYTES_PER_HOP]);
            let mut buffer = vec![0u8; header_length + Self::BYTES_PER_HOP];
            rho(h_rho(secret), &mut buffer);
            filler_string = xor(extended, &buffer[header_length - i * Self::BYTES_PER_HOP..]);
        }

        let mut buffer = [0u8; REPLY_META_LENGTH + 1];
        rho(h_rho(shared_secrets.last().unwrap()), &mut buffer);

        let mut padding =
            vec![0u8; (self.max_path_length as usize - path.len()) * Self::BYTES_PER_HOP];
        rand::rng().fill_bytes(&mut padding);

        let mut beta = concat(
            &concat(&xor(&final_info, &buffer), &padding),
            &filler_string,
        );

        assert_eq!(beta.len(), header_length);

        let mut buffer = vec![0u8; header_length];

        for i in (0..path.len() - 1).rev() {
            let next_hop = &path[i + 1];
            let next_secret = &shared_secrets[i + 1];
            let shared_secret = &shared_secrets[i];

            let mut info = [0u8; PER_HOP_META_LENGTH + KAPPA + 1];
            info[0] = Flag::Relay as u8;
            info[1..1 + 32].copy_from_slice(&next_hop.address);
            info[1 + PER_HOP_META_LENGTH..].copy_from_slice(&mu(&h_mu(next_secret), &beta));

            rho(h_rho(shared_secret), &mut buffer);
            beta = xor(concat(info, beta), &buffer);

            assert_eq!(beta.len(), header_length);
        }

        let gamma = mu(&h_mu(shared_secrets.first().unwrap()), &beta);

        let mut payload = Vec::from(payload);
        for shared_secret in shared_secrets.iter().rev() {
            payload = pi(h_pi(shared_secret), &payload);
        }

        let mut output = vec![];
        output.write_all(&alpha_zero.compress().0).unwrap();
        output.write_all(&beta).unwrap();
        output.write_all(&gamma).unwrap();
        output.write_all(&payload).unwrap();

        (shared_secrets, output)
    }

    fn header_length(&self) -> u32 {
        Self::BYTES_PER_HOP as u32 * (self.max_path_length - 1) + (1 + REPLY_META_LENGTH as u32)
    }

    pub fn process(&self, private_key: &Scalar, onion: &[u8]) -> Result<ProcessedOnion> {
        let header_length = self.header_length() as usize;

        let alpha = CompressedEdwardsY(onion[0..ALPHA_LEN].try_into().unwrap())
            .decompress()
            .unwrap();
        let shared_secret = alpha * private_key;

        let beta = &onion[ALPHA_LEN..ALPHA_LEN + header_length];

        let expected_gamma = &onion[ALPHA_LEN + header_length..ALPHA_LEN + header_length + KAPPA];
        let my_gamma = mu(&h_mu(&shared_secret), beta);

        if expected_gamma != my_gamma {
            return Err(Error::MacMismatch);
        }

        let mut buffer = vec![0u8; header_length + Self::BYTES_PER_HOP];
        rho(h_rho(&shared_secret), &mut buffer);
        let routing = xor(&concat(beta, &[0u8; Self::BYTES_PER_HOP]), &buffer);

        let info = &routing[..Self::BYTES_PER_HOP];

        let delta = &onion[ALPHA_LEN + header_length + KAPPA..];
        let delta = pi_inv(h_pi(&shared_secret), &delta);

        match info[0] {
            _ if info[0] == Flag::Relay as u8 => {
                let meta: &[u8; PER_HOP_META_LENGTH] = &info[1..1 + PER_HOP_META_LENGTH].try_into().unwrap();
                let next_mac = &info[1 + PER_HOP_META_LENGTH..];
                let blinded_alpha = alpha * h_b(&alpha, &shared_secret);

                let mut output = vec![];
                output.write_all(&blinded_alpha.compress().0).unwrap();
                output.write_all(&routing[Self::BYTES_PER_HOP..]).unwrap();
                output.write_all(next_mac).unwrap();
                output.write_all(&delta).unwrap();
                Ok(ProcessedOnion::Relay {
                    meta: *meta,
                    onion: output,
                })
            }
            _ if info[0] == Flag::Fragment as u8 => {
                let index = u128::from_be_bytes(info[1..1 + KAPPA].try_into().unwrap());
                let set_id = u128::from_be_bytes(info[1 + KAPPA..1 + 2 * KAPPA].try_into().unwrap());
                Ok(ProcessedOnion::Fragment {
                    set_id,
                    index,
                    data: delta,
                })
            }
            _ if info[0] == Flag::Deliver as u8 => {
                let meta: [u8; REPLY_META_LENGTH] = info[1..1 + REPLY_META_LENGTH].try_into().unwrap();
                Ok(ProcessedOnion::Reply {
                    meta,
                    data: delta,
                })
            }
            _ => Err(Error::InvalidHeaderFlag),
        }
    }

    pub fn defrag<A: AsRef<[u8]>>(&self, fragments: &[A]) -> Result<(FinalHopMeta, Vec<u8>)> {
        let mut data = aont_inv(fragments)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if data.len() < KAPPA || data[..KAPPA].iter().any(|x| *x != 0) {
            return Err(Error::MissingFragments);
        }

        data.drain(..KAPPA);
        let address = data.drain(..FINAL_HOP_META_LENGTH).collect::<Vec<_>>().try_into().unwrap();

        Ok((address, data))
    }

    pub fn create_surb(
        &self,
        path: &[Node],
        meta: &ReplyMeta,
    ) -> (Vec<[u8; PI_KEY_SIZE]>, Vec<u8>) {
        let mut final_info = [0u8; REPLY_META_LENGTH + 1];
        final_info[0] = Flag::Deliver as u8;
        final_info[1..].copy_from_slice(meta);
        let (secrets, surb) = self.wrap(path, &final_info, &[]);
        let secrets = secrets.iter().map(h_pi).collect::<Vec<_>>();
        (secrets, surb)
    }

    pub fn unwrap_reply(&self, secrets: &[[u8; PI_KEY_SIZE]], data: &[u8]) -> Vec<u8> {
        let mut data = Vec::from(data);
        for secret in secrets.iter().rev() {
            data = pi(*secret, &data);
        }
        data
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::collections::HashMap;

    const ADDR_LEN: usize = 32;

    #[test]
    fn test_aont() {
        let rng = rand::rng();
        let fragments = &[b"foo" as &[u8], b"raboof"];
        let transformed = aont(rng, fragments);
        let reverted = aont_inv(&transformed).unwrap();
        assert_eq!(fragments.as_ref(), &reverted)
    }

    #[test]
    fn test_create_onion() {
        let mut success = false;
        let mut rng = rand::rng();
        let scylla = Scylla::new(5, 128);

        let private_keys = &[
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
        ];
        let nodes = &[
            Node::from_private_key([0; ADDR_LEN], &private_keys[0]),
            Node::from_private_key([1; ADDR_LEN], &private_keys[1]),
            Node::from_private_key([2; ADDR_LEN], &private_keys[2]),
            Node::from_private_key([3; ADDR_LEN], &private_keys[3]),
        ];
        let path1 = nodes;
        let path2 = &[nodes[0], nodes[2], nodes[1], nodes[3]];
        let mut onions = scylla
            .create_onions(
                &[path1, path2],
                &[13; ADDR_LEN],
                vec![vec![2; 128 - 4 * KAPPA], vec![3; 128]],
            )
            .unwrap()
            .into_iter()
            .map(|x| ([0u8; ADDR_LEN], x))
            .collect::<Vec<_>>();

        let mut fragments = HashMap::<u128, Vec<(u128, Vec<u8>)>>::new();

        while !onions.is_empty() {
            let (hop, onion) = onions.pop().unwrap();
            let private_key = &private_keys[hop[0] as usize];

            let procd = scylla.process(private_key, &onion).unwrap();

            match procd {
                ProcessedOnion::Relay { meta, onion } => {
                    println!("Relaying to {meta:?}");
                    onions.push((meta[..ADDR_LEN].try_into().unwrap(), onion));
                }
                ProcessedOnion::Fragment {
                    set_id,
                    index,
                    data,
                } => {
                    println!("Received fragment {set_id}:{index}");
                    let frags = fragments.entry(set_id).or_default();
                    frags.push((index, data));
                    frags.sort_by_key(|x| x.0);
                    println!(
                        "Received {} fragments for this set so far, checking completeness",
                        frags.len()
                    );
                    let set = frags.iter().map(|x| x.1.clone()).collect::<Vec<_>>();
                    let data = scylla.defrag(&set);
                    match data {
                        Ok(x) => {
                            println!("Complete: {x:?}");
                            success = x.0 == [13; ADDR_LEN] && x.1.iter().all(|x| *x == 2 || *x == 3);
                        }
                        Err(_) => println!("Still incomplete"),
                    }
                }
                ProcessedOnion::Reply { .. } => panic!("no reply expected"),
            }
        }

        assert!(success);
    }

    #[test]
    fn test_surb() {
        let mut rng = rand::rng();
        let scylla = Scylla::new(5, 128);

        let private_keys = &[
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
            Scalar::from_bytes_mod_order_wide(&rng.random()),
        ];
        let nodes = &[
            Node::from_private_key([0; ADDR_LEN], &private_keys[0]),
            Node::from_private_key([1; ADDR_LEN], &private_keys[1]),
            Node::from_private_key([2; ADDR_LEN], &private_keys[2]),
            Node::from_private_key([3; ADDR_LEN], &private_keys[3]),
        ];
        let reply_id: u128 = rng.random();
        let reply_addr = &[42; ADDR_LEN];
        let meta = concat(reply_addr, reply_id.to_be_bytes());
        let meta = concat(&meta, &[0, 0, 0]);
        let (secrets, surb) = scylla.create_surb(nodes, meta.as_slice().try_into().unwrap());
        let text = b"Widdewiddewitt und drei macht neune";

        let mut onion = concat(surb, text);

        let ProcessedOnion::Relay { onion: o, .. } =
            scylla.process(&private_keys[0], &onion).unwrap()
        else {
            panic!()
        };
        onion = o;

        let ProcessedOnion::Relay { onion: o, .. } =
            scylla.process(&private_keys[1], &onion).unwrap()
        else {
            panic!()
        };
        onion = o;

        let ProcessedOnion::Relay { onion: o, .. } =
            scylla.process(&private_keys[2], &onion).unwrap()
        else {
            panic!()
        };
        onion = o;

        let ProcessedOnion::Reply { meta, data } =
            scylla.process(&private_keys[3], &onion).unwrap()
        else {
            panic!()
        };

        assert_eq!(&meta[..ADDR_LEN], [42; ADDR_LEN]);
        assert_eq!(&meta[ADDR_LEN..][..16], reply_id.to_be_bytes());

        let payload = scylla.unwrap_reply(&secrets, &data);
        assert_eq!(payload, text);
    }
}
