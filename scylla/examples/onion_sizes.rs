use scylla::{Scylla, Node};

const PATH_LENGTHS: &[u32] = &[1, 2, 3, 4, 5];
const PAYLOAD_SIZES: &[usize] = &[128, 256, 512, 1024];
const FRAGMENT_COUNTS: &[usize] = &[1, 2, 5, 10];

fn main() {
    println!("path_length,fragment_count,payload_size,onion_size");
    for &length in PATH_LENGTHS {
        let (_, node) = Node::random(rand::rng());
        let path = vec![node.clone(); length as usize];
        for &payload_size in PAYLOAD_SIZES {
            let scylla = Scylla::new(length, payload_size as u32);
            for &fragment_count in FRAGMENT_COUNTS {
                let paths = vec![path.clone(); fragment_count];
                let mut fragments = Vec::new();
                fragments.push(vec![1u8; payload_size - 4 * 16]);
                for i in 1..fragment_count {
                    fragments.push(vec![i as u8 + 1; payload_size]);
                }
                let onions = scylla.create_onions(&paths, &[0; 32], fragments.clone()).unwrap();
                let onion_size = onions.iter().map(|o| o.len()).sum::<usize>();
                println!("{length},{fragment_count},{payload_size},{onion_size}");
            }
        }
    }
}
