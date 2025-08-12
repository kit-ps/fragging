use criterion::{Criterion, criterion_group, criterion_main};
use frinx::{Frinx, Node, ProcessedOnion};

const PATH_LENGTHS: &[u32] = &[1, 2, 3, 4, 5];
const PAYLOAD_SIZES: &[usize] = &[128, 256, 512, 1024];
const FRAGMENT_COUNTS: &[usize] = &[1, 2, 5, 10];

fn creation(c: &mut Criterion) {
    for &length in PATH_LENGTHS {
        let (_, node) = Node::random(rand::rng());
        let path = vec![node.clone(); length as usize];
        for &payload_size in PAYLOAD_SIZES {
            let frinx = Frinx::new(5, payload_size as u32);
            for &fragment_count in FRAGMENT_COUNTS {
                let paths = vec![path.clone(); fragment_count];
                let mut fragments = Vec::new();
                fragments.push(vec![1u8; payload_size - 3 * 16]);
                for i in 1..fragment_count {
                    fragments.push(vec![i as u8 + 1; payload_size]);
                }
                c.bench_function(
                    &format!("Frinx::create_onions({length}, {payload_size}, {fragment_count})"),
                    |b| {
                        b.iter(|| {
                            frinx
                                .create_onions(&paths, &[0; 16], fragments.clone())
                                .unwrap()
                        })
                    },
                );
            }
        }
        let frinx = Frinx::new(5, 1024);
        c.bench_function(&format!("Frinx::create_surb({length})"), |b| {
            b.iter(|| frinx.create_surb(&path, &[27; 16], 1337));
        });
    }
}

fn processing(c: &mut Criterion) {
    let (private_key, node) = Node::random(rand::rng());
    for &payload_size in PAYLOAD_SIZES {
        let frinx = Frinx::new(5, payload_size as u32);

        let fragments = vec![vec![0u8; payload_size - 3 * 16]];
        let onion = &frinx
            .create_onions(&[&[node, node]], &[0; 16], fragments.clone())
            .unwrap()[0];

        c.bench_function(
            &format!("Frinx::process(Flag::Relay, {payload_size})"),
            |b| {
                b.iter(|| frinx.process(&private_key, onion).unwrap());
            },
        );

        let ProcessedOnion::Relay { onion, .. } = frinx.process(&private_key, onion).unwrap()
        else {
            unreachable!()
        };

        c.bench_function(
            &format!("Frinx::process(Flag::Fragment, {payload_size})"),
            |b| {
                b.iter(|| frinx.process(&private_key, &onion).unwrap());
            },
        );

        let (_secrets, surb) = frinx.create_surb(&[node], &[1; 16], 4242);
        let mut onion = Vec::from(surb);
        onion.extend(vec![2; payload_size]);

        assert!(matches!(
            frinx.process(&private_key, &onion),
            Ok(ProcessedOnion::Reply { .. })
        ));

        c.bench_function(
            &format!("Frinx::process(Flag::Deliver, {payload_size})"),
            |b| {
                b.iter(|| frinx.process(&private_key, &onion).unwrap());
            },
        );
    }
}

fn defrag(c: &mut Criterion) {
    let (private_key, node) = Node::random(rand::rng());
    let path = vec![node.clone()];
    for &payload_size in PAYLOAD_SIZES {
        let frinx = Frinx::new(5, payload_size as u32);
        for &fragment_count in FRAGMENT_COUNTS {
            let paths = vec![path.clone(); fragment_count];
            let mut fragments = Vec::new();
            fragments.push(vec![1u8; payload_size - 3 * 16]);
            for i in 1..fragment_count {
                fragments.push(vec![i as u8 + 1; payload_size]);
            }
            let onions = frinx.create_onions(&paths, &[4; 16], fragments).unwrap();
            assert_eq!(onions.len(), fragment_count);
            let mut onions = onions
                .into_iter()
                .map(|o| frinx.process(&private_key, &o).unwrap())
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
                &format!("Frinx::defrag({payload_size}, {fragment_count})"),
                |b| {
                    b.iter(|| frinx.defrag(&onions).unwrap());
                },
            );
        }
    }
}

criterion_group!(frinx, creation, processing, defrag);
criterion_main!(frinx);
