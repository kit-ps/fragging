use sphinx_packet::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, MAX_PATH_LENGTH, NODE_ADDRESS_LENGTH,
};
use sphinx_packet::crypto::keygen;
use sphinx_packet::header::delays;
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::payload::PAYLOAD_OVERHEAD_SIZE;
use sphinx_packet::SphinxPacketBuilder;
use std::convert::TryInto;
use std::time::Duration;

fn main() {
    let nodes = (0..MAX_PATH_LENGTH)
        .map(|i| {
            let (_, pk) = keygen();
            Node::new(
                NodeAddressBytes::from_bytes([i.try_into().unwrap(); NODE_ADDRESS_LENGTH]),
                pk,
            )
        })
        .collect::<Vec<_>>();

    let delays = delays::generate_from_average_duration(nodes.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );

    for payload_size in [512, 1024, 2048, 4069] {
        let message = vec![13u8; payload_size];

        let packet = SphinxPacketBuilder::default()
            .with_payload_size(payload_size + PAYLOAD_OVERHEAD_SIZE)
            .build_packet(message.clone(), &nodes, &destination, &delays).unwrap();
        println!(
            "{MAX_PATH_LENGTH},{payload_size},{}",
            packet.to_bytes().len()
        );
    }
}
