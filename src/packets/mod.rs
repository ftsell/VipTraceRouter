use crate::argparse::Arguments;
use log::{debug, trace, warn};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;

mod icmp;
mod icmp6;
mod ipv4;
mod ipv6;

/// Handle generic incoming bytes that were received from the wire and optionally generate a
/// response that should be written back to the wire.
pub fn handle(program_args: &Arguments, buffer: &[u8]) -> Option<Vec<u8>> {
    // peek into the packet and see if its ip header defines it as IPv4
    if (buffer[0] >> 4) == 0b0100 {
        match Ipv4Packet::new(buffer) {
            None => {
                warn!("Could not parse incoming packet as IPv4 packet even though header byte matched");
                None
            }
            Some(packet) => {
                trace!("Recognized and parsed IPv4 packet [packet={:?}]", packet);
                ipv4::handle_ipv4_packet(program_args, &packet)
            }
        }
    }
    // also peek in to see if it is IPv6
    else if (buffer[0] >> 4) == 0b0110 {
        match Ipv6Packet::new(buffer) {
            None => {
                warn!("Could not parse incoming packet as IPv6 packet even though header byte matched");
                None
            }
            Some(packet) => {
                trace!("Recognized and parsed IPv6 packet [packet={:?}]", packet);
                ipv6::handle_ipv6_packet(program_args, &packet)
            }
        }
    } else {
        debug!(
            "Received unknown layer 2 packet [first_byte={:08b}]",
            &buffer[0]
        );
        None
    }

    // TODO handle IPv6 packets
}
