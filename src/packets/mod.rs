use log::{debug, trace, warn};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{checksum, Ipv4, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::Packet;

mod icmp;

pub fn handle(buffer: &[u8]) -> Option<Vec<u8>> {
    // peek into the packet and see if its ip header defines it as IPv4
    if (buffer[0] >> 4) == 0b0100 {
        match Ipv4Packet::new(buffer) {
            None => {
                warn!("Could not parse incoming packet as IPv4 packet even though header byte matched");
                None
            }
            Some(packet) => {
                trace!("Recognized and parsed IPv4 packet [packet={:?}]", packet);
                handle_ipv4_packet(&packet)
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

fn handle_ipv4_packet(ip_packet: &Ipv4Packet) -> Option<Vec<u8>> {
    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        match IcmpPacket::new(ip_packet.payload()) {
            None => {
                warn!("Could not parse incoming ICMP packet even though IP header defined it as being ICMP");
                None
            }
            Some(icmp_packet) => {
                trace!(
                    "Recognized and parsed ICMP packet [packet={:?}]",
                    icmp_packet
                );
                match icmp::handle_icmp_packet(ip_packet, &icmp_packet) {
                    None => None,
                    Some(icmp_response) => Some(build_ipv4_response(ip_packet, icmp_response)),
                }
            }
        }
    } else {
        debug!(
            "Received IPv4 packet with unhandled higher protocol [proto={}]",
            ip_packet.get_next_level_protocol()
        );
        None
    }
}

fn build_ipv4_response(request: &Ipv4Packet, data: Vec<u8>) -> Vec<u8> {
    let mut response = vec![0; MutableIpv4Packet::minimum_packet_size() + data.len()];

    let mut packet = MutableIpv4Packet::new(&mut response)
        .expect("Could not construct IPv4 packet with vector as buffer");
    packet.populate(&Ipv4 {
        version: 4,
        header_length: 5,
        dscp: 0,
        ecn: 0,
        total_length: 20_u16 + data.len() as u16,
        identification: 42,
        flags: Ipv4Flags::DontFragment,
        fragment_offset: 0,
        ttl: request.get_ttl() - 1,
        next_level_protocol: IpNextHeaderProtocols::Icmp,
        checksum: 0,
        source: request.get_destination(),
        destination: request.get_source(),
        options: vec![],
        payload: data,
    });
    packet.set_checksum(checksum(&packet.to_immutable()));

    trace!(
        "Constructed IPv4 response [len={}, response={:?}]",
        packet.get_total_length(),
        packet.to_immutable(),
    );
    response
}
