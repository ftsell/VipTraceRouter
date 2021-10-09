use log::{debug, trace};
use pnet_packet::icmp::{checksum, Icmp, IcmpCode, IcmpPacket, IcmpType, MutableIcmpPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::Packet;

/// Handle an incoming ICMP packet and optionally return a response ICMP packet
pub fn handle_icmp_packet(_ip_packet: &Ipv4Packet, icmp_packet: &IcmpPacket) -> Option<Vec<u8>> {
    if icmp_packet.get_icmp_type() == IcmpType(8) && icmp_packet.get_icmp_code() == IcmpCode(0) {
        Some(build_icmp_echo_response(icmp_packet.payload()))
    } else {
        debug!(
            "Received unhandled ICMP packet [type={:?}, code={:?}]",
            icmp_packet.get_icmp_type(),
            icmp_packet.get_icmp_code()
        );
        None
    }
}

fn build_icmp_echo_response(icmp_payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0; MutableIcmpPacket::minimum_packet_size() + icmp_payload.len()];

    let mut packet = MutableIcmpPacket::new(&mut result)
        .expect("Could not construct ICMP packet with vector as buffer");
    packet.populate(&Icmp {
        icmp_type: IcmpType(0),
        icmp_code: IcmpCode(0),
        checksum: 0,
        payload: icmp_payload.to_vec(),
    });
    packet.set_checksum(checksum(&packet.to_immutable()));

    trace!(
        "Constructed ICMP response [response={:?}]",
        packet.to_immutable()
    );

    result
}
