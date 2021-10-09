use log::{debug, trace};
use pnet_packet::icmp::destination_unreachable::{
    DestinationUnreachable, MutableDestinationUnreachablePacket,
};
use pnet_packet::icmp::time_exceeded::{MutableTimeExceededPacket, TimeExceeded};
use pnet_packet::icmp::{checksum, Icmp, IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::{Packet, PacketSize};

/// Handle an incoming ICMP packet and optionally return a response ICMP packet
pub fn handle_icmp_packet(_ip_packet: &Ipv4Packet, icmp_packet: &IcmpPacket) -> Option<Vec<u8>> {
    // if the incoming packet is an echo request, handle it and send back a proper response
    if icmp_packet.get_icmp_type() == IcmpTypes::EchoRequest
        && icmp_packet.get_icmp_code() == IcmpCode(0)
    {
        Some(build_icmp_echo_response(icmp_packet.payload()))
    }
    // ignore all other ICMP types
    else {
        debug!(
            "Received unhandled ICMP packet [type={:?}, code={:?}]",
            icmp_packet.get_icmp_type(),
            icmp_packet.get_icmp_code()
        );
        None
    }
}

/// Build an ICMP packet that is an echo response and has the provided payload.
///
/// `icmp_payload` can usually simply be copied from an echo request because an echo response
/// should normally just respond with all data as it was provided.
fn build_icmp_echo_response(icmp_payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0; MutableIcmpPacket::minimum_packet_size() + icmp_payload.len()];

    let mut packet = MutableIcmpPacket::new(&mut result)
        .expect("Could not construct ICMP packet with vector as buffer");
    packet.populate(&Icmp {
        icmp_type: IcmpTypes::EchoReply,
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

/// Build an *ICMP timeout exceeded* packet.
///
/// The *timeout exceeded* packets should be generated when an IP packet's time to live
/// reaches 0. It also includes the failed original packet which can be provided via
/// `original_ip_packet`.
pub fn build_icmp_time_exceeded_response(original_ip_packet: &Ipv4Packet) -> Vec<u8> {
    let mut result = vec![
        0;
        MutableTimeExceededPacket::minimum_packet_size()
            + original_ip_packet.packet_size()
    ];

    let mut packet = MutableTimeExceededPacket::new(&mut result)
        .expect("Could not create ICMP time exceeded packet from empty buffer");
    packet.populate(&TimeExceeded {
        icmp_type: IcmpTypes::TimeExceeded,
        icmp_code: pnet_packet::icmp::time_exceeded::IcmpCodes::TimeToLiveExceededInTransit,
        checksum: 0,
        unused: 0,
        payload: original_ip_packet.packet().to_vec(),
    });
    packet.set_checksum(checksum(&IcmpPacket::new(packet.packet()).unwrap()));

    result
}

/// Build an *ICMP destination unreachable* packet.
///
/// The *destination unreachable* packets should be generated when a higher level protocol cannot
/// be delivered. It also includes the failed original packet which can be provided via
/// `original_ip_packet`.
pub fn build_icmp_destination_unreachable_response(original_ip_packet: &Ipv4Packet) -> Vec<u8> {
    let mut result = vec![
        0;
        MutableDestinationUnreachablePacket::minimum_packet_size()
            + original_ip_packet.packet_size()
    ];

    let mut packet = MutableDestinationUnreachablePacket::new(&mut result).expect(
        "Could not build view into buffer to construct destination unreachable ICMP packet",
    );
    packet.populate(&DestinationUnreachable {
        icmp_type: IcmpTypes::DestinationUnreachable,
        icmp_code: IcmpCode(3),
        checksum: 0,
        unused: 0,
        payload: original_ip_packet.packet().to_vec(),
    });
    packet.set_checksum(checksum(&IcmpPacket::new(packet.packet()).unwrap()));

    result
}
