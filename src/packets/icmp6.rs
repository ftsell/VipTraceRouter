use log::{debug, trace};
use pnet_packet::icmpv6::{
    checksum, Icmpv6, Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet,
};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::{Packet, PacketSize};
use std::net::Ipv6Addr;

/// Handle an incoming ICMPv6 packet and optionally return a response ICMPv6 packet
pub fn handle_icmp6_packet(
    packet: &Icmpv6Packet,
    response_src_address: &Ipv6Addr,
    response_dst_address: &Ipv6Addr,
) -> Option<Vec<u8>> {
    // if the incoming packet is an echo request, handle it and send back a proper response
    if packet.get_icmpv6_type() == Icmpv6Types::EchoRequest
        && packet.get_icmpv6_code() == Icmpv6Code(0)
    {
        trace!("Handling ICMPv6 echo request by building an ICMPv6 echo response");
        Some(build_icmp6_echo_response(
            &packet.payload(),
            response_src_address,
            response_dst_address,
        ))
    }
    // ignore all other ICMP types
    else {
        debug!(
            "Received unhandled ICMPv6 packet [type={:?}, code={:?}]",
            packet.get_icmpv6_type(),
            packet.get_icmpv6_code()
        );
        None
    }
}

/// Build an ICMPv6 packet that is an echo response and has the provided payload.
///
/// `icmp_payload` can usually be copied from an echo request because an echo response should
/// normally just response with all data as it was sent.
///
/// `src_address` and `dst_address` need to be provided to calculate an ICMPv6 checksum.
fn build_icmp6_echo_response(
    icmp_payload: &[u8],
    my_src_address: &Ipv6Addr,
    my_dst_address: &Ipv6Addr,
) -> Vec<u8> {
    let mut response = vec![0; MutableIcmpv6Packet::minimum_packet_size() + icmp_payload.len()];

    let mut packet = MutableIcmpv6Packet::new(&mut response)
        .expect("Could not create ICMPv6 packet with vector as buffer");
    packet.populate(&Icmpv6 {
        icmpv6_type: Icmpv6Types::EchoReply,
        icmpv6_code: Icmpv6Code(0),
        checksum: 0,
        payload: icmp_payload.to_vec(),
    });
    packet.set_checksum(checksum(
        &packet.to_immutable(),
        my_src_address,
        my_dst_address,
    ));

    response
}

/// Build an *ICMPv6 timeout exceeded* packet.
///
/// The *timeout exceeded* packets should be generated when an IPv6 packet's hop limit reaches 0.
///
/// This packet includes the original IPv6 packet in it's payload to provide the sender with some
/// context.
///
/// `src_address` and `dst_address` need to be provided to calculate an ICMPv6 checksum.
pub fn build_icmp6_time_exceeded_response(
    original_ip_packet: &Ipv6Packet,
    my_src_address: &Ipv6Addr,
    my_dst_address: &Ipv6Addr,
) -> Vec<u8> {
    // ICMP time exceeded responses have 4 8bit words of unused space between header and actual payload
    const RESERVED_WORDS: usize = 4;

    let mut result = vec![
        0;
        MutableIcmpv6Packet::minimum_packet_size()
            + original_ip_packet.packet_size()
            + RESERVED_WORDS
    ];

    let mut packet = MutableIcmpv6Packet::new(&mut result)
        .expect("Could not create ICMPv6 time exceeded with vector as buffer");
    packet.populate(&Icmpv6 {
        icmpv6_type: Icmpv6Types::TimeExceeded,
        icmpv6_code: Icmpv6Code(0),
        checksum: 0,
        payload: [&[0; RESERVED_WORDS], original_ip_packet.packet()].concat(),
    });
    packet.set_checksum(checksum(
        &packet.to_immutable(),
        my_src_address,
        my_dst_address,
    ));

    result
}

/// Build an *ICMPv6 destination unreachable* packet.
///
/// The *destination unreachable* packets should be generated when a higher level protocol cannot
/// be delivered.
///
/// This packet includes the original IPv6 packet in it's payload to provide the sender with some
/// context.
///
/// `src_address` and `dst_address` need to be provided to calculate an ICMPv6 checksum.
pub fn build_icmp6_destination_unreachable_response(
    original_ip_packet: &Ipv6Packet,
    my_src_address: &Ipv6Addr,
    my_dst_address: &Ipv6Addr,
) -> Vec<u8> {
    // ICMP destination unreachable messages have 4 8bit words of unused space between header and actual payload
    const RESERVED_WORDS: usize = 4;

    let mut result = vec![
        0;
        MutableIcmpv6Packet::minimum_packet_size()
            + original_ip_packet.packet_size()
            + RESERVED_WORDS
    ];

    let mut packet = MutableIcmpv6Packet::new(&mut result)
        .expect("Could not build into buffer to construct destination unreachable ICMPv6 packet");
    packet.populate(&Icmpv6 {
        icmpv6_type: Icmpv6Types::DestinationUnreachable,
        icmpv6_code: Icmpv6Code(4),
        checksum: 0,
        payload: [&[0; RESERVED_WORDS], original_ip_packet.packet()].concat(),
    });
    packet.set_checksum(checksum(
        &packet.to_immutable(),
        my_src_address,
        my_dst_address,
    ));

    result
}
