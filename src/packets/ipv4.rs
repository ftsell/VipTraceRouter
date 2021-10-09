use super::icmp;
use crate::argparse::Arguments;
use crate::ip_addrs;
use log::{debug, trace, warn};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{checksum, Ipv4, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::Packet;
use std::net::Ipv4Addr;

/// Handle incoming IPv4 packet and optionally return a response IPv4 packet
pub fn handle_ipv4_packet(program_args: &Arguments, packet: &Ipv4Packet) -> Option<Vec<u8>> {
    // The nth address in the virtual network if the request's TTL is used as n
    let nth_address_from_ttl = ip_addrs::get_nth_address_in_network4(
        packet.get_ttl() as u32,
        ip_addrs::calc_netmask_size_with_n_hosts4(program_args.n_hosts),
        &packet.get_destination(),
    );

    // if the packet has exceeded its hop limit but not yet reached its goal, terminate it early
    if (packet.get_ttl() as usize) < program_args.n_hosts
        && nth_address_from_ttl != packet.get_destination()
    {
        debug!("Received IPv4 packet with small TTL, sending time exceeded response");
        Some(build_ipv4_response(
            &packet,
            nth_address_from_ttl,
            icmp::build_icmp_time_exceeded_response(&packet),
        ))
    }
    // otherwise continue parsing the next layer
    else {
        // we know how to handle ICMP so try to parse and handle it
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
            match IcmpPacket::new(packet.payload()) {
                None => {
                    warn!("Could not parse incoming ICMP packet even though IP header defined it as being ICMP");
                    None
                }
                Some(icmp_packet) => {
                    trace!(
                        "Recognized and parsed ICMP packet [packet={:?}]",
                        icmp_packet
                    );
                    match icmp::handle_icmp_packet(packet, &icmp_packet) {
                        None => None,
                        Some(icmp_response) => Some(build_ipv4_response(
                            packet,
                            packet.get_destination(),
                            icmp_response,
                        )),
                    }
                }
            }
        }
        // all other upper layer protocols we don't know so we just don't respond at all
        else {
            debug!(
                "Received IPv4 packet with unhandled higher protocol [proto={}]",
                packet.get_next_level_protocol()
            );
            None
        }
    }
}

/// Build an IPv4 packet in response to the provided one
///
/// The generated response packet will have most of it's relevant data extracted from `request`
/// except for it's own source address which is provided via `src_address`. It will also have
/// the given `data` as its payload.
fn build_ipv4_response(request: &Ipv4Packet, src_address: Ipv4Addr, data: Vec<u8>) -> Vec<u8> {
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
        source: src_address,
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
