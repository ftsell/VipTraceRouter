use super::icmp6;
use crate::argparse::Arguments;
use crate::ip_addrs;
use log::{debug, trace, warn};
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::{Ipv6, Ipv6Packet, MutableIpv6Packet};
use pnet_packet::Packet;
use std::net::Ipv6Addr;

/// Handle incoming IPv6 packet and optionally return a response IPv6 packet
pub fn handle_ipv6_packet(program_args: &Arguments, packet: &Ipv6Packet) -> Option<Vec<u8>> {
    // The nth address in the virtual network if the request's TTL is used as n
    let nth_address_from_ttl = ip_addrs::get_nth_address_in_network6(
        packet.get_hop_limit() as usize,
        ip_addrs::calc_netmask_size_with_n_hosts6(program_args.n_hosts),
        &packet.get_destination(),
    );

    // if the packet has exceeded its hop limit but not yet reached its goal, terminate it early
    if (packet.get_hop_limit() as usize) < program_args.n_hosts
        && nth_address_from_ttl != packet.get_destination()
    {
        debug!(
            "Received IPv6 packet with small hop limit, sending time exceeded response [packet_hop_limit={}, n_hosts={}, v_addr={}]",
            packet.get_hop_limit(),
            program_args.n_hosts,
            nth_address_from_ttl
        );
        Some(build_ipv6_response(
            packet,
            nth_address_from_ttl,
            icmp6::build_icmp6_time_exceeded_response(
                packet,
                &nth_address_from_ttl,
                &packet.get_source(),
            ),
            Some(64),
        ))
    }
    // otherwise continue parsing the next layer
    else {
        // we know how to handle ICMP6 so try to parse and handle it
        if packet.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
            match Icmpv6Packet::new(packet.payload()) {
                None => {
                    warn!("Could not parse incoming ICMP6 packet");
                    None
                }
                Some(icmp_packet) => {
                    trace!(
                        "Recognized and parsed ICMP6 packet [packet={:?}]",
                        icmp_packet
                    );
                    match icmp6::handle_icmp6_packet(
                        &icmp_packet,
                        &packet.get_destination(),
                        &packet.get_source(),
                    ) {
                        None => None,
                        Some(icmp_response) => Some(build_ipv6_response(
                            packet,
                            packet.get_destination(),
                            icmp_response,
                            None,
                        )),
                    }
                }
            }
        }
        // if we receive a UDP or TCP packet, we send an ICMP destination unreachable response
        // to indicate that the port is closed
        else if packet.get_next_header() == IpNextHeaderProtocols::Udp
            || packet.get_next_header() == IpNextHeaderProtocols::Tcp
        {
            Some(build_ipv6_response(
                packet,
                packet.get_destination(),
                icmp6::build_icmp6_destination_unreachable_response(
                    packet,
                    &packet.get_destination(),
                    &packet.get_source(),
                ),
                None,
            ))
        }
        // all other upper layer protocols we don't know so we just don't respond at all
        else {
            debug!(
                "Received IPv6 packet with unhandled higher protocol [proto={}]",
                packet.get_next_header()
            );
            None
        }
    }
}

/// Build an IPv6 packet in response to the provided one
///
/// The generated response packet will have most of it's relevant data extracted from `request`
/// except for it's own source address which is provided via `src_address`.
/// It will also have the given `data` as it's paylaod.
fn build_ipv6_response(
    request: &Ipv6Packet,
    src_address: Ipv6Addr,
    data: Vec<u8>,
    hop_limit: Option<u8>,
) -> Vec<u8> {
    let mut response = vec![0; MutableIpv6Packet::minimum_packet_size() + data.len()];

    let mut packet = MutableIpv6Packet::new(&mut response)
        .expect("Could not construct IPv6 packet with vector as buffer");
    packet.populate(&Ipv6 {
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: data.len() as u16,
        next_header: IpNextHeaderProtocols::Icmpv6,
        hop_limit: hop_limit.unwrap_or(request.get_hop_limit() - 1),
        source: src_address,
        destination: request.get_source(),
        payload: data,
    });

    response
}
