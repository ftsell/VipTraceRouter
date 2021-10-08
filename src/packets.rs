use log::{debug, info, warn};
use pdu::{IcmpPdu, Ip, Ipv4, Ipv6};

pub(crate) fn handle_packet(buffer: &[u8]) {
    match Ip::new(buffer) {
        Err(e) => warn!("Could not parse incoming packet [error={}]", e),
        Ok(ip_packet) => {
            match ip_packet {
                Ip::Ipv4(ip_packet) => match ip_packet.inner() {
                    Err(e) => warn!("Could not extract IPv4 packet data [error={}]", e),
                    Ok(data) => match data {
                        Ipv4::Icmp(icmp_packet) => handle_icmp_packet(icmp_packet),
                        _ => debug!(
                            "Received IPv4 packet type which is not handled [protocol={:?}]",
                            ip_packet.protocol(),
                        ),
                    },
                },
                Ip::Ipv6(ip_packet) => match ip_packet.inner() {
                    Err(e) => warn!("Could not extract IPv6 packet data [error={}]", e),
                    Ok(data) => match data {
                        Ipv6::Icmp(icmp_packet) => handle_icmp_packet(icmp_packet),
                        _ => debug!(
                            "Received IPv6 packet type which is not handled [protocol={:?}]",
                            ip_packet.computed_protocol()
                        ),
                    },
                },
            };
        }
    }
}

fn handle_icmp_packet(icmp_packet: IcmpPdu) {
    match icmp_packet.message_type() {
        8 => {
            info!("Received ICMP ping request [packet={:?}]", icmp_packet)
        }
        128 => {
            info!("Received ICMP6 ping request [packet={:?}", icmp_packet)
        }
        _ => debug!(
            "Received ICMP packet type which is not handled [type={}]",
            icmp_packet.message_type()
        ),
    }
}
