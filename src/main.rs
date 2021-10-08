#![feature(ip)]
#![feature(async_closure)]

use log::{debug, info, trace, warn, LevelFilter};
use pdu::{IcmpPdu, Ip, Ipv4, Ipv6};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::any::Any;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::sleep;

mod argparse;
mod ip_addrs;
mod tun_management;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = argparse::parse_arguments();
    setup_logging(args.log_level);
    debug!("Parsed program arguments [args={:?}]", args);

    let tun_devices =
        tun_management::create_tun_devices(&args.tun_device_name, args.n_hosts, &args.networks)
            .await;
    debug!("Created all tun devices");

    loop {}

    /*
    let address4 = IpAddr::from_str("10.10.0.1").unwrap();
    let mut tun_device4 = tun_management::create_ipv4_tun_device(
        "tunTestV4",
        address4,
        Ipv4Addr::new(255, 255, 255, 0),
    )
    .await;

    let address6 = IpAddr::from_str("1010::1").unwrap();
    let mut tun_device6 = tun_management::create_ipv6_tun_device("tunTestV6", address6, 64).await;

    info!(
        "Now listening for packets. [ip4={}, ip6={}]",
        address4, address6
    );

    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; 1024];
            let n = tun_device4.read(&mut buf).await.unwrap();
            trace!("read IPv4 bytes [n={}, bytes={:x?}]", n, &buf[..n]);
            handle_packet(&buf[..n]);
        }
    });

    loop {
        let mut buf = [0u8; 1024];
        let n = tun_device6.read(&mut buf).await.unwrap();
        trace!("read IPv6 bytes [n={}, bytes={:?}]", n, &buf[..n]);
        handle_packet(&buf[..n]);
    }
     */
}

fn setup_logging(log_level: LevelFilter) {
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );
}

fn handle_packet(buffer: &[u8]) {
    match Ip::new(buffer) {
        Err(e) => warn!("Could not parse incoming packet [error={}]", e),
        Ok(ip_packet) => {
            match ip_packet {
                Ip::Ipv4(ip_packet) => match ip_packet.inner() {
                    Err(e) => warn!("Could not extract IPv4 packet data [error={}]", e),
                    Ok(data) => match data {
                        Ipv4::Icmp(icmp_packet) => handle_icmp_packet(icmp_packet),
                        other => debug!(
                            "Received IPv4 packet type which is not handled [protocol={:?}]",
                            ip_packet.protocol(),
                        ),
                    },
                },
                Ip::Ipv6(ip_packet) => match ip_packet.inner() {
                    Err(e) => warn!("Could not extract IPv6 packet data [error={}]", e),
                    Ok(data) => match data {
                        Ipv6::Icmp(icmp_packet) => handle_icmp_packet(icmp_packet),
                        other => debug!(
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
