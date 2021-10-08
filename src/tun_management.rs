use crate::ip_addrs;
use log::{debug, trace};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_tun::{Tun, TunBuilder};

pub async fn create_tun_devices(
    base_name: &str,
    n_hosts: usize,
    networks: &Vec<IpAddr>,
) -> Vec<Tun> {
    let mut result = Vec::with_capacity(networks.len());

    let netmask_size = 32 - ((n_hosts as f64).abs() + 2.0).log2().ceil() as u32;
    trace!(
        "Calculated netmask [n_hosts={}, netmask=/{}, n_hosts_avail={}]",
        n_hosts,
        netmask_size,
        2_usize.pow(32 - netmask_size) - 2
    );

    for (i, network) in networks.iter().enumerate() {
        match network {
            IpAddr::V4(network) => {
                let netmask = Ipv4Addr::new(255, 255, 255, 0);
                let tun = create_ipv4_tun_device(
                    &format!("{}{}", base_name, i),
                    ip_addrs::get_nth_address_in_network4(1, netmask_size, &network),
                    ip_addrs::calc_netmask_from_size4(netmask_size),
                )
                .await;
                result.push(tun);
            }
            IpAddr::V6(network) => {
                let tun = create_ipv6_tun_device(
                    &format!("{}{}", base_name, i),
                    crate::ip_addrs::get_nth_address_in_network6(
                        1,
                        netmask_size as usize,
                        &network,
                    ),
                    netmask_size as u32,
                )
                .await;
                result.push(tun);
            }
        }
    }

    result
}

pub async fn create_ipv4_tun_device(
    device_name: &str,
    device_address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Tun {
    match TunBuilder::new()
        .name(device_name)
        .tap(false) // tap would be ethernet bridging but we are only interested in IP packets
        .address(IpAddr::V4(device_address))
        .netmask(netmask)
        .packet_info(false)
        .up() // automatically bring the device online (instead of having to run `ip link set <name> up`)
        .try_build()
    {
        Ok(tun) => {
            debug!(
                "Created tun device [name={}, address={}]",
                device_name, device_address
            );
            tun
        }
        Err(err) => panic!("Could not create TUN device [error={}]", err),
    }
}

pub async fn create_ipv6_tun_device(
    device_name: &str,
    device_address: Ipv6Addr,
    prefix_length: u32,
) -> Tun {
    match TunBuilder::new()
        .name(device_name)
        .tap(false)
        .address(IpAddr::V6(device_address))
        .prefix_length(prefix_length)
        .packet_info(false)
        .up()
        .try_build()
    {
        Ok(tun) => {
            debug!(
                "Created tun device [name={}, address={}]",
                device_name, device_address
            );
            tun
        }
        Err(err) => panic!("Could not create TUN device [error={}]", err),
    }
}
