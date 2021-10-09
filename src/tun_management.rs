use crate::ip_addrs;
use log::info;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_tun::{Tun, TunBuilder};

pub async fn create_tun_devices(
    base_name: &str,
    n_hosts: usize,
    networks: &Vec<IpAddr>,
) -> Vec<Tun> {
    let mut result = Vec::with_capacity(networks.len());

    for (i, network) in networks.iter().enumerate() {
        match network {
            IpAddr::V4(network) => {
                let netmask_size = ip_addrs::calc_netmask_size_with_n_hosts4(n_hosts);
                let tun_address = ip_addrs::get_nth_address_in_network4(1, netmask_size, &network);
                let tun = create_ipv4_tun_device(
                    &format!("{}{}", base_name, i),
                    tun_address,
                    ip_addrs::calc_netmask_from_size4(netmask_size),
                )
                .await;
                info!("Created TUN device [own_address={}]", tun_address);
                result.push(tun);
            }
            IpAddr::V6(network) => {
                let netmask_size = ip_addrs::calc_netmask_size_with_n_hosts6(n_hosts);
                let tun_address =
                    ip_addrs::get_nth_address_in_network6(1, netmask_size as usize, &network);
                let tun = create_ipv6_tun_device(
                    &format!("{}{}", base_name, i),
                    tun_address,
                    netmask_size as u32,
                )
                .await;
                info!("Created TUN device [own_address={}]", tun_address);
                result.push(tun);
            }
        }
    }

    result
}

async fn create_ipv4_tun_device(
    device_name: &str,
    device_address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Tun {
    TunBuilder::new()
        .name(device_name)
        .tap(false) // tap would be ethernet bridging but we are only interested in IP packets
        .address(IpAddr::V4(device_address))
        .netmask(netmask)
        .packet_info(false)
        .up() // automatically bring the device online (instead of having to run `ip link set <name> up`)
        .try_build()
        .expect("Could not create TUN device")
}

async fn create_ipv6_tun_device(
    device_name: &str,
    device_address: Ipv6Addr,
    prefix_length: u32,
) -> Tun {
    TunBuilder::new()
        .name(device_name)
        .tap(false)
        .address(IpAddr::V6(device_address))
        .prefix_length(prefix_length)
        .packet_info(false)
        .up()
        .try_build()
        .expect("Could not create TUN device")
}
