use log::trace;
use std::net::{Ipv4Addr, Ipv6Addr};

/// reverse of `Ipv4Addr::from(<u32>)`
fn ipv4_to_u32(addr: &Ipv4Addr) -> u32 {
    let mut octets = addr.octets();
    octets.reverse();
    unsafe { std::mem::transmute(octets) }
}

/// reverse of `Ipv6Addr::from(<128>)`
fn ipv6_to_u128(addr: &Ipv6Addr) -> u128 {
    let mut octets = addr.octets();
    octets.reverse();
    unsafe { std::mem::transmute(octets) }
}

/// Calculate an IPv4 netmask from a given size
pub fn calc_netmask_from_size4(size: u32) -> Ipv4Addr {
    let mut netmask: u32 = 0;
    for i in 0..size {
        netmask |= 0b1 << (31 - i)
    }
    Ipv4Addr::from(netmask)
}

/// Calculate an IPv6 netmask from a given prefix length
fn calc_netmask_from_size6(prefix_length: usize) -> Ipv6Addr {
    let mut netmask: u128 = 0;
    for i in 0..prefix_length {
        netmask |= 0b1 << (127 - i)
    }
    Ipv6Addr::from(netmask)
}

/// Calculate the size an IPv4 netmask would need to encompass the number of hosts
pub fn calc_netmask_size_with_n_hosts4(n: usize) -> u32 {
    32 - ((n as f64).abs() + 2.0).log2().ceil() as u32
}

/// Calculate the size an IPv6 netmask would need to encompass the number of hosts
pub fn calc_netmask_size_with_n_hosts6(n: usize) -> usize {
    128 - ((n as f64).abs() + 2.0).log2().ceil() as usize
}

pub fn get_nth_address_in_network4(
    n: u32,
    netmask_size: u32,
    network_address: &Ipv4Addr,
) -> Ipv4Addr {
    // calculate binary netmask with correct number of leading 1s
    let netmask = ipv4_to_u32(&calc_netmask_from_size4(netmask_size));

    // calculate base network address from given address and netmask
    let mut network_address = ipv4_to_u32(network_address);
    network_address &= netmask;

    // calculate nth device address in network
    let device_address = network_address + (n & !netmask);
    trace!(
        "Calculated nth device address in network [n={}, netmask={}, net_ip={}, device_ip={}]",
        n,
        Ipv4Addr::from(netmask),
        Ipv4Addr::from(network_address),
        Ipv4Addr::from(device_address)
    );

    Ipv4Addr::from(device_address)
}

pub fn get_nth_address_in_network6(n: usize, prefix_length: usize, network: &Ipv6Addr) -> Ipv6Addr {
    // calculate binary netmask with correct number of leading 1s
    let netmask = ipv6_to_u128(&calc_netmask_from_size6(prefix_length));

    // calculate base network address from given address and netmask
    let mut network_address = ipv6_to_u128(network);
    network_address &= netmask;

    // calculate nth device address in network
    let device_address = network_address + (n as u128 & !netmask);
    trace!(
        "Calculated nth device address in network [n={}, netmask={}, net_ip={}, device_ip={}]",
        n,
        Ipv6Addr::from(netmask),
        Ipv6Addr::from(network_address),
        Ipv6Addr::from(device_address)
    );

    Ipv6Addr::from(device_address)
}

#[cfg(test)]
#[test]
fn test_calc_netmask_from_size4() {
    assert_eq!(
        calc_netmask_from_size4(30),
        Ipv4Addr::new(255, 255, 255, 252)
    );
    assert_eq!(calc_netmask_from_size4(24), Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(calc_netmask_from_size4(16), Ipv4Addr::new(255, 255, 0, 0));
}

#[cfg(test)]
#[test]
fn test_get_nth_address_in_network4() {
    assert_eq!(
        get_nth_address_in_network4(1, 24, &Ipv4Addr::new(10, 0, 0, 0)),
        Ipv4Addr::new(10, 0, 0, 1)
    );
    assert_eq!(
        get_nth_address_in_network4(255, 24, &Ipv4Addr::new(10, 0, 0, 0)),
        Ipv4Addr::new(10, 0, 0, 255)
    );
    assert_eq!(
        get_nth_address_in_network4(1, 24, &Ipv4Addr::new(10, 0, 0, 125)),
        Ipv4Addr::new(10, 0, 0, 1)
    );
    assert_eq!(
        get_nth_address_in_network4(1, 30, &Ipv4Addr::new(10, 0, 0, 4)),
        Ipv4Addr::new(10, 0, 0, 5)
    );
}

#[cfg(test)]
#[test]
fn test_calc_netmask_from_size6() {
    assert_eq!(
        calc_netmask_from_size6(64),
        Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)
    )
}

#[cfg(test)]
#[test]
fn test_get_nth_address_in_network6() {
    assert_eq!(
        get_nth_address_in_network6(1, 64, &Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
    )
}
