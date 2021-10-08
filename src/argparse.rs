use clap::{App, Arg, ArgGroup};
use log::LevelFilter;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug)]
pub struct Arguments {
    pub log_level: LevelFilter,
    pub tun_device_name: String,
    pub n_hosts: usize,
    pub networks: Vec<IpAddr>,
}

pub fn parse_arguments() -> Arguments {
    let matches = App::new("TraceRouteExtender")
        .version(env!("CARGO_PKG_VERSION"))
        .about(
            "Adds additional ip addresses when tracerouting the host where this app is running on",
        )
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .long("verbose")
                .help("Increase program verbosity (can be given more than once)")
                .multiple(true),
        )
        .arg(
            Arg::with_name("tun_device_name")
                .short("i")
                .long("iface")
                .help("Name of the created TUN interface")
                .default_value("tunTraceRtExt")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("net4")
                .long("net4")
                .help("IPv4 network part of virtual addresses")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("net6")
                .long("net6")
                .help("IPv6 network part of virtual addresses")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("nhosts")
                .short("n")
                .long("nhosts")
                .help("Number of hosts inside the virtual network")
                .required(true)
                .takes_value(true),
        )
        .group(
            ArgGroup::with_name("g_address")
                .args(&["net4", "net6"])
                .multiple(true)
                .required(true),
        )
        .get_matches();

    let mut networks = match matches.values_of("net4") {
        None => Vec::new(),
        Some(v4_networks) => v4_networks
            .map(|raw_address| IpAddr::from_str(raw_address).expect("Could not parse IP address"))
            .collect(),
    };
    if let Some(v6_networks) = matches.values_of("net6") {
        networks.extend(
            v6_networks.map(|raw_address| {
                IpAddr::from_str(raw_address).expect("Could not parse IP address")
            }),
        )
    }

    Arguments {
        log_level: match matches.occurrences_of("verbosity") {
            0 => LevelFilter::Info,  // default log level
            1 => LevelFilter::Debug, // verbosity increased once
            _ => LevelFilter::Trace, // verbosity increased at least twice
        },
        tun_device_name: matches.value_of("tun_device_name").unwrap().to_string(),
        n_hosts: usize::from_str(matches.value_of("nhosts").unwrap())
            .expect("could not parse nhosts as number"),
        networks,
    }
}
