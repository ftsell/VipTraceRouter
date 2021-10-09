use clap::{App, Arg};
use log::LevelFilter;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
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
            Arg::with_name("networks")
                .long("net")
                .help("Network part of the desired virtual IP addresses")
                .required(true)
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
        .get_matches();

    Arguments {
        log_level: match matches.occurrences_of("verbosity") {
            0 => LevelFilter::Info,  // default log level
            1 => LevelFilter::Debug, // verbosity increased once
            _ => LevelFilter::Trace, // verbosity increased at least twice
        },
        tun_device_name: matches.value_of("tun_device_name").unwrap().to_string(),
        n_hosts: usize::from_str(matches.value_of("nhosts").unwrap())
            .expect("could not parse nhosts as number"),
        networks: matches
            .values_of("networks")
            .unwrap()
            .map(|address| IpAddr::from_str(address).expect("Could not parse IP address"))
            .collect(),
    }
}
