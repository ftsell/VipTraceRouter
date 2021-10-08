#![feature(ip)]
#![feature(async_closure)]

use log::{debug, info, LevelFilter};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tokio_tun::Tun;

mod argparse;
mod ip_addrs;
mod packets;
mod tun_management;

#[tokio::main]
async fn main() {
    let args = argparse::parse_arguments();
    setup_logging(args.log_level);
    debug!("Parsed program arguments [args={:?}]", args);

    let tun_devices =
        tun_management::create_tun_devices(&args.tun_device_name, args.n_hosts, &args.networks)
            .await;
    debug!("Created all tun devices");

    let handles: Vec<JoinHandle<_>> = tun_devices
        .into_iter()
        .map(|tun| tokio::spawn(async move { loop_for_tun_device(tun).await }))
        .collect();
    info!("Now Listening for incoming packets");

    for handle in handles {
        let _ = tokio::join!(handle);
    }
}

fn setup_logging(log_level: LevelFilter) {
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("Could not setup logging");
}

async fn loop_for_tun_device(mut tun: Tun) {
    loop {
        let mut buf = [0u8; 1024];
        let n = tun
            .read(&mut buf)
            .await
            .expect("Could not read from TUN device");
        packets::handle_packet(&buf[..n]);
    }
}
