use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::Parser;
use cli::TunnelCommand;
use fern::colors::{Color, ColoredLevelConfig};
use log::{error, info, warn};
use ssh_tunnel_core::ssh_forward::{self, HostAddress, SshAuthMethod};

mod cli;

#[tokio::main]
async fn main() {
    let clip = cli::Cli::parse();
    init_log().expect("init log error:");

    let host_addr = HostAddress::HostName(Cow::Borrowed(&clip.host));
    let ssh_auth = match &clip.auth {
        cli::AuthMethod::Password => SshAuthMethod::Password {
            password: Cow::Borrowed(&clip.pwd),
        },
        cli::AuthMethod::KeyPair => {
            if clip.private_key.is_empty() {
                panic!("when auth is {:?}, --private-key can not be empty.", cli::AuthMethod::KeyPair);
            }
            SshAuthMethod::KeyPair {
                private_key: std::borrow::Cow::Borrowed(&clip.private_key),
                passphrase: clip.passphrase.map(|s| std::borrow::Cow::from(s)),
            }
        }
    };

    let local_listen_ip = std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let (tx, rx) = tokio::sync::mpsc::channel::<bool>(1);

    match &clip.tunnel {
        TunnelCommand::Local {
            local_port,
            remote_host,
            remote_port,
        } => {
            let remote_addr = HostAddress::HostName(Cow::Borrowed(remote_host));
            ctrlc_async::set_async_handler(async move {
                tx.send(true).await.expect("send exit_signal err:");
                warn!("Received Ctrl-C, exiting");
            })
            .expect("Error for setting Ctrl-C handler:");

            ssh_forward::open_local_tunnel(
                rx,
                &host_addr,
                clip.port,
                &clip.user,
                &ssh_auth,
                local_listen_ip,
                *local_port,
                &remote_addr,
                *remote_port,
            )
            .await
            .unwrap()
            .await
            .unwrap();
        }
        TunnelCommand::Remote {
            local_host,
            local_port,
            remote_port,
        } => {
            let ipaddr: IpAddr = local_host.parse().unwrap();
            ssh_forward::open_remote_tunnel(rx, &host_addr, clip.port, &clip.user, &ssh_auth, ipaddr, *local_port, *remote_port)
                .await
                .unwrap()
                .await
                .unwrap();
        }
        _ => {}
    }
}

fn init_log() -> Result<()> {
    let colors = ColoredLevelConfig::new().debug(Color::Magenta).info(Color::Green);
    fern::Dispatch::new()
        // write console
        .chain(
            fern::Dispatch::new()
                .format(move |out, message, record| {
                    out.finish(format_args!(
                        "[{}]{}[{}:{:?}] {}",
                        colors.color(record.level()),
                        chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                        //record.target(),
                        record.file().unwrap_or("<unnamed>"),
                        record.line().unwrap_or(0),
                        message.to_string().split("\n\nStack backtrace:").collect::<Vec<&str>>().get(0).unwrap_or(&"")
                    ))
                })
                .level(log::LevelFilter::Info)
                //.filter(|meta_data| meta_data.level() == log::LevelFilter::Info || meta_data.level() == log::LevelFilter::Warn)
                .chain(std::io::stdout()),
        )
        // Apply globally
        .apply()?;

    // and log using log crate macros!
    info!("init log config success!");

    Ok(())
}
