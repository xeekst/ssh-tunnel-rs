use clap::{arg, command, Parser, Subcommand, ValueEnum};

///TCP local port forward via SSH Tunnel by rust.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// ip address or domain name of ssh server [eg: 192.168.1.5]
    #[arg(long, required(true))]
    pub host: String,

    /// port of ssh server
    #[arg(long, default_value_t = 22)]
    pub port: u16,

    /// username of ssh server
    #[arg(short, long, required(true))]
    pub user: String,

    /// password of ssh server
    #[arg(long, required(true))]
    pub pwd: String,

    #[command(subcommand)]
    pub tunnel: TunnelCommand,
}

#[derive(Debug, Subcommand)]
pub enum TunnelCommand {
    Local {
        /// local listen port for accepting tcp request
        #[arg(short, long, required(true))]
        local_port: u16,

        /// remote host or domain name for ssh server, will be connect this address from ssh server to remote-host:remote-port
        #[arg(long, required(true))]
        remote_host: String,

        /// remote port for remote_host
        #[arg(long, required(true))]
        remote_port: u16,
    },
    Remote {
        /// local host ip for your tcp server, will be connect this address from ssh server to local-host:local-port
        #[arg(long, required(true))]
        local_host: String,

        /// local listen port for accepting tcp request
        #[arg(short, long, required(true))]
        local_port: u16,

        /// remote port for remote_host
        #[arg(long, required(true))]
        remote_port: u16,
    },
}
