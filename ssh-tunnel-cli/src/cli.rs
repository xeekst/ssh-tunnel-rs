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

    /// auth method (password or key-pair)
    #[arg(short, long, required(true))]
    pub auth: AuthMethod,

    /// password of ssh server, when auth is password, this is required
    #[arg(long, required(false), default_value_t = String::from(""))]
    pub pwd: String,

    /// your ssh private key file path (usually path: /$HOME/.ssh/<private_key_file>),  when auth is key-pair, will require private_key
    #[arg(long, required(false), default_value_t = String::from(""))]
    pub private_key: String,

    /// password of ssh private key file
    #[arg(long, default_value = None, required(false))]
    pub passphrase: Option<String>,

    #[command(subcommand)]
    pub tunnel: TunnelCommand,
}

#[derive(Debug, Subcommand)]
pub enum TunnelCommand {
    /// Use local port forward ssh server port so that it can access the ports that the SSH server can access
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
    /// Use remote port forward ssh server port so that ssh server can access local port
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

#[derive(ValueEnum, Clone, Debug)]
pub enum AuthMethod {
    Password,
    KeyPair,
}
