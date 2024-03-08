use core::fmt;
use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, Result};
use async_ssh2_lite::{AsyncSession, SessionConfiguration, TokioTcpStream};
use async_std_resolver::resolver_from_system_conf;
//use futures::FutureExt;
use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Receiver,
};

#[derive(Debug)]
pub enum HostAddress<'host> {
    IpAddr(IpAddr),
    HostName(Cow<'host, str>),
}

impl<'host> fmt::Display for HostAddress<'host> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IpAddr(ip_addr) => ip_addr.fmt(f),
            Self::HostName(host_name) => host_name.fmt(f),
        }
    }
}

impl<'host> HostAddress<'host> {
    pub fn into_static(&self) -> HostAddress<'static> {
        match self {
            Self::IpAddr(ip_addr) => HostAddress::IpAddr(*ip_addr),
            Self::HostName(host_name) => {
                HostAddress::HostName(Cow::Owned(host_name.clone().into_owned()))
            }
        }
    }
}

pub enum SshAuthMethod<'auth> {
    KeyPair {
        private_key: Cow<'auth, str>,
        passphrase: Option<Cow<'auth, str>>,
    },
    Password {
        password: Cow<'auth, str>,
    },
}

/// SSH session that has been established.
pub struct SshSession(pub(crate) AsyncSession<async_ssh2_lite::TokioTcpStream>);

impl Deref for SshSession {
    type Target = AsyncSession<async_ssh2_lite::TokioTcpStream>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SshSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub async fn open_local_tunnel(
    exit_signal_rx: Receiver<bool>,
    host_addr: &HostAddress<'_>,
    host_port: u16,
    username: &str,
    auth_method: &SshAuthMethod<'_>,
    local_listen_ip: IpAddr,
    local_listen_port: u16,
    target_host: &HostAddress<'_>,
    target_port: u16,
) -> Result<tokio::task::JoinHandle<()>> {
    let ssh_session = new_ssh_session(host_addr, host_port, username, auth_method).await?;

    let local_socket = SocketAddr::new(local_listen_ip, local_listen_port);
    let spawn_join_handle = open_local_port_forward_channel(
        exit_signal_rx,
        ssh_session,
        local_socket,
        target_host,
        target_port,
    ).await?;

    Ok(spawn_join_handle)
}

pub async fn open_remote_tunnel(
    exit_signal_rx: Receiver<bool>,
    host_addr: &HostAddress<'_>,
    host_port: u16,
    username: &str,
    auth_method: &SshAuthMethod<'_>,
    local_listen_ip: IpAddr,
    local_listen_port: u16,
    remote_port: u16,
) -> Result<tokio::task::JoinHandle<()>> {
    let ssh_session = new_ssh_session(host_addr, host_port, username, auth_method).await?;

    let local_socket = SocketAddr::new(local_listen_ip, local_listen_port);
    let spawn_join_handle = open_remote_port_forward_channel(exit_signal_rx, ssh_session, local_socket, remote_port)
        .await?;

    Ok(spawn_join_handle)
}

async fn new_ssh_session(
    host_addr: &HostAddress<'_>,
    host_port: u16,
    username: &str,
    auth_method: &SshAuthMethod<'_>,
) -> Result<SshSession> {
    let host_ip = match host_addr {
        HostAddress::IpAddr(ip) => ip.to_owned(),
        HostAddress::HostName(host_name) => resolve_ip(host_name).await?,
    };

    info!("ssh server host_ip is: {host_ip}");

    let mut session_config = SessionConfiguration::new();
    session_config.set_compress(true);
    session_config.set_keepalive(false, 30);
    let mut session = AsyncSession::<TokioTcpStream>::connect(
        SocketAddr::from((host_ip, host_port)),
        Some(session_config),
    )
    .await?;

    session.handshake().await?;
    match auth_method {
        SshAuthMethod::KeyPair {
            private_key,
            passphrase,
        } => {
            session
                .userauth_pubkey_file(
                    username,
                    None,
                    Path::new(private_key.as_ref()),
                    passphrase.as_deref(),
                )
                .await?
        }
        SshAuthMethod::Password { password } => {
            session
                .userauth_password(username, password.as_ref())
                .await?
        }
    }

    if !session.authenticated() {
        return Err(anyhow!(
            "try login to {host_addr}:{host_port} auth failed. error:{:?}",
            session.last_error()
        ));
    }

    Ok(SshSession(session))
}

async fn open_local_port_forward_channel(
    exit_signal_rx: Receiver<bool>,
    ssh_session: SshSession,
    local_socket: SocketAddr,
    target_host: &HostAddress<'_>,
    target_port: u16,
) -> Result<tokio::task::JoinHandle<()>> {
    let local_listener = tokio::net::TcpListener::bind(local_socket).await?;
    let target_address = target_host.to_string();
    info!("ssh server target_address is: {target_address}:{target_port}");
    let mut exit_signal_rx = exit_signal_rx;

    //TODO: invoke callback to notify UI is running
    
    let spawn_join_handle: tokio::task::JoinHandle<()> = tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = exit_signal_rx.recv() => {
                    warn!("recv exit_signal, will break loop then exit process.");
                    break;
                }
                r = local_listener.accept() => match r {
                    Ok((mut request_stream, req_socket)) => {
                        let mut request_buf = vec![0; 16384];
                        let mut channel_buf = vec![0; 16384];
                        info!("accept a tcp connect from:{:?}", req_socket);

                        let mut ssh_channel = match (&ssh_session)
                            .channel_direct_tcpip(&target_address, target_port, None)
                            .await
                        {
                            Ok(channel) => channel,
                            Err(err) => {
                                error!("create ssh channel_direct_tcpip error:{:?}", err);
                                tokio::time::sleep(core::time::Duration::from_secs(5)).await;
                                continue;
                            }
                        };

                        tokio::task::spawn(async move {
                            loop {
                                tokio::select! {
                                    ret_request_stream_r = request_stream.read(&mut request_buf) => match ret_request_stream_r{
                                        Ok(0) => {
                                            if let Err(e) = ssh_channel.flush().await {
                                                error!("try flush ssh channel error:{:?}",e);
                                            }
                                            info!("request stream read EOF => will be finish current tcp connect.");
                                            break;
                                        },
                                        Ok(n) => {
                                            if let Err(e) = ssh_channel.write(&request_buf[..n]).await {
                                                error!("ssh_channel write error:{:?} request_buf[..{n}] - bytes:{:?}", e, request_buf);
                                                break;
                                            }
                                        }
                                        Err(e)=>{
                                            error!("request_stream read from request stream error:{:?}", e);
                                            break;
                                        }
                                    },
                                    ret_ssh_channel = ssh_channel.read(&mut channel_buf) => match ret_ssh_channel {
                                        Ok(0) => {
                                            if let Err(e) = request_stream.flush().await {
                                                error!("try flush request stream error:{:?}",e);
                                            }
                                            info!("ssh channel read EOF => will be finish current tcp connect.");
                                            break;
                                        },
                                        Ok(n) => {
                                            if let Err(e) = request_stream.write(&channel_buf[..n]).await {
                                                error!("request_stream write error:{:?} channel_buf[..{n}] - bytes:{:?}", e, channel_buf);
                                                break;
                                            }
                                        }
                                        Err(e)=>{
                                            error!("ssh_channel read from ssh channel error:{:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                            warn!("finish a tcp connect:{:?}", req_socket);
                            if let Err(e) = ssh_channel.close().await {
                                error!("ssh channel close error:{:?}", e)
                            }
                        });
                    }
                    Err(e) => {
                        error!("local tcp listener accept error:{:?}", e);
                    }
                }
            }
        }
    });

    Ok(spawn_join_handle)
}

async fn open_remote_port_forward_channel(
    exit_signal_rx: Receiver<bool>,
    ssh_session: SshSession,
    local_socket: SocketAddr,
    //target_host: &HostAddress<'_>,
    remote_port: u16,
) -> Result<tokio::task::JoinHandle<()>> {
    let (mut remote_listener, port) = ssh_session
        .channel_forward_listen(remote_port, None, None)
        .await?;
    let mut exit_signal_rx = exit_signal_rx;
    //TODO: invoke callback to notify UI is running
    let spawn_join_handle = tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = exit_signal_rx.recv() => {
                    warn!("recv exit_signal, will break loop then exit process.");
                    break;
                }
                r = remote_listener.accept() => match r {
                    Ok(mut ssh_channel) => {
                        let mut response_stream = match TokioTcpStream::connect(local_socket).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!("try connect local:{:?} error:{:?}", local_socket, e);
                                tokio::time::sleep(core::time::Duration::from_secs(5)).await;
                                continue;
                            }
                        };

                        let mut response_buf = vec![0; 16384];
                        let mut channel_buf = vec![0; 16384];

                        tokio::task::spawn(async move {
                            loop {
                                tokio::select! {
                                    ret_ssh_channel = ssh_channel.read(&mut channel_buf) => match ret_ssh_channel {
                                        Ok(0) => {
                                            info!("ssh_channel read EOF => will be finish current tcp connect.");
                                            break;
                                        },
                                        Ok(n) => {
                                            if let Err(e) = response_stream.write(&channel_buf[..n]).await {
                                                error!("response_stream write data error:{e}");
                                                break;
                                            }
                                        },
                                        Err(e) => {
                                            error!("ssh channel read error:{:?}",e);
                                            break;
                                        }
                                    },
                                    ret_response_stream = response_stream.read(&mut response_buf) => match ret_response_stream{
                                        Ok(0) => {
                                            info!("response stream read EOF => will be finish current tcp connect.");
                                            break;
                                        },
                                        Ok(n) => {
                                            if let Err(e) = ssh_channel.write(&response_buf[..n]).await {
                                                error!("ssh_channel write data error:{e}");
                                                break;
                                            }
                                        },
                                        Err(e) => {
                                            error!("response stream read error:{:?}",e);
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("remote ssh listener accept error:{:?}", e);
                    }
                }
            }
        }
    });

    Ok(spawn_join_handle)
}

async fn resolve_ip(host_name: &str) -> Result<IpAddr> {
    let resolver = resolver_from_system_conf().await?;
    let response = resolver.lookup_ip(host_name).await?;

    let ip = response.iter().next().map_or(
        Err(anyhow!("can not relove host name:{host_name} to ip addr.")),
        |i| Ok(i),
    )?;

    Ok(ip)
}
