use std::{borrow::Cow, net::Ipv4Addr};

use chrono::DateTime;
use fltk::app::GlobalState;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use ssh_tunnel_core::ssh_forward::{open_local_tunnel, open_remote_tunnel, HostAddress, SshAuthMethod};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::ssh_tunnel_view::{SSHTunnelThreadEvent, SSHTunnelThreadEventType};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TunnelType {
    Local,
    Remote,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Status {
    Started,
    Stopped,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSHTunnelJson {
    pub id: i32,
    pub name: String,

    pub forward_type: TunnelType,
    pub forward_port: String,
    pub real_service_host: String,
    pub real_service_port: String,

    pub ssh_user: String,
    pub ssh_host: String,
    pub ssh_port: String,
    pub ssh_pwd: String,
}

#[derive(Debug)]
pub struct SSHTunnel {
    pub id: i32,
    pub name: String,
    pub status: Status,

    pub forward_type: TunnelType,
    pub forward_port: u16,
    pub real_service_host: String,
    pub real_service_port: u16,

    ssh_user: String,
    ssh_host: String,
    ssh_port: u16,
    ssh_pwd: String,

    exit_signal_sendx: Option<Sender<bool>>,
}

impl SSHTunnel {
    pub fn new(
        id: i32,
        name: String,
        status: Status,

        forward_type: TunnelType,
        forward_port: u16,
        real_service_host: String,
        real_service_port: u16,

        ssh_host: String,
        ssh_port: u16,
        ssh_user: String,
        ssh_pwd: String,
    ) -> Self {
        SSHTunnel {
            id,
            name,
            status,
            forward_type,
            forward_port,
            real_service_host,
            real_service_port,
            ssh_user,
            ssh_host,
            ssh_port,
            ssh_pwd,
            exit_signal_sendx: None,
        }
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if self.status == Status::Stopped {
            info!("current ssh tunnel is stopped, will be skip stop command.");
        } else {
            info!("will be stop current ssh tunnel.");
            if let Some(tx) = &self.exit_signal_sendx {
                warn!("send stop signal to tunnel id:{:?}, name:{:?}", self.id, self.name);
                if !tx.is_closed() {
                    tx.send(true).await?;
                }
            }

            self.status = Status::Stopped;
        }

        Ok(())
    }

    pub async fn start(&mut self, ui_tunnel_sx: std::sync::Arc<tokio::sync::Mutex<Sender<SSHTunnelThreadEvent>>>) -> anyhow::Result<()> {
        if self.status == Status::Started {
            warn!("ssh tunnel is started, will be skip create.")
        }
        let (sx, rx) = tokio::sync::mpsc::channel::<bool>(1);
        self.exit_signal_sendx = Some(sx);
        let ssh_host = self.ssh_host.clone();
        let ssh_pwd = self.ssh_pwd.clone();
        let id = self.id;

        let forward_port = self.forward_port.clone();
        let ssh_port = self.ssh_port.clone();
        let ssh_user = self.ssh_user.clone();
        let real_service_host = self.real_service_host.clone();
        let real_service_port = self.real_service_port.clone();

        match self.forward_type {
            TunnelType::Local => {
                let local_listen_ip = std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

                tokio::spawn(async move {
                    // let g: GlobalState<crate::G> = fltk::app::GlobalState::get();
                    // g.with(|gg| println!("thread g:{:?}", gg));
                    // g.with(|gg| {
                    //     gg.name = "THREAD G2".to_string();
                    // });
                    let host_addr = HostAddress::HostName(Cow::Borrowed(&ssh_host));
                    let ssh_auth = SshAuthMethod::Password {
                        password: Cow::Borrowed(&ssh_pwd),
                    };
                    let real_service_host = HostAddress::HostName(Cow::Borrowed(&real_service_host));

                    let join_handle = match open_local_tunnel(
                        rx,
                        &host_addr,
                        ssh_port,
                        &ssh_user,
                        &ssh_auth,
                        local_listen_ip,
                        forward_port,
                        &real_service_host,
                        real_service_port,
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(err) => {
                            let err_msg = format!("open local tunnel error:{:?}", err);
                            error!("{err_msg}");
                            let event = SSHTunnelThreadEvent {
                                event_type: SSHTunnelThreadEventType::CommonError,
                                data: format!("{id}|[{}]{err_msg}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f")),
                            };
                            if let Err(serr) = ui_tunnel_sx.lock().await.send(event).await {
                                error!("open local tunnel -> ui_sx send msg error:{:?}", serr);
                            }
                            return;
                        }
                    };

                    info!(
                        "start a local tunnel forward local(0.0.0.0:{}) -> ssh({:?}:{}) -> remote({}:{})",
                        forward_port, host_addr, ssh_port, real_service_host, real_service_port
                    );
                    if let Err(thread_err) = join_handle.await {
                        error!("await thread for ssh_tunnel:{:?} error:{:?}", ssh_host, thread_err);
                    }
                });
            }
            TunnelType::Remote => {
                tokio::spawn(async move {
                    let host_addr = HostAddress::HostName(Cow::Borrowed(&ssh_host));
                    let ssh_auth = SshAuthMethod::Password {
                        password: Cow::Borrowed(&ssh_pwd),
                    };
                    let real_service_host = std::net::IpAddr::V4(match real_service_host.parse::<Ipv4Addr>() {
                        Ok(r) => r,
                        Err(err) => {
                            let err_msg = format!("open temote tunnel try parse:{real_service_host} error:{:?}", err);
                            error!("{err_msg}");
                            let event = SSHTunnelThreadEvent {
                                event_type: SSHTunnelThreadEventType::CommonError,
                                data: format!("{id}|[{}]{err_msg}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f")),
                            };
                            if let Err(serr) = ui_tunnel_sx.lock().await.send(event).await {
                                error!("open local tunnel -> ui_sx send msg error:{:?}", serr);
                            }

                            return;
                        }
                    });
                    let join_handle = match open_remote_tunnel(
                        rx,
                        &host_addr,
                        ssh_port,
                        &ssh_user,
                        &ssh_auth,
                        real_service_host,
                        real_service_port,
                        forward_port,
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(err) => {
                            error!("open temote tunnel error:{:?}", err);

                            return;
                        }
                    };

                    info!(
                        "start a remote tunnel forward remote(127.0.0.1:{}) -> ssh({:?}:{}) -> local({}:{})",
                        forward_port, host_addr, ssh_port, real_service_host, real_service_port
                    );
                    if let Err(thread_err) = join_handle.await {
                        error!("await thread for ssh_tunnel:{:?} error:{:?}", ssh_host, thread_err);
                    }
                });
            }
        }
        self.status = Status::Started;

        Ok(())
    }
}
