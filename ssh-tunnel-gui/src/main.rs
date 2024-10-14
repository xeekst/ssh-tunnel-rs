mod basic_view;
mod config;
mod ssh_tunnel;
mod ssh_tunnel_view;

use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Stdin, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use std::{fs, thread};

use anyhow::Ok;
use fern::colors::ColoredLevelConfig;
use fltk::app::{self, Receiver, Sender};
use fltk::browser::*;
use fltk::button::*;
use fltk::dialog::*;
use fltk::enums::*;
use fltk::frame::*;
use fltk::group::*;
use fltk::image::*;
use fltk::input::*;
use fltk::menu::*;
use fltk::misc::*;
use fltk::output::*;
use fltk::prelude::*;
use fltk::table::*;
use fltk::text::*;
use fltk::tree::*;
use fltk::valuator::*;
use fltk::widget::*;
use fltk::window::*;
use fltk_theme::{ThemeType, WidgetTheme};
use log::info;
use serde::Deserialize;
use ssh_tunnel::{SSHTunnel, SSHTunnelJson};
use ssh_tunnel_view::{SSHTunnelCommand, SSHTunnelView};

use crate::ssh_tunnel_view::handle_view_msg;

lazy_static::lazy_static! {
    pub static ref RWLOCK_MSG_CHANNEL: RwLock<(Sender<UiMessage>, Receiver<UiMessage>)> =
        RwLock::new(fltk::app::channel::<UiMessage>());
}

const AUTO_SAVE_TIMESPAN: i64 = 5;

#[derive(Debug)]
pub struct UiMessage {
    pub msg_type: MsgType,
    pub msg: String,
}

#[derive(Debug, PartialEq)]
pub enum MsgType {
    INFO,
    ERROR,

    AddLocalTunnelRow,
    AddRemoteTunnelRow,
    ResizeMainWindow,
    StartTunnel,
    AppendTunnelDialogErrorText,
    StopTunnel,
    DeleteTunnel,
    UpdateConfig,
    ShowTunnelInfoDialog,
}

#[derive(Debug)]
pub struct GS {
    pub name: String,
}

fn main() {
    init_log().expect("init log error:");
    let app = app::App::default();
    let (screen_width, screen_height) = app::screen_size();
    let widget_theme = WidgetTheme::new(ThemeType::AquaClassic);
    widget_theme.apply();
    let mut view = SSHTunnelView::new();
    view.init();
    // view.basic_view
    //     .scroll_view
    //     .remove(&view.basic_view.tunnel_row);
    // view.add_ssh_tunnel_row();

   // let g = app::GlobalState::new(G { name: "G1".to_string() });

    //let mut map: HashMap<usize, SSHTunnel> = HashMap::new();
    let (mut command_sx, command_rx) = std::sync::mpsc::channel::<(SSHTunnelCommand, Option<SSHTunnel>, i32)>();
    ssh_tunnel_view::handle_ssh_tunnel_event(command_rx);
    let mut last_save_time = chrono::Local::now();

    app::add_idle3(move |_handle| match RWLOCK_MSG_CHANNEL.read() {
        Err(err) => fltk::dialog::alert_default(&format!("RWLOCK_MSG_CHANNEL error:{:?}", err)),
        core::result::Result::Ok(r) => {
            let ui_msg = r.1.recv();
            if let Some(m) = ui_msg {
                handle_view_msg((screen_width, screen_height), &mut view, m, &mut command_sx);
            } else {
                thread::sleep(Duration::from_millis(1));
            }

            if (chrono::Local::now() - last_save_time) > chrono::Duration::seconds(crate::AUTO_SAVE_TIMESPAN) {
                last_save_time = chrono::Local::now();
                ssh_tunnel_view::save_config(&mut view);
            }
        }
    });

    app.run().unwrap();
}

fn init_log() -> anyhow::Result<()> {
    let colors = ColoredLevelConfig::new().debug(fern::colors::Color::Magenta).info(fern::colors::Color::Green);
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
