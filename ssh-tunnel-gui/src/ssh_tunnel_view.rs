use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use fltk::app::GlobalState;
use fltk::browser::*;
use fltk::button::*;
use fltk::dialog::*;
use fltk::enums::*;
use fltk::frame::*;
use fltk::group::*;
use fltk::image::*;
use fltk::image::{PngImage, RgbImage, SharedImage};
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
use image::{DynamicImage, ImageBuffer, Rgba};
use log::error;
use log::info;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::basic_view::BasicView;
use crate::config;
use crate::ssh_tunnel::SSHTunnel;
use crate::ssh_tunnel::SSHTunnelJson;
use crate::ssh_tunnel::TunnelType;
use crate::MsgType;
use crate::UiMessage;
use crate::RWLOCK_MSG_CHANNEL;
use anyhow::{anyhow, Result};

//const IMG_MAIN_ICON: &[u8; 3619] = include_bytes!("../asset/network.png");
const IMG_MAIN_ICON: &[u8; 2474] = include_bytes!("../asset/pipeline.png");
const IMG_ADD: &[u8; 631] = include_bytes!("../asset/add.png");
const IMG_DEL: &[u8; 616] = include_bytes!("../asset/del.png");
const IMG_INACTIVE_PLAY: &[u8; 642] = include_bytes!("../asset/inactive_play.png");
const IMG_INACTIVE_STOP: &[u8; 631] = include_bytes!("../asset/inactive_stop.png");
const IMG_INACTIVE_DEL: &[u8; 565] = include_bytes!("../asset/inactive_del.png");
const IMG_PLAY: &[u8; 738] = include_bytes!("../asset/play.png");
const IMG_STOP: &[u8; 607] = include_bytes!("../asset/stop.png");

pub struct SSHTunnelView {
    pub basic_view: BasicView,

    pub tunnel_rows: Vec<SSHTunnelRow>,
    //pub ssh_tunnels_dict: HashMap<i32, SSHTunnel>,
}

#[derive(Debug)]
pub struct SSHTunnelRow {
    pub id: i32,
    pub tunnel_type: TunnelType,

    pub row_group: Group,
    pub index_txt: Frame,
    pub name_input: Input,
    pub forward_type_box: Frame,
    pub start_btn: Button,
    pub stop_btn: Button,
    pub del_btn: Button,

    pub img_gray_line: Frame,
    pub info_btn: Button,
    pub img_pc: Frame,
    pub img_arrow1: Frame,
    pub img_arrow2: Frame,
    pub img_arrow3: Frame,
    pub img_firewall: Frame,
    pub listen_addr_box: Frame,
    pub ssh_server_box: Frame,
    pub real_service_addr_box: Frame,

    // 指新创建的一个监听TCP服务地址
    // 类型为: Local =>  是在本机监听的一个TCP端口，供本机服务访问该端口
    // 类型为: Remote => 是在远程ssh服务器监听的一个TCP端口，以供ssh服务器可以访问该端口
    pub listen_port_input: Input,
    pub ssh_server_host_input: Input,
    pub ssh_server_port_input: Input,
    pub ssh_server_username_input: Input,
    pub ssh_server_pwd_input: SecretInput,
    // real service 是指实际提供服务 ip:port
    // 类型为: Local =>  是在远程服务器上的某个服务
    // 类型为: Remote => 是在本机上可访问的某个服务
    pub real_service_host_input: Input,
    pub real_service_port_input: Input,

    pub info_data: String,
}

impl SSHTunnelView {
    pub fn new() -> Self {
        let mut view = BasicView::make_window();
        view.main_window = view.main_window.center_screen();
        SSHTunnelView {
            basic_view: view,
            tunnel_rows: vec![],
            //ssh_tunnels_dict: HashMap::new(),
        }
    }

    pub fn init(&mut self) {
        self.basic_view.main_window.resize_callback(|_, x, y, w, h| {
            send(UiMessage {
                msg_type: MsgType::ResizeMainWindow,
                msg: format!("{x}|{y}|{w}|{h}"),
            })
        });
        self.basic_view.main_window.set_icon(Some(trans_bytes_to_png(IMG_MAIN_ICON, 128, 128)));
        self.basic_view.add_local_tunnel_btn.set_callback(|b| {
            send(UiMessage {
                msg_type: MsgType::AddLocalTunnelRow,
                msg: String::from(""),
            })
        });
        self.basic_view.add_remote_tunnel_btn.set_callback(|b| {
            send(UiMessage {
                msg_type: MsgType::AddRemoteTunnelRow,
                msg: String::from(""),
            })
        });
        self.basic_view.local_tunnel_group.hide();
        self.basic_view.remote_tunnel_group.hide();
        self.basic_view.save_btn.set_callback(|_| {
            send(UiMessage {
                msg_type: MsgType::UpdateConfig,
                msg: "".to_owned(),
            })
        });
        self.init_data();
    }

    pub fn init_data(&mut self) {
        let configs = config::read_config().unwrap();
        for config in configs {
            match config.forward_type {
                TunnelType::Local => self.add_ssh_local_tunnel_row(Some(config)),
                TunnelType::Remote => self.add_ssh_remote_tunnel_row(Some(config)),
            }
        }
    }

    pub fn add_ssh_remote_tunnel_row(&mut self, data: Option<SSHTunnelJson>) {
        let idx = self.tunnel_rows.len() as i32;
        let id = idx;
        let y_offset = (self.basic_view.local_tunnel_group.h() + 10) * idx;
        let mut tunnel_group = Group::new(
            self.basic_view.local_tunnel_group.x(),
            self.basic_view.local_tunnel_group.y() + y_offset,
            self.basic_view.local_tunnel_group.w(),
            self.basic_view.local_tunnel_group.h(),
            "",
        );
        tunnel_group.set_frame(FrameType::UpBox);
        tunnel_group.set_color(Color::by_index(54));
        tunnel_group.set_label_color(Color::by_index(54));
        tunnel_group.set_align(unsafe { std::mem::transmute(0) });
        self.basic_view.scroll_view.add(&tunnel_group);

        let mut index_txt = Frame::new(
            self.basic_view.index_txt.x(),
            self.basic_view.index_txt.y() + y_offset,
            self.basic_view.index_txt.w(),
            self.basic_view.index_txt.h(),
            None,
        );
        index_txt.set_color(Color::by_index(46));
        index_txt.set_label_font(Font::by_index(1));
        index_txt.set_label_color(Color::by_index(229));
        index_txt.set_label(&format!("{idx}"));
        tunnel_group.add(&index_txt);

        let mut name_input = Input::new(
            self.basic_view.name_input.x(),
            self.basic_view.name_input.y() + y_offset,
            self.basic_view.name_input.w(),
            self.basic_view.name_input.h(),
            "",
        );
        name_input.set_align(Align::Left);

        tunnel_group.add(&name_input);

        let mut remote_tunnel_type_box = Frame::new(
            self.basic_view.remote_tunnel_type_box.x(),
            self.basic_view.local_tunnel_type_box.y() + y_offset,
            self.basic_view.remote_tunnel_type_box.w(),
            self.basic_view.remote_tunnel_type_box.h(),
            "Remote Tunnel",
        );
        remote_tunnel_type_box.set_label_font(Font::by_index(1));
        remote_tunnel_type_box.set_label_color(Color::by_index(229));
        tunnel_group.add(&remote_tunnel_type_box);

        let mut start_btn = Button::new(
            self.basic_view.start_btn.x(),
            self.basic_view.start_btn.y() + y_offset,
            self.basic_view.start_btn.w(),
            self.basic_view.start_btn.h(),
            None,
        );

        start_btn.set_tooltip("start tunnel");

        start_btn.set_image(Some(trans_bytes_to_png(IMG_PLAY, 24, 24)));
        start_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_PLAY, 24, 24)));
        start_btn.set_frame(FrameType::FlatBox);
        start_btn.set_color(Color::by_index(255));
        start_btn.set_align(unsafe { std::mem::transmute(16) });
        start_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::StartTunnel,
                msg: id.to_string(),
            })
        });
        tunnel_group.add(&start_btn);

        let mut stop_btn = Button::new(
            self.basic_view.stop_btn.x(),
            self.basic_view.stop_btn.y() + y_offset,
            self.basic_view.stop_btn.w(),
            self.basic_view.stop_btn.h(),
            None,
        );
        stop_btn.set_tooltip("stop tunnel");
        stop_btn.set_image(Some(trans_bytes_to_png(IMG_STOP, 24, 24)));
        stop_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_STOP, 24, 24)));
        stop_btn.set_frame(FrameType::FlatBox);
        stop_btn.set_color(Color::by_index(255));
        stop_btn.set_align(unsafe { std::mem::transmute(16) });
        stop_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::StopTunnel,
                msg: id.to_string(),
            })
        });
        stop_btn.deactivate();
        stop_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::StopTunnel,
                msg: id.to_string(),
            })
        });
        tunnel_group.add(&stop_btn);

        let mut del_btn = Button::new(
            self.basic_view.del_btn.x(),
            self.basic_view.del_btn.y() + y_offset,
            self.basic_view.del_btn.w(),
            self.basic_view.del_btn.h(),
            None,
        );
        del_btn.set_tooltip("delete this tunnel");
        del_btn.set_image(Some(trans_bytes_to_png(IMG_DEL, 24, 24)));
        del_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_DEL, 24, 24)));
        del_btn.set_frame(FrameType::FlatBox);
        del_btn.set_color(Color::by_index(255));
        del_btn.set_align(unsafe { std::mem::transmute(16) });
        del_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::DeleteTunnel,
                msg: id.to_string(),
            })
        });
        tunnel_group.add(&del_btn);

        let mut img_gray_line = Frame::new(
            self.basic_view.gray_line.x(),
            self.basic_view.gray_line.y() + y_offset,
            self.basic_view.gray_line.w(),
            self.basic_view.gray_line.h(),
            None,
        );
        img_gray_line.set_frame(FrameType::FlatBox);
        img_gray_line.set_color(Color::by_index(38));
        img_gray_line.set_label_type(LabelType::None);
        tunnel_group.add(&img_gray_line);

        let mut info_btn_remote = Button::new(
            self.basic_view.info_btn_remote.x(),
            self.basic_view.info_btn_local.y() + y_offset,
            self.basic_view.info_btn_remote.w(),
            self.basic_view.info_btn_remote.h(),
            "!",
        );
        info_btn_remote.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::ShowTunnelInfoDialog,
                msg: id.to_string(),
            })
        });
        info_btn_remote.set_label_color(Color::by_index(38));
        tunnel_group.add(&info_btn_remote);

        let mut img_pc = Frame::new(
            self.basic_view.img_pc.x(),
            self.basic_view.img_pc.y() + y_offset,
            self.basic_view.img_pc.w(),
            self.basic_view.img_pc.h(),
            "💻",
        );
        img_pc.set_label_size(40);

        tunnel_group.add(&img_pc);

        let mut img_arrow1 = Frame::new(
            self.basic_view.img_left_arrow1.x(),
            self.basic_view.img_right_arrow1.y() + y_offset,
            self.basic_view.img_left_arrow1.w(),
            self.basic_view.img_left_arrow1.h(),
            "❮🠔",
        );
        img_arrow1.set_frame(FrameType::FlatBox);
        img_arrow1.set_color(Color::by_index(53));
        img_arrow1.set_label_type(LabelType::Engraved);
        img_arrow1.set_label_font(Font::by_index(1));
        img_arrow1.set_label_size(15);
        img_arrow1.set_label_color(Color::by_index(229));
        tunnel_group.add(&img_arrow1);
        let mut img_arrow2 = Frame::new(
            self.basic_view.img_left_arrow2.x(),
            self.basic_view.img_right_arrow2.y() + y_offset,
            self.basic_view.img_left_arrow2.w(),
            self.basic_view.img_left_arrow2.h(),
            "❮🠔",
        );
        img_arrow2.set_frame(FrameType::FlatBox);
        img_arrow2.set_color(Color::by_index(53));
        img_arrow2.set_label_type(LabelType::Engraved);
        img_arrow2.set_label_font(Font::by_index(1));
        img_arrow2.set_label_size(15);
        img_arrow2.set_label_color(Color::by_index(229));
        tunnel_group.add(&img_arrow2);
        let mut img_arrow3 = Frame::new(
            self.basic_view.img_left_arrow3.x(),
            self.basic_view.img_right_arrow3.y() + y_offset,
            self.basic_view.img_left_arrow3.w(),
            self.basic_view.img_left_arrow3.h(),
            "❮🠔",
        );
        img_arrow3.set_frame(FrameType::FlatBox);
        img_arrow3.set_color(Color::by_index(53));
        img_arrow3.set_label_type(LabelType::Engraved);
        img_arrow3.set_label_font(Font::by_index(1));
        img_arrow3.set_label_size(15);
        img_arrow3.set_label_color(Color::by_index(229));
        tunnel_group.add(&img_arrow3);

        let mut img_firewall = Frame::new(
            self.basic_view.remote_img_firewall.x(),
            self.basic_view.img_firewall.y() + y_offset,
            self.basic_view.remote_img_firewall.w(),
            self.basic_view.remote_img_firewall.h(),
            "firewall",
        );
        img_firewall.set_frame(FrameType::FlatBox);
        img_firewall.set_color(Color::by_index(92));
        img_firewall.set_label_type(LabelType::Embossed);
        img_firewall.set_label_color(Color::by_index(90));
        img_firewall.set_align(unsafe { std::mem::transmute(1) });
        tunnel_group.add(&img_firewall);

        let mut real_service_addr_box = Frame::new(
            self.basic_view.real_service_addr_box_remote.x(),
            self.basic_view.remote_addr_box.y() + y_offset,
            self.basic_view.real_service_addr_box_remote.w(),
            self.basic_view.real_service_addr_box_remote.h(),
            "local service addr",
        );
        real_service_addr_box.set_frame(FrameType::UpBox);
        real_service_addr_box.set_label_type(LabelType::Embossed);
        real_service_addr_box.set_label_color(Color::by_index(229));
        real_service_addr_box.set_align(unsafe { std::mem::transmute(1) });
        tunnel_group.add(&real_service_addr_box);

        let mut real_service_host_input = Input::new(
            self.basic_view.local_host_input.x(),
            self.basic_view.remote_host_input.y() + y_offset,
            self.basic_view.local_host_input.w(),
            self.basic_view.local_host_input.h(),
            "",
        );
        tunnel_group.add(&real_service_host_input);
        let mut real_service_port_input = Input::new(
            self.basic_view.local_port_input.x(),
            self.basic_view.remote_port_input.y() + y_offset,
            self.basic_view.local_port_input.w(),
            self.basic_view.local_port_input.h(),
            ":",
        );
        tunnel_group.add(&real_service_port_input);

        let mut ssh_server_box = Frame::new(
            self.basic_view.ssh_server_box.x(),
            self.basic_view.ssh_server_box.y() + y_offset,
            self.basic_view.ssh_server_box.w(),
            self.basic_view.ssh_server_box.h(),
            "SSH Server",
        );
        ssh_server_box.set_frame(FrameType::UpBox);
        ssh_server_box.set_label_type(LabelType::Embossed);
        ssh_server_box.set_label_color(Color::by_index(229));
        ssh_server_box.set_align(unsafe { std::mem::transmute(1) });
        tunnel_group.add(&ssh_server_box);

        let mut ssh_server_host_input = Input::new(
            self.basic_view.ssh_server_ip_input.x(),
            self.basic_view.ssh_server_ip_input.y() + y_offset,
            self.basic_view.ssh_server_ip_input.w(),
            self.basic_view.ssh_server_ip_input.h(),
            "host:",
        );
        tunnel_group.add(&ssh_server_host_input);

        let mut ssh_server_port_input = Input::new(
            self.basic_view.ssh_port_input.x(),
            self.basic_view.ssh_port_input.y() + y_offset,
            self.basic_view.ssh_port_input.w(),
            self.basic_view.ssh_port_input.h(),
            "port:",
        );
        tunnel_group.add(&ssh_server_port_input);

        let mut ssh_server_username_input = Input::new(
            self.basic_view.ssh_username_input.x(),
            self.basic_view.ssh_username_input.y() + y_offset,
            self.basic_view.ssh_username_input.w(),
            self.basic_view.ssh_username_input.h(),
            "user:",
        );
        tunnel_group.add(&ssh_server_username_input);

        let mut ssh_server_pwd_input = SecretInput::new(
            self.basic_view.ssh_pwd_input.x(),
            self.basic_view.ssh_pwd_input.y() + y_offset,
            self.basic_view.ssh_pwd_input.w(),
            self.basic_view.ssh_pwd_input.h(),
            "pwd:",
        );
        tunnel_group.add(&ssh_server_pwd_input);

        let mut listen_addr_box = Frame::new(
            self.basic_view.remote_listen_addr_box.x(),
            self.basic_view.local_listen_addr_box.y() + y_offset,
            self.basic_view.remote_listen_addr_box.w(),
            self.basic_view.remote_listen_addr_box.h(),
            "remote listen addr",
        );
        listen_addr_box.set_frame(FrameType::UpBox);
        listen_addr_box.set_label_type(LabelType::Embossed);
        listen_addr_box.set_label_color(Color::by_index(229));
        listen_addr_box.set_align(unsafe { std::mem::transmute(1) });
        tunnel_group.add(&listen_addr_box);

        let mut listen_port_input = Input::new(
            self.basic_view.forward_port_input_remote.x(),
            self.basic_view.forward_port_input.y() + y_offset,
            self.basic_view.forward_port_input_remote.w(),
            self.basic_view.forward_port_input_remote.h(),
            "127.0.0.1:",
        );
        tunnel_group.add(&listen_port_input);

        if let Some(d) = data {
            name_input.set_value(&d.name);
            listen_port_input.set_value(&d.forward_port.to_string());
            ssh_server_host_input.set_value(&d.ssh_host);
            ssh_server_port_input.set_value(&d.ssh_port.to_string());
            ssh_server_username_input.set_value(&d.ssh_user);
            ssh_server_pwd_input.set_value(&d.ssh_pwd);
            real_service_host_input.set_value(&d.real_service_host);
            real_service_port_input.set_value(&d.real_service_port.to_string());
        }

        let row = SSHTunnelRow {
            id: idx,
            tunnel_type: TunnelType::Remote,
            row_group: tunnel_group,
            index_txt,
            name_input,
            forward_type_box: remote_tunnel_type_box,
            start_btn,
            stop_btn,
            del_btn,
            info_btn: info_btn_remote,
            img_gray_line,
            img_pc,
            img_arrow1,
            img_arrow2,
            img_arrow3,
            img_firewall,
            listen_addr_box,
            ssh_server_box,
            real_service_addr_box,
            listen_port_input,
            ssh_server_host_input,
            ssh_server_port_input,
            ssh_server_username_input,
            ssh_server_pwd_input,
            real_service_host_input,
            real_service_port_input,
            info_data: "".to_owned(),
        };

        self.tunnel_rows.push(row);
    }

    pub fn add_ssh_local_tunnel_row(&mut self, data: Option<SSHTunnelJson>) {
        let idx = self.tunnel_rows.len() as i32;
        let id = idx;
        let y_offset = (self.basic_view.local_tunnel_group.h() + 10) * idx;
        let mut local_tunnel_group = Group::new(
            self.basic_view.local_tunnel_group.x(),
            self.basic_view.local_tunnel_group.y() + y_offset,
            self.basic_view.local_tunnel_group.w(),
            self.basic_view.local_tunnel_group.h(),
            "",
        );
        local_tunnel_group.set_frame(FrameType::UpBox);
        local_tunnel_group.set_color(Color::by_index(54));
        local_tunnel_group.set_label_color(Color::by_index(54));
        local_tunnel_group.set_align(unsafe { std::mem::transmute(0) });
        self.basic_view.scroll_view.add(&local_tunnel_group);

        let mut index_txt = Frame::new(
            self.basic_view.index_txt.x(),
            self.basic_view.index_txt.y() + y_offset,
            self.basic_view.index_txt.w(),
            self.basic_view.index_txt.h(),
            None,
        );
        index_txt.set_color(Color::by_index(46));
        index_txt.set_label_font(Font::by_index(1));
        index_txt.set_label_color(Color::by_index(229));
        index_txt.set_label(&format!("{idx}"));
        local_tunnel_group.add(&index_txt);

        let mut name_input = Input::new(
            self.basic_view.name_input.x(),
            self.basic_view.name_input.y() + y_offset,
            self.basic_view.name_input.w(),
            self.basic_view.name_input.h(),
            "",
        );
        name_input.set_align(Align::Left);
        local_tunnel_group.add(&name_input);

        let mut local_tunnel_type_box = Frame::new(
            self.basic_view.local_tunnel_type_box.x(),
            self.basic_view.local_tunnel_type_box.y() + y_offset,
            self.basic_view.local_tunnel_type_box.w(),
            self.basic_view.local_tunnel_type_box.h(),
            "Local Tunnel",
        );
        local_tunnel_type_box.set_label_font(Font::by_index(1));
        local_tunnel_type_box.set_label_color(Color::by_index(229));
        local_tunnel_group.add(&local_tunnel_type_box);

        let mut start_btn = Button::new(
            self.basic_view.start_btn.x(),
            self.basic_view.start_btn.y() + y_offset,
            self.basic_view.start_btn.w(),
            self.basic_view.start_btn.h(),
            None,
        );
        start_btn.set_tooltip("start tunnel");
        start_btn.set_image(Some(trans_bytes_to_png(IMG_PLAY, 24, 24)));
        start_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_PLAY, 24, 24)));
        start_btn.set_frame(FrameType::FlatBox);
        start_btn.set_color(Color::by_index(255));
        start_btn.set_align(unsafe { std::mem::transmute(16) });
        start_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::StartTunnel,
                msg: id.to_string(),
            })
        });
        local_tunnel_group.add(&start_btn);

        let mut stop_btn = Button::new(
            self.basic_view.stop_btn.x(),
            self.basic_view.stop_btn.y() + y_offset,
            self.basic_view.stop_btn.w(),
            self.basic_view.stop_btn.h(),
            None,
        );
        stop_btn.set_tooltip("stop tunnel");
        stop_btn.set_image(Some(trans_bytes_to_png(IMG_STOP, 24, 24)));
        stop_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_STOP, 24, 24)));
        stop_btn.set_frame(FrameType::FlatBox);
        stop_btn.set_color(Color::by_index(255));
        stop_btn.set_align(unsafe { std::mem::transmute(16) });
        stop_btn.deactivate();
        stop_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::StopTunnel,
                msg: id.to_string(),
            })
        });
        local_tunnel_group.add(&stop_btn);

        let mut del_btn = Button::new(
            self.basic_view.del_btn.x(),
            self.basic_view.del_btn.y() + y_offset,
            self.basic_view.del_btn.w(),
            self.basic_view.del_btn.h(),
            None,
        );

        del_btn.set_tooltip("delete this tunnel");
        del_btn.set_image(Some(trans_bytes_to_png(IMG_DEL, 24, 24)));
        del_btn.set_deimage(Some(trans_bytes_to_png(IMG_INACTIVE_DEL, 24, 24)));
        del_btn.set_frame(FrameType::FlatBox);
        del_btn.set_color(Color::by_index(255));
        del_btn.set_align(unsafe { std::mem::transmute(16) });
        del_btn.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::DeleteTunnel,
                msg: id.to_string(),
            })
        });
        local_tunnel_group.add(&del_btn);

        let mut img_gray_line = Frame::new(
            self.basic_view.gray_line.x(),
            self.basic_view.gray_line.y() + y_offset,
            self.basic_view.gray_line.w(),
            self.basic_view.gray_line.h(),
            None,
        );
        img_gray_line.set_frame(FrameType::FlatBox);
        img_gray_line.set_color(Color::by_index(38));
        img_gray_line.set_label_type(LabelType::None);
        local_tunnel_group.add(&img_gray_line);

        let mut info_btn_local = Button::new(
            self.basic_view.info_btn_local.x(),
            self.basic_view.info_btn_local.y() + y_offset,
            self.basic_view.info_btn_local.w(),
            self.basic_view.info_btn_local.h(),
            "!",
        );
        info_btn_local.set_callback(move |b| {
            send(UiMessage {
                msg_type: MsgType::ShowTunnelInfoDialog,
                msg: id.to_string(),
            })
        });
        info_btn_local.set_label_color(Color::by_index(38));
        local_tunnel_group.add(&info_btn_local);

        let mut img_pc = Frame::new(
            self.basic_view.img_pc.x(),
            self.basic_view.img_pc.y() + y_offset,
            self.basic_view.img_pc.w(),
            self.basic_view.img_pc.h(),
            "💻",
        );
        img_pc.set_label_size(40);

        local_tunnel_group.add(&img_pc);

        let mut img_arrow1 = Frame::new(
            self.basic_view.img_right_arrow1.x(),
            self.basic_view.img_right_arrow1.y() + y_offset,
            self.basic_view.img_right_arrow1.w(),
            self.basic_view.img_right_arrow1.h(),
            "🠖❯",
        );
        img_arrow1.set_frame(FrameType::FlatBox);
        img_arrow1.set_color(Color::by_index(53));
        img_arrow1.set_label_type(LabelType::Engraved);
        img_arrow1.set_label_font(Font::by_index(1));
        img_arrow1.set_label_size(15);
        img_arrow1.set_label_color(Color::by_index(229));
        local_tunnel_group.add(&img_arrow1);
        let mut img_arrow2 = Frame::new(
            self.basic_view.img_right_arrow2.x(),
            self.basic_view.img_right_arrow2.y() + y_offset,
            self.basic_view.img_right_arrow2.w(),
            self.basic_view.img_right_arrow2.h(),
            "🠖❯",
        );
        img_arrow2.set_frame(FrameType::FlatBox);
        img_arrow2.set_color(Color::by_index(53));
        img_arrow2.set_label_type(LabelType::Engraved);
        img_arrow2.set_label_font(Font::by_index(1));
        img_arrow2.set_label_size(15);
        img_arrow2.set_label_color(Color::by_index(229));
        local_tunnel_group.add(&img_arrow2);
        let mut img_arrow3 = Frame::new(
            self.basic_view.img_right_arrow3.x(),
            self.basic_view.img_right_arrow3.y() + y_offset,
            self.basic_view.img_right_arrow3.w(),
            self.basic_view.img_right_arrow3.h(),
            "🠖❯",
        );
        img_arrow3.set_frame(FrameType::FlatBox);
        img_arrow3.set_color(Color::by_index(53));
        img_arrow3.set_label_type(LabelType::Engraved);
        img_arrow3.set_label_font(Font::by_index(1));
        img_arrow3.set_label_size(15);
        img_arrow3.set_label_color(Color::by_index(229));
        local_tunnel_group.add(&img_arrow3);

        let mut img_firewall = Frame::new(
            self.basic_view.img_firewall.x(),
            self.basic_view.img_firewall.y() + y_offset,
            self.basic_view.img_firewall.w(),
            self.basic_view.img_firewall.h(),
            "firewall",
        );
        img_firewall.set_frame(FrameType::FlatBox);
        img_firewall.set_color(Color::by_index(92));
        img_firewall.set_label_type(LabelType::Embossed);
        img_firewall.set_label_color(Color::by_index(90));
        img_firewall.set_align(unsafe { std::mem::transmute(1) });
        local_tunnel_group.add(&img_firewall);

        let mut listen_addr_box = Frame::new(
            self.basic_view.local_listen_addr_box.x(),
            self.basic_view.local_listen_addr_box.y() + y_offset,
            self.basic_view.local_listen_addr_box.w(),
            self.basic_view.local_listen_addr_box.h(),
            "local listen addr",
        );
        listen_addr_box.set_frame(FrameType::UpBox);
        listen_addr_box.set_label_type(LabelType::Embossed);
        listen_addr_box.set_label_color(Color::by_index(229));
        listen_addr_box.set_align(unsafe { std::mem::transmute(1) });
        local_tunnel_group.add(&listen_addr_box);

        let mut ssh_server_box = Frame::new(
            self.basic_view.ssh_server_box.x(),
            self.basic_view.ssh_server_box.y() + y_offset,
            self.basic_view.ssh_server_box.w(),
            self.basic_view.ssh_server_box.h(),
            "SSH Server",
        );
        ssh_server_box.set_frame(FrameType::UpBox);
        ssh_server_box.set_label_type(LabelType::Embossed);
        ssh_server_box.set_label_color(Color::by_index(229));
        ssh_server_box.set_align(unsafe { std::mem::transmute(1) });
        local_tunnel_group.add(&ssh_server_box);

        let mut real_service_addr_box = Frame::new(
            self.basic_view.remote_addr_box.x(),
            self.basic_view.remote_addr_box.y() + y_offset,
            self.basic_view.remote_addr_box.w(),
            self.basic_view.remote_addr_box.h(),
            "remote service addr",
        );
        real_service_addr_box.set_frame(FrameType::UpBox);
        real_service_addr_box.set_label_type(LabelType::Embossed);
        real_service_addr_box.set_label_color(Color::by_index(229));
        real_service_addr_box.set_align(unsafe { std::mem::transmute(1) });
        local_tunnel_group.add(&real_service_addr_box);

        let mut listen_port_input = Input::new(
            self.basic_view.forward_port_input.x(),
            self.basic_view.forward_port_input.y() + y_offset,
            self.basic_view.forward_port_input.w(),
            self.basic_view.forward_port_input.h(),
            "0.0.0.0:",
        );
        local_tunnel_group.add(&listen_port_input);

        let mut ssh_server_host_input = Input::new(
            self.basic_view.ssh_server_ip_input.x(),
            self.basic_view.ssh_server_ip_input.y() + y_offset,
            self.basic_view.ssh_server_ip_input.w(),
            self.basic_view.ssh_server_ip_input.h(),
            "host:",
        );
        local_tunnel_group.add(&ssh_server_host_input);

        let mut ssh_server_port_input = Input::new(
            self.basic_view.ssh_port_input.x(),
            self.basic_view.ssh_port_input.y() + y_offset,
            self.basic_view.ssh_port_input.w(),
            self.basic_view.ssh_port_input.h(),
            "port:",
        );
        local_tunnel_group.add(&ssh_server_port_input);

        let mut ssh_server_username_input = Input::new(
            self.basic_view.ssh_username_input.x(),
            self.basic_view.ssh_username_input.y() + y_offset,
            self.basic_view.ssh_username_input.w(),
            self.basic_view.ssh_username_input.h(),
            "user:",
        );
        local_tunnel_group.add(&ssh_server_username_input);

        let mut ssh_server_pwd_input = SecretInput::new(
            self.basic_view.ssh_pwd_input.x(),
            self.basic_view.ssh_pwd_input.y() + y_offset,
            self.basic_view.ssh_pwd_input.w(),
            self.basic_view.ssh_pwd_input.h(),
            "pwd:",
        );
        local_tunnel_group.add(&ssh_server_pwd_input);

        let mut real_service_host_input = Input::new(
            self.basic_view.remote_host_input.x(),
            self.basic_view.remote_host_input.y() + y_offset,
            self.basic_view.remote_host_input.w(),
            self.basic_view.remote_host_input.h(),
            "",
        );
        local_tunnel_group.add(&real_service_host_input);
        let mut real_service_port_input = Input::new(
            self.basic_view.remote_port_input.x(),
            self.basic_view.remote_port_input.y() + y_offset,
            self.basic_view.remote_port_input.w(),
            self.basic_view.remote_port_input.h(),
            ":",
        );
        local_tunnel_group.add(&real_service_port_input);

        if let Some(d) = data {
            name_input.set_value(&d.name);
            listen_port_input.set_value(&d.forward_port.to_string());
            ssh_server_host_input.set_value(&d.ssh_host);
            ssh_server_port_input.set_value(&d.ssh_port.to_string());
            ssh_server_username_input.set_value(&d.ssh_user);
            ssh_server_pwd_input.set_value(&d.ssh_pwd);
            real_service_host_input.set_value(&d.real_service_host);
            real_service_port_input.set_value(&d.real_service_port.to_string());
        }

        let row = SSHTunnelRow {
            id,
            tunnel_type: TunnelType::Local,
            row_group: local_tunnel_group,
            index_txt,
            name_input,
            forward_type_box: local_tunnel_type_box,
            start_btn,
            stop_btn,
            del_btn,
            img_gray_line,
            info_btn: info_btn_local,
            img_pc,
            img_arrow1,
            img_arrow2,
            img_arrow3,
            img_firewall,
            listen_addr_box,
            ssh_server_box,
            real_service_addr_box,
            listen_port_input,
            ssh_server_host_input,
            ssh_server_port_input,
            ssh_server_username_input,
            ssh_server_pwd_input,
            real_service_host_input,
            real_service_port_input,
            info_data: "".to_owned(),
        };

        self.tunnel_rows.push(row);
    }

    pub fn try_verify_start_tunnel_params(&mut self, id: i32) -> Result<SSHTunnel> {
        //info!("tunnel_rows:{:#?}", self.tunnel_rows);
        let row_ot = self.tunnel_rows.iter_mut().find(|t| t.id == id);
        if let Some(row) = row_ot {
            let tunnel = SSHTunnel::new(
                row.id,
                row.name_input.value(),
                crate::ssh_tunnel::Status::Stopped,
                row.tunnel_type,
                row.listen_port_input.value().parse::<u16>()?,
                row.real_service_host_input.value(),
                row.real_service_port_input.value().parse::<u16>()?,
                row.ssh_server_host_input.value(),
                row.ssh_server_port_input.value().parse::<u16>()?,
                row.ssh_server_username_input.value(),
                row.ssh_server_pwd_input.value(),
            );

            row.start_btn.deactivate();
            row.stop_btn.activate();
            row.del_btn.deactivate();
            row.listen_port_input.deactivate();
            row.ssh_server_host_input.deactivate();
            row.ssh_server_port_input.deactivate();
            row.ssh_server_username_input.deactivate();
            row.ssh_server_pwd_input.deactivate();
            row.real_service_host_input.deactivate();
            row.real_service_port_input.deactivate();

            return Ok(tunnel);
        }

        Err(anyhow!("can not found this config row by id:{id}"))
    }
}

pub fn send(m: UiMessage) {
    match &RWLOCK_MSG_CHANNEL.read() {
        Ok(channel) => {
            let sender = &channel.0;
            sender.send(m);
        }
        Err(err) => panic!("get message channel sender error:{}", err),
    }
}

fn trans_bytes_to_png(bytes: &[u8], width: u32, height: u32) -> PngImage {
    let o_img = image::load_from_memory(bytes).unwrap();
    let image_buffer: ImageBuffer<Rgba<u8>, Vec<u8>> = image::imageops::resize(&o_img, width, height, image::imageops::FilterType::Gaussian);
    let dynamic_image: DynamicImage = DynamicImage::ImageRgba8(image_buffer);
    let mut ib = vec![];
    dynamic_image
        .write_to(&mut std::io::Cursor::new(&mut ib), image::ImageOutputFormat::Png)
        .unwrap();
    let image = PngImage::from_data(&ib).unwrap();

    image
}

#[derive(Debug)]
pub enum SSHTunnelCommand {
    Start,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SSHTunnelThreadEventType {
    PortIsBeenUsed,
    NotConnectSSHServer,
    ConnectionBroken,
    SSHConnectError,
    CommonError,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSHTunnelThreadEvent {
    pub event_type: SSHTunnelThreadEventType,
    pub data: String,
}

pub fn handle_ssh_tunnel_event(command_rx: std::sync::mpsc::Receiver<(SSHTunnelCommand, Option<SSHTunnel>, i32)>) {
    let (ui_tunnel_sx, mut ui_tunnel_rx) = tokio::sync::mpsc::channel::<SSHTunnelThreadEvent>(256);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("oops, why tokio runtime panic? error:");
        rt.block_on(async move {
            let ui_tunnel_sx = Arc::new(Mutex::new(ui_tunnel_sx));
            let mut ssh_tunnel_dict = HashMap::<i32, SSHTunnel>::new();

            loop {
                let ui_tunnel_sx_arc = ui_tunnel_sx.clone();
                info!("waiting a command send...");
                match command_rx.recv() {
                    Ok((SSHTunnelCommand::Start, Some(mut tunnel), id)) => {
                        info!("accept start command, tunnel:{:?}", tunnel);
                        let t_option = ssh_tunnel_dict.get_mut(&tunnel.id);

                        if let Some(ssh_t) = t_option {
                            info!("stop a existed tunnel:{:?}", ssh_t);
                            if let Err(stop_err) = ssh_t.stop().await {
                                let err_text = format!("try to stop SSHTunnel:{:#?}, error:{:?}", ssh_t, stop_err);
                                error!("{}", &err_text);
                                alert_default(&err_text);
                            }
                        }

                        info!("start a new tunnel.");
                        if let Err(e) = tunnel.start(ui_tunnel_sx_arc).await {
                            error!("tunnel:{:?} start error:{:?}", tunnel, e);
                        } else {
                            ssh_tunnel_dict.insert(tunnel.id, tunnel);
                        }
                    }
                    Ok((SSHTunnelCommand::Stop, None, id)) => {
                        info!("accept stop command, id:{:?}", id);
                        let t_option = ssh_tunnel_dict.get_mut(&id);
                        match t_option {
                            Some(ssh_t) => {
                                if let Err(stop_err) = ssh_t.stop().await {
                                    let err_text = format!("try to stop SSHTunnel:{:#?}, error:{:?}", ssh_t, stop_err);
                                    error!("{}", &err_text);
                                    alert_default(&err_text);
                                }
                            }
                            None => {
                                warn!("nothing to do, because can not found id:{}", id);
                            }
                        }
                    }

                    Err(e) => {
                        error!("accept SSHTunnelCommand error:{:?}", e);
                        tokio::time::sleep(Duration::from_millis(3000)).await;
                    }
                    _ => {}
                }
            }
        });
    });

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("oops, why tokio runtime panic? error:");
        rt.block_on(async move {
            loop {
                match ui_tunnel_rx.recv().await {
                    Some(r) => send(UiMessage {
                        msg_type: MsgType::AppendTunnelDialogErrorText,
                        msg: r.data,
                    }),
                    None => {
                        todo!();
                        warn!("ui_tunnel_rx recv None.")
                    }
                }
            }
        });
    });
}

pub fn handle_view_msg(
    (screen_width, screen_height): (f64, f64),
    view: &mut SSHTunnelView,
    ui_msg: UiMessage,
    ssh_tunnel_event_sender: &mut std::sync::mpsc::Sender<(SSHTunnelCommand, Option<SSHTunnel>, i32)>,
) {
    // let g: GlobalState<crate::G> = fltk::app::GlobalState::get();
    // g.with(|gg| println!("handle_view_msg g:{:?}", gg));

    match ui_msg.msg_type {
        MsgType::INFO => todo!(),
        MsgType::ERROR => todo!(),
        MsgType::AddLocalTunnelRow => view.add_ssh_local_tunnel_row(None),
        MsgType::AddRemoteTunnelRow => view.add_ssh_remote_tunnel_row(None),
        MsgType::StartTunnel => {
            let id = ui_msg.msg.parse::<i32>().expect("id must be i32, error:");
            match view.try_verify_start_tunnel_params(id) {
                Ok(t) => {
                    if let Err(sender_err) = ssh_tunnel_event_sender.send((SSHTunnelCommand::Start, Some(t), id)) {
                        error!("{:?}", sender_err);
                        alert_default(&format!("{:?}", sender_err));
                    }
                }
                Err(e) => alert_default(&format!("start params error:{:?}", e)),
            }
        }
        MsgType::StopTunnel => {
            let id = ui_msg.msg.parse::<i32>().expect("id must be i32, error:");
            if deactive_ui_row(id, view, "".to_owned()) {
                if let Err(sender_err) = ssh_tunnel_event_sender.send((SSHTunnelCommand::Stop, None, id)) {
                    error!("{:?}", sender_err);
                    alert_default(&format!("{:?}", sender_err));
                }
            }
        }
        MsgType::ResizeMainWindow => {
            let arr = ui_msg.msg.split("|").collect::<Vec<&str>>();
            let w = arr.get(2).expect("ResizeMainWindow index for w error:").parse::<i32>().expect("w must be i32, error:");
            let h = arr.get(3).expect("ResizeMainWindow index for h error:").parse::<i32>().expect("h must be i32, error:");

            view.basic_view
                .scroll_view
                .resize(view.basic_view.scroll_view.x(), view.basic_view.scroll_view.y(), w, h - 60);
            view.basic_view.main_window.redraw();
        }
        MsgType::DeleteTunnel => {
            let id = ui_msg.msg.parse::<i32>().expect("id must be i32, error:");

            if let Some(index) = view.tunnel_rows.iter().position(|t| t.id == id) {
                let removed_element = view.tunnel_rows.remove(index);
                if let Err(sender_err) = ssh_tunnel_event_sender.send((SSHTunnelCommand::Stop, None, removed_element.id)) {
                    error!("{:?}", sender_err);
                    alert_default(&format!("{:?}", sender_err));
                }
                view.basic_view.scroll_view.remove(&removed_element.row_group);

                let y_offset = view.basic_view.local_tunnel_group.h() + 10;
                for idx in index..view.tunnel_rows.len() {
                    let index_txt = &mut view.tunnel_rows[idx].index_txt;
                    index_txt.set_label(idx.to_string().as_str());

                    let x = view.tunnel_rows[idx].row_group.x();
                    let y = view.tunnel_rows[idx].row_group.y() - y_offset;
                    view.tunnel_rows[idx].row_group.set_pos(x, y);
                }
            }
        }
        MsgType::UpdateConfig => {
            save_config(view);
        }
        MsgType::AppendTunnelDialogErrorText => {
            let datas = ui_msg.msg.split("|").collect::<Vec<&str>>();
            let id = datas[0].parse::<i32>().expect("id must be i32, error:");
            let info_data = datas[1].to_string();
            if deactive_ui_row(id, view, info_data) {
                if let Err(sender_err) = ssh_tunnel_event_sender.send((SSHTunnelCommand::Stop, None, id)) {
                    error!("{:?}", sender_err);
                    alert_default(&format!("{:?}", sender_err));
                }
            }
        }
        MsgType::ShowTunnelInfoDialog => {
            let id = ui_msg.msg.parse::<i32>().expect("id must be i32, error:");
            let row_ot = view.tunnel_rows.iter_mut().find(|t| t.id == id);
            if let Some(row) = row_ot {
                show_tunnel_info(screen_width, screen_height, &row.info_data);
                row.info_btn.set_label_color(Color::by_index(38));
            }
        }
    }

    view.basic_view.scroll_view.redraw();
}

fn show_tunnel_info(screen_width: f64, screen_height: f64, log: &str) {
    let w: i32 = 800;
    let h = 400;
    let mut help = fltk::dialog::HelpDialog::new((screen_width.floor() as i32 - w) / 2, (screen_height.floor() as i32 - h) / 2, w, h);
    help.set_text_size(16);
    help.set_value(format!("<div>{log}</div>").as_str()); // this takes html
    help.show();
    while help.shown() {
        fltk::app::wait();
    }
}

fn deactive_ui_row(id: i32, view: &mut SSHTunnelView, info_data: String) -> bool {
    let row_ot = view.tunnel_rows.iter_mut().find(|t| t.id == id);
    if let Some(row) = row_ot {
        if !info_data.is_empty() {
            row.info_btn.set_label_color(Color::Red);
            row.info_data += "<br>";
            row.info_data += &info_data;
        }

        row.start_btn.activate();
        row.stop_btn.deactivate();
        row.del_btn.activate();
        row.listen_port_input.activate();
        row.ssh_server_host_input.activate();
        row.ssh_server_port_input.activate();
        row.ssh_server_username_input.activate();
        row.ssh_server_pwd_input.activate();
        row.real_service_host_input.activate();
        row.real_service_port_input.activate();

        true
    } else {
        false
    }
}

pub fn save_config(view: &mut SSHTunnelView) {
    let mut configs: Vec<SSHTunnelJson> = vec![];
    for row in view.tunnel_rows.iter() {
        let json_row = SSHTunnelJson {
            id: row.id,
            name: row.name_input.value(),

            forward_type: row.tunnel_type,
            forward_port: row.listen_port_input.value(),
            real_service_host: row.real_service_host_input.value(),
            real_service_port: row.real_service_port_input.value(),
            ssh_user: row.ssh_server_username_input.value(),
            ssh_host: row.ssh_server_host_input.value(),
            ssh_port: row.ssh_server_port_input.value(),
            ssh_pwd: row.ssh_server_pwd_input.value(),
        };
        configs.push(json_row);
    }
    if let Err(err) = config::save_config(&configs) {
        error!("save config error:{:?}", err);
        alert_default(&format!("save config error:{:?}", err));
    }
}
