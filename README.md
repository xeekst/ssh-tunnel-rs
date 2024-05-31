# ssh-tunnel-rs
this is a ssh tunnel forward tool by rust, contains cross platform GUI and CLI

### Dependency Framework
- GUI: FLTK:https://github.com/fltk-rs/fltk-rs

- CLI: Rust 


### GUI 
![ssh-tunnel-gui.jpg](ssh-tunnel-gui.jpg)

### CLI
![ssh-tunnel-cli.png](ssh-tunnel-cli.png)

### How to use?

#### 1. Local port forward
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser --pwd somepwd local --local-port 3316 --remote-host 192.168.5.36 --remote-port 3306
```

#### 2. Remote port forward
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser --pwd somepwd remote --local-port 3316 --local-host 192.168.5.36 --remote-port 3306
```

### Roadmap
- [x] GUI for windows/winpe, linux, macos
- [x] cli for windows/winpe, linux, macos about local/remote tunnel
- [x] local ssh tunnel by user/password
- [x] remote ssh tunnel by user/password
- [ ] support auth by ssh file
- [ ] support dynamic port forward
- [ ] support clearer status display
