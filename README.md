# ssh-tunnel-rs
this is a ssh tunnel forward tool by rust, contains cross platform GUI and CLI

### Dependency Framework
> if compile openssl error, try install cmake: https://cmake.org/download/ and https://strawberryperl.com/

- CLI: Rust 

- GUI: FLTK:https://github.com/fltk-rs/fltk-rs

### CLI
![ssh-tunnel-cli.png](ssh-tunnel-cli.png)

### GUI 
![ssh-tunnel-gui.jpg](ssh-tunnel-gui.jpg)

### How to run?

#### 1. just run cli
```sh
cargo run --bin ssh-tunnel-cli -- -h
# run with args
cargo run --bin ssh-tunnel-cli -- --host 192.168.5.45 --user someuser -a password --pwd somepwd local --local-port 3316 --remote-host 192.168.5.36 --remote-port 3306
```

#### 2. just run gui
```sh
cargo run --bin ssh-tunnel-gui
```

### How to use?

#### 1. Local port forward by password
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser -a password --pwd somepwd local --local-port 3316 --remote-host 192.168.5.36 --remote-port 3306
```

#### 2. Remote port forward by password
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser -a password --pwd somepwd remote --local-port 3316 --local-host 192.168.5.36 --remote-port 3306
```

#### 3. Local port forward by KeyPair
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser -a key-pair --private-key /usr/yourname/private_k_file --local-port 3316 --remote-host 192.168.5.36 --remote-port 3306
```

#### 4. Remote port forward by KeyPair
```sh
ssh-tunnel-cli --host 192.168.5.45 --user someuser -a key-pair --private-key /usr/yourname/private_k_file remote --local-port 3316 --local-host 192.168.5.36 --remote-port 3306
```

### Roadmap
- [x] GUI for windows/winpe, linux, macos
- [x] cli for windows/winpe, linux, macos about local/remote tunnel
- [x] local ssh tunnel by user/password
- [x] remote ssh tunnel by user/password
- [x] support auth by ssh file
- [ ] support dynamic port forward
- [ ] support clearer status display
- [ ] interactive mode

### Welcome any suggestions and contributions
##### If you have any questions, you can submit your issue
