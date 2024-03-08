#[cfg(target_os = "windows")]
use winres;

#[cfg(target_os = "windows")]
fn main() {
    // use std::env;
    // use std::path::PathBuf;
    // 以下代码告诉 Cargo ，一旦指定的文件 `src/register/register_view.fl` 发生了改变，就重新运行当前的构建脚本
    println!("cargo:rerun-if-changed=src/basic_view.fl");
    let g = fl2rust::Generator::default();
    //let out_path = PathBuf::from("src/register/register_view.rs");
    g.in_out("src/basic_view.fl", "src/basic_view.rs")
        .expect("Failed to generate rust from fl file!");

    use std::io::Write;
    // only build the resource for release builds
    // as calling rc.exe might be slow
    if std::env::var("PROFILE").unwrap() == "release" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("ssh.ico").set_manifest(
            r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="asInvoker" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
    "#,
        );
        match res.compile() {
            Err(error) => {
                write!(std::io::stderr(), "{}", error).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
}
