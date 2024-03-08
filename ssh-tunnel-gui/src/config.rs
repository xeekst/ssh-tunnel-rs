use std::{path::PathBuf, fs, io::Write};

use crate::ssh_tunnel::SSHTunnelJson;

const CONFIG_FILE: &str = "ssh-tunnel-rs.json";

pub fn read_config() -> anyhow::Result<Vec<SSHTunnelJson>> {
    if !PathBuf::from(CONFIG_FILE).exists() {
        return Ok(vec![]);
    }

    let content = fs::read_to_string(CONFIG_FILE)?;
    let r = serde_json::from_str::<Vec<SSHTunnelJson>>(&content)?;

    Ok(r)
}

pub fn save_config(config: &Vec<SSHTunnelJson>) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(config)?;

    let mut f = fs::File::create(CONFIG_FILE)?;
    f.write_all(content.as_bytes())?;

    Ok(())
}
