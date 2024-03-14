use anyhow::{bail, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, File},
    path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct DxEnvironment {
    pub apiserver_protocol: String,

    pub username: String,

    pub cli_wd: String,

    pub apiserver_host: String,

    pub project_context_id: String,

    pub project_context_name: String,

    pub apiserver_port: u32,

    pub auth_token_type: String,

    pub auth_token: String,
}

// --------------------------------------------------
fn dx_env_dir() -> Result<PathBuf> {
    if let Ok(dirname) = env::var("DX_USER_CONF_DIR") {
        Ok(PathBuf::from(dirname))
    } else if let Some(dir) = home_dir() {
        Ok(dir.join(".dnanexus_config"))
    } else {
        bail!("Cannot find $DX_USER_CONF_DIR or $HOME")
    }
}

// --------------------------------------------------
fn dx_env_json() -> Result<PathBuf> {
    dx_env_dir().map(|dir| dir.join("dx_env.json"))
}

// --------------------------------------------------
pub fn get_dx_username() -> Option<String> {
    if let Ok(conf_dir) = dx_env_dir() {
        let file = conf_dir.join("DX_USERNAME");
        fs::read_to_string(file).ok()
    } else {
        None
    }
}

// --------------------------------------------------
pub fn get_dx_env() -> Result<DxEnvironment> {
    let file = dx_env_json()?;
    if file.is_file() {
        let contents = fs::read_to_string(file)?;
        Ok(serde_json::from_str::<DxEnvironment>(&contents)?)
    } else {
        bail!("Please login")
    }
}

// --------------------------------------------------
pub fn save_dx_env(dx_env: &DxEnvironment) -> Result<()> {
    let conf_dir = dx_env_dir()?;
    //dbg!(&conf_dir);

    if !conf_dir.is_dir() {
        fs::create_dir(&conf_dir)?;
    }

    let dx_env_file = dx_env_json()?;
    let fh = File::create(dx_env_file)?;
    serde_json::to_writer_pretty(&fh, &dx_env)?;
    Ok(())
}
