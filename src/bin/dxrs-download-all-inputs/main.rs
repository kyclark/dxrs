use anyhow::{bail, Result};
use clap::Parser;
use dxrs::{
    api,
    dxenv::{get_dx_env, DxEnvironment},
    {DownloadOptions, FileDescribeField, FileDescribeOptions},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
/// Download all job inputs
struct Args {
    /// Input "job_input.json" file
    #[arg(short, long)]
    input_json: Option<String>,

    /// Output directory
    #[arg(short, long)]
    out_dir: Option<String>,

    /// Download in parallel
    #[arg(short, long)]
    parallel: bool,

    /// Number of threads
    #[arg(short, long)]
    threads: Option<usize>,

    /// Values that should be skipped
    #[arg(short, long)]
    except: Vec<String>,
}

#[derive(Debug)]
struct DownloadFile {
    file_id: String,

    filename: String,

    directory: PathBuf,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum InputValue {
    File(InputFile),

    VecFile(Vec<InputFile>),

    Other(serde_json::Value),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct InputFile {
    #[serde(rename = "$dnanexus_link")]
    dnanexus_link: String,
}

// --------------------------------------------------
fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

// --------------------------------------------------
fn run(args: Args) -> Result<()> {
    // Optionally set num of threads, default will use all available
    if let Some(num) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num)
            .build_global()
            .unwrap();
    }

    let dx_env = get_dx_env()?;
    let home = &env::var("HOME")?;
    let home_dir = Path::new(home);
    let out_dir = match args.out_dir {
        Some(val) => PathBuf::from(val),
        _ => home_dir.join("in"),
    };
    let input_json = match args.input_json {
        Some(filename) => PathBuf::from(filename),
        _ => home_dir.join("job_input.json"),
    };

    let inputs: HashMap<String, InputValue> = parse_json(&input_json)?;
    let mut downloads: Vec<DownloadFile> = vec![];

    for (key, val) in inputs.iter() {
        if !args.except.contains(key) {
            match val {
                InputValue::File(file) => downloads.push(DownloadFile {
                    file_id: file.dnanexus_link.clone(),
                    filename: get_filename(&dx_env, &file.dnanexus_link)?,
                    directory: out_dir.join(key),
                }),
                InputValue::VecFile(files) => {
                    let num_digits = files.len().to_string().len();
                    for (i, file) in files.iter().enumerate() {
                        downloads.push(DownloadFile {
                            file_id: file.dnanexus_link.clone(),
                            filename: get_filename(
                                &dx_env,
                                &file.dnanexus_link,
                            )?,
                            directory: out_dir.join(key).join(format!(
                                "{:0width$}",
                                i,
                                width = num_digits
                            )),
                        })
                    }
                }
                _ => (),
            }
        }
    }

    let results: Vec<_> = if args.parallel {
        downloads
            .par_iter()
            .map(|file| download_file(&dx_env, &file))
            .collect()
    } else {
        downloads
            .iter()
            .map(|file| download_file(&dx_env, &file))
            .collect()
    };

    for err in results.iter().filter(|v| v.is_err()) {
        eprintln!("{}", err.as_ref().unwrap_err());
    }

    Ok(())
}

// --------------------------------------------------
pub fn get_filename(dx_env: &DxEnvironment, file_id: &str) -> Result<String> {
    let options = FileDescribeOptions {
        project: None,
        fields: Some(HashMap::from([(FileDescribeField::Name, true)])),
        details: true,
        properties: true,
    };
    let file = api::describe_file(dx_env, &file_id, &options)?;
    Ok(file.name.unwrap_or(file_id.to_string()))
}

// --------------------------------------------------
pub fn parse_json<T: for<'a> Deserialize<'a>>(
    filename: &PathBuf,
) -> Result<T> {
    match File::open(filename) {
        Err(e) => bail!("{}: {e}", filename.display()),

        Ok(mut file) => {
            let mut contents = String::new();
            let _ = &file.read_to_string(&mut contents)?;
            Ok(serde_json::from_str::<T>(&contents)?)
        }
    }
}

// --------------------------------------------------
fn download_file(dx_env: &DxEnvironment, file: &DownloadFile) -> Result<()> {
    let dl_opts = DownloadOptions {
        duration: None,
        filename: None,
        project: None,
        preauthenticated: None,
        sticky_ip: None,
    };

    if !file.directory.is_dir() {
        fs::create_dir_all(&file.directory)?;
    }

    let out_path = file.directory.join(&file.filename);
    println!("Starting {} => {}", file.filename, out_path.display());
    let out_file = File::create(out_path)?;
    let download = api::download(dx_env, &file.file_id, &dl_opts)?;
    api::download_file(&download, out_file, &file.filename, true)?;

    println!("Finished {}", file.filename);

    Ok(())
}
