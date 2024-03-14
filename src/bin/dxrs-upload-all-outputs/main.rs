use anyhow::{bail, Result};
use clap::Parser;
use dxrs::{
    api,
    dxenv::{get_dx_env, DxEnvironment},
    json_parser::{DxApp, InputOutputClass},
    upload_local_file, AppDescribeField, AppDescribeOptions,
    JobDescribeField, JobDescribeOptions, JobDescribeResult, ProjectPath,
};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Debug, Parser)]
/// Upload all job outputs
struct Args {
    /// job ID
    #[arg(short, long, conflicts_with = "app_json")]
    job_id: Option<String>,

    /// dxapp.json file
    #[arg(short, long, conflicts_with = "job_id")]
    app_json: Option<String>,

    /// Output directory
    #[arg(short, long)]
    out_dir: Option<String>,

    /// Wait for files to close
    #[arg(short, long)]
    wait_on_close: bool,

    /// Download in parallel
    #[arg(short, long)]
    parallel: bool,

    /// Number of threads
    #[arg(short, long)]
    threads: Option<usize>,

    /// Directories that should be skipped
    #[arg(short, long)]
    except: Vec<String>,
}

#[derive(Debug)]
struct Output {
    name: String,

    class: InputOutputClass,

    optional: bool,
}

#[derive(Debug)]
struct Upload {
    output_name: String,

    filename: String,
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
    let outputs = get_outputs(&dx_env, &args);
    dbg!(&outputs);

    //let home = &env::var("HOME")?;
    //let home_dir = Path::new(home);
    //let out_dir = match args.out_dir {
    //    Some(val) => PathBuf::from(val),
    //    _ => home_dir.join("out"),
    //};

    //let project_path = match job {
    //    Some(desc) => ProjectPath {
    //        project_id: desc
    //            .project
    //            .unwrap_or(dx_env.project_context_id.clone()),
    //        path: PathBuf::from(desc.folder.unwrap_or("/".to_string())),
    //    },
    //    _ => ProjectPath {
    //        project_id: dx_env.project_context_id.clone(),
    //        path: PathBuf::from("/".to_string()),
    //    },
    //};

    //let mut uploads: Vec<Upload> = vec![];
    //for output in output_spec
    //    .iter()
    //    .filter(|o| !args.except.contains(&o.name))
    //{
    //    let files = find_files(&out_dir.join(&output.name));
    //    dbg!(&files);

    //    if files.is_empty() && !output.optional {
    //        bail!(r#"Required output "{}" has no files"#, output.name);
    //    }

    //    match output.class {
    //        InputOutputClass::File => {
    //            if files.len() > 1 {
    //                bail!(
    //                    "{} should have one output but has {}",
    //                    output.name,
    //                    files.len()
    //                );
    //            }
    //        }
    //        _ => (),
    //    }

    //    for file in files {
    //        uploads.push(Upload {
    //            output_name: output.name.clone(),
    //            filename: file.display().to_string(),
    //        });
    //    }
    //}

    //dbg!(&uploads);

    //let results: Vec<_> = if args.parallel {
    //    uploads
    //        .par_iter()
    //        .map(|u| {
    //            (
    //                u.output_name.clone(),
    //                upload_local_file(&dx_env, &u.filename, &project_path),
    //            )
    //        })
    //        .collect()
    //} else {
    //    uploads
    //        .iter()
    //        .map(|u| {
    //            (
    //                u.output_name.clone(),
    //                upload_local_file(&dx_env, &u.filename, &project_path),
    //            )
    //        })
    //        .collect()
    //};

    //dbg!(&results);

    //let mut json_output: HashMap<String, String> = vec![];
    //for (output_name, res) in results {
    //    match res {
    //        Err(e) => eprintln!("{output_name}: {e}"),
    //        Ok(v) => {
    //            json_output.insert(output_name, v)
    //        }
    //    }
    //}

    Ok(())
}

// --------------------------------------------------
fn find_files(path: &PathBuf) -> Vec<PathBuf> {
    if path.is_dir() {
        WalkDir::new(path)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().into())
            .collect()
    } else {
        vec![]
    }
}

// --------------------------------------------------
fn get_outputs(dx_env: &DxEnvironment, args: &Args) -> Result<Vec<Output>> {
    if let Some(job_id) = &args.job_id.clone().or(env::var("DX_JOB_ID").ok())
    {
        get_outputs_from_job(&dx_env, &job_id)
    } else if let Some(app_json) = &args
        .app_json
        .clone()
        .or(env::var("DX_TEST_DXAPP_JSON").ok())
    {
        get_outputs_from_json(&app_json)
    } else {
        unreachable!("Must have job ID or app JSON file")
    }
}

// --------------------------------------------------
fn get_outputs_from_job(
    dx_env: &DxEnvironment,
    job_id: &str,
) -> Result<Vec<Output>> {
    let job_opts = JobDescribeOptions {
        default_fields: None,
        fields: Some(HashMap::from([
            (JobDescribeField::Output, true),
            (JobDescribeField::App, true),
            (JobDescribeField::Applet, true),
        ])),
        try_number: None,
    };

    let job = api::describe_job(&dx_env, &job_id, &job_opts)?;
    let app_id = if let Some(id) = &job.app {
        id
    } else if let Some(id) = &job.applet {
        id
    } else {
        bail!(r#"Job "{job_id}" missing app/applet ID"#)
    };

    let app_opts = AppDescribeOptions {
        fields: HashMap::from([(AppDescribeField::OutputSpec, true)]),
    };
    let app = api::describe_app(dx_env, &app_id, &app_opts)?;
    if let Some(spec) = app.output_spec {
        Ok(spec
            .iter()
            .filter(|o| {
                matches!(
                    o.class,
                    InputOutputClass::File | InputOutputClass::ArrayFile
                )
            })
            .map(|o| Output {
                name: o.name.clone(),
                class: o.class.clone(),
                optional: o.optional.unwrap_or(true),
            })
            .collect())
    } else {
        bail!(r#"No outputSpec in app "{app_id}""#)
    }
}

// --------------------------------------------------
fn get_outputs_from_json(app_json: &str) -> Result<Vec<Output>> {
    match File::open(&app_json) {
        Err(e) => bail!("{app_json}: {e}"),
        Ok(mut file) => {
            let mut contents = String::new();
            let _ = &file.read_to_string(&mut contents)?;
            let app = serde_json::from_str::<DxApp>(&contents)?;
            let output = app
                .output_spec
                .iter()
                .filter(|o| {
                    matches!(
                        o.class,
                        InputOutputClass::File | InputOutputClass::ArrayFile
                    )
                })
                .map(|o| Output {
                    name: o.name.clone(),
                    class: o.class.clone(),
                    optional: o.optional.unwrap_or(true),
                })
                .collect();
            Ok(output)
        }
    }
}
