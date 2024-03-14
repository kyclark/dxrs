pub mod api;
pub mod dxenv;
pub mod json_parser;

use crate::dxenv::{get_dx_env, save_dx_env, DxEnvironment};
use ansi_term::Colour::Cyan;
use anyhow::{anyhow, bail, Result};
use chrono::{serde::ts_milliseconds_option, DateTime, Utc};
use clap::{builder::PossibleValue, command, ArgAction, Parser, ValueEnum};
use flate2::write::GzEncoder;
use flate2::Compression;
use inquire::{
    Confirm,
    //validator::{StringValidator, Validation},
    Password,
    Select,
    Text,
};
use json_parser::{
    AccessSpec, DxApp, DxAsset, ExecDepends, InputOutputClass, InputSpec,
    Interpreter, LinuxDistribution, LinuxRelease, LinuxVersion, OutputSpec,
    PackageManager, RegionalOptions, RunSpec, SystemRequirements,
    TimeoutUnit, VALID_INSTANCE_TYPE, VALID_REGION,
};
use log::debug;

use ordinal::Ordinal;
use regex::Regex;
use serde::{Deserialize, Serialize};
use size::Size;
use std::{
    collections::HashMap,
    env,
    fmt::{self, Write},
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    str::FromStr,
};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString};
use tabular::{Row, Table};
use tar::Builder;
use termtree::Tree;
use textnonce::TextNonce;
//use tempfile::NamedTempFile;

const MD5_READ_CHUNK_SIZE: usize = 1024 * 1024 * 4;

// --------------------------------------------------
#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(short, long, default_value = "false")]
    pub debug: bool,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Build applet or asset
    #[clap(alias = "bu")]
    Build(BuildArgs),

    /// Change directory
    Cd(CdArgs),

    /// Show object metadata
    #[clap(alias = "desc", alias = "de")]
    Describe(DescribeArgs),

    /// Download a file or directory
    #[clap(alias = "dl")]
    Download(DownloadArgs),

    /// Environment listing
    Env(EnvArgs),

    /// Find apps
    #[clap(alias = "fa")]
    FindApps(FindAppsArgs),

    /// Find data
    #[clap(alias = "fd")]
    FindData(FindDataArgs),

    /// Format app/asset JSON
    #[clap(alias = "fmt")]
    Format(FormatArgs),

    /// Lint app/asset JSON
    Lint(LintArgs),

    /// Login to platform
    #[clap(alias = "li")]
    Login(LoginArgs),

    /// Logout of platform
    #[clap(alias = "lo")]
    Logout {},

    /// Directory listing
    Ls(LsArgs),

    /// Create directory
    Mkdir(MkdirArgs),

    /// Create project
    #[clap(alias = "newp")]
    NewProject(NewProjectArgs),

    /// Print working directory
    Pwd {},

    /// Remove a file or directory
    Rm(RmArgs),

    /// Remove a directory
    #[clap(alias = "rmd")]
    Rmdir(RmdirArgs),

    /// Delete projects and all associated data
    #[clap(alias = "rmp")]
    RmProject(RmProjectArgs),

    /// Select working project
    #[clap(alias = "se")]
    Select(SelectArgs),

    /// List folders and objects in a tree
    #[clap(alias = "tr")]
    Tree(TreeArgs),

    /// Upload a local file to the platform
    #[clap(alias = "up")]
    Upload(UploadArgs),

    /// Watch a job
    #[clap(alias = "wa")]
    Watch(WatchArgs),

    /// Identify currently logged in user
    #[clap(alias = "who")]
    Whoami(WhoamiArgs),

    /// Wizard for creating applets
    #[clap(alias = "wiz")]
    Wizard(WizardArgs),
}

#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    /// Directory name of applet or asset resources
    #[arg(default_value = ".")]
    src: String,

    /// Destination for built applet
    #[arg(short, long)]
    destination: Option<String>,

    /// Overwrite an existing applet
    #[arg(short, long, default_value = "false")]
    force: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct CdArgs {
    /// Directory name
    #[arg()]
    dirname: Option<String>,
}

#[derive(Clone, Parser, Debug)]
pub struct DescribeArgs {
    /// Object identifier
    #[arg()]
    ids: Vec<String>,

    /// Output JSON representation
    #[arg(long, default_value = "false")]
    json: bool,

    /// Attempt number for restarted job
    #[arg(long = "try", value_name = "INT")]
    try_number: Option<u64>,
}

#[derive(Clone, Parser, Debug)]
pub struct FindDataArgs {
    /// Data object name
    #[arg(short, long)]
    name: Option<String>,

    /// Class
    #[arg(short, long)]
    class: Option<String>,

    /// Search path
    #[arg(short, long)]
    path: Option<String>,

    /// Output JSON representation
    #[arg(long, default_value = "false")]
    json: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct FormatArgs {
    /// Filename
    #[arg()]
    filename: String,

    #[arg(short, long, default_value = "-")]
    output: String,
}

#[derive(Clone, Parser, Debug)]
pub struct LintArgs {
    /// Filename
    #[arg()]
    filename: String,
}

#[derive(Clone, Parser, Debug)]
pub struct LoginArgs {
    /// Login token
    #[arg(short, long)]
    token: Option<String>,
}

#[derive(Clone, Parser, Debug)]
pub struct LsArgs {
    /// Directory name
    #[arg()]
    paths: Vec<String>,

    /// Long listing
    #[arg(short, long)]
    long: bool,

    /// Show only file IDs
    #[arg(short, long)]
    brief: bool,

    /// Show hidden
    #[arg(short, long)]
    all: bool,

    /// Human-readable file sizes
    #[arg(short('H'), long)]
    human: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct MkdirArgs {
    /// Directory name
    #[arg()]
    paths: Vec<String>,

    /// Create parent directories as needed
    #[arg(short, long, default_value = "false")]
    parents: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct NewProjectArgs {
    /// Project name
    #[arg()]
    project_name: Option<String>,

    /// Print only the project ID
    #[arg(long)]
    brief: bool,

    /// Select the new project as current after creating
    #[arg(short, long)]
    select: bool,

    /// Add PHI protection to project
    #[arg(long)]
    phi: bool,

    /// Viewers on the project cannot access database data directly
    #[arg(long("database-ui-view-only"))]
    database_ui_view_only: bool,

    /// Region affinity of the new project
    #[arg(long)]
    region: Option<String>,

    /// ID of the user or org to which the project will be
    /// billed. The default value is the billTo of the
    /// requesting user.
    #[arg(long("bill-to"))]
    bill_to: Option<String>,

    /// Monthly project spending limit for compute
    #[arg(long("monthly-compute-limit"))]
    monthly_compute_limit: Option<u64>,

    /// Monthly project spending limit for egress (in Bytes)
    #[arg(long("monthly-egress-bytes-limit"))]
    monthly_egress_bytes_limit: Option<u64>,
}

#[derive(Clone, Parser, Debug)]
pub struct DownloadArgs {
    /// Object identifier
    #[arg()]
    paths: Vec<String>,

    /// Output directory
    #[arg(short, long)]
    dir: Option<String>,

    /// Local filename, "-" for STDOUT
    #[arg(short, long)]
    output: Option<String>,

    /// Overwrite local file
    #[arg(short, long, default_value = "false")]
    force: bool,

    /// Upload directories recursively
    #[arg(short, long, default_value = "false")]
    recursive: bool,

    /// Download all matching objects
    #[arg(short, long, default_value = "false")]
    all: bool,

    /// Do not show a progress bar
    #[arg(short, long, default_value = "false")]
    quiet: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct EnvArgs {
    /// Bash commands to export variables
    #[arg(long, default_value = "false")]
    bash: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct FindAppsArgs {
    /// App name
    #[arg(short, long)]
    name: Option<String>,
}

#[derive(Clone, Parser, Debug)]
pub struct UploadArgs {
    /// Project ID or name
    #[arg()]
    files: Vec<String>,

    /// Upload directories recursively
    #[arg(short, long, default_value = "false")]
    recursive: bool,

    /// Create any necessary parent folders
    #[arg(short, long, default_value = "false")]
    parents: bool,

    /// Destination path
    #[arg(long)]
    path: Option<String>,
}

#[derive(Clone, Parser, Debug)]
pub struct WatchArgs {
    /// Show user ID instead of username
    job_id: String,

    /// Number of recent messages to get
    #[arg(short, long)]
    num_recent_messages: Option<u32>,

    /// Include the entire job tree
    #[arg(long, action(ArgAction::SetTrue))]
    tree: Option<bool>,

    /// Level
    #[arg(short, long)]
    level: Vec<WatchLevel>,

    /// Watch particular try. T=0 is first try. Default is latest try.
    #[arg(long("try"))]
    try_number: Option<u32>,

    /// Extract STDOUT only from this job
    #[arg(long, action(ArgAction::SetTrue))]
    get_stdout: bool,

    /// Extract STDERR only from this job
    #[arg(long, action(ArgAction::SetTrue))]
    get_stderr: bool,

    /// Extract only STDOUT/STDERR from this job
    #[arg(long, action(ArgAction::SetTrue))]
    get_streams: bool,

    /// Omit timestamps from messages
    #[arg(long, action(ArgAction::SetTrue))]
    no_timestamps: bool,

    /// Print job ID in each message
    #[arg(long, action(ArgAction::SetTrue))]
    job_ids: bool,

    /// Omit job info and status updates
    #[arg(long, action(ArgAction::SetTrue))]
    no_job_ids: bool,

    /// Do not print extra info messages
    #[arg(long, action(ArgAction::SetTrue))]
    quiet: bool,

    /// Message format
    #[arg(short, long)]
    format: Option<WatchFormat>,

    /// Exit after the first new message is received
    #[arg(long, action(ArgAction::SetTrue))]
    no_wait: bool,

    /// Select display mode for detailed job metrics, if they were collected
    #[arg(long)]
    metrics: Option<WatchMetricsFormat>,
}

#[derive(Clone, Debug)]
pub enum WatchMetricsFormat {
    Interspersed,
    Top,
    Csv,
    None_,
}

impl ValueEnum for WatchMetricsFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            WatchMetricsFormat::Interspersed,
            WatchMetricsFormat::Top,
            WatchMetricsFormat::Csv,
            WatchMetricsFormat::None_,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            WatchMetricsFormat::Interspersed => {
                PossibleValue::new("interspersed")
            }
            WatchMetricsFormat::Top => PossibleValue::new("top"),
            WatchMetricsFormat::Csv => PossibleValue::new("csv"),
            WatchMetricsFormat::None_ => PossibleValue::new("none"),
        })
    }
}

#[derive(Clone, Debug)]
pub enum WatchFormat {
    Job,
    Try,
    Level,
    Msg,
    Date,
}

impl ValueEnum for WatchFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            WatchFormat::Job,
            WatchFormat::Try,
            WatchFormat::Level,
            WatchFormat::Msg,
            WatchFormat::Date,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            WatchFormat::Job => PossibleValue::new("job"),
            WatchFormat::Try => PossibleValue::new("try"),
            WatchFormat::Level => PossibleValue::new("level"),
            WatchFormat::Msg => PossibleValue::new("msg"),
            WatchFormat::Date => PossibleValue::new("date"),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WatchLevel {
    Emerg,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
    Stderr,
    Stdout,
    Metrics,
}

impl ValueEnum for WatchLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            WatchLevel::Emerg,
            WatchLevel::Alert,
            WatchLevel::Critical,
            WatchLevel::Error,
            WatchLevel::Warning,
            WatchLevel::Notice,
            WatchLevel::Info,
            WatchLevel::Debug,
            WatchLevel::Stderr,
            WatchLevel::Stdout,
            WatchLevel::Metrics,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            WatchLevel::Emerg => PossibleValue::new("EMERG"),
            WatchLevel::Alert => PossibleValue::new("ALERT"),
            WatchLevel::Critical => PossibleValue::new("CRITICAL"),
            WatchLevel::Error => PossibleValue::new("ERROR"),
            WatchLevel::Warning => PossibleValue::new("WARNING"),
            WatchLevel::Notice => PossibleValue::new("NOTICE"),
            WatchLevel::Info => PossibleValue::new("INFO"),
            WatchLevel::Debug => PossibleValue::new("DEBUG"),
            WatchLevel::Stderr => PossibleValue::new("STDERR"),
            WatchLevel::Stdout => PossibleValue::new("STDOUT"),
            WatchLevel::Metrics => PossibleValue::new("METRICS"),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "numRecentMessages")]
    num_recent_messages: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "recurseJobs")]
    recurse_jobs: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tail: Option<bool>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    levels: Vec<WatchLevel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatchResult {
    id: String,
}

#[derive(Clone, Parser, Debug)]
pub struct WhoamiArgs {
    /// Show user ID instead of username
    #[arg(long, default_value = "false")]
    id: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct WizardArgs {
    /// Applet name
    #[arg()]
    name: Option<String>,

    /// Template
    #[arg(short, long, value_name = "dxapp.json")]
    json_template: Option<String>,
}

#[derive(Clone, Parser, Debug)]
pub struct TreeArgs {
    /// Directoy path
    #[arg()]
    path: Option<String>,

    /// Long listing format
    #[arg(short, long, default_value = "false")]
    long: bool,

    /// Human-readable file sizes
    #[arg(short('H'), long, default_value = "false")]
    human: bool,

    /// Show hidden files
    #[arg(short, long, default_value = "false")]
    all: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct RmArgs {
    /// Object IDs or paths
    #[arg()]
    paths: Vec<String>,

    /// Recurse into a directory
    #[arg(short, long, default_value = "false")]
    recursive: bool,

    /// Force removal of files
    #[arg(short, long, default_value = "false")]
    force: bool,

    /// Apply to all results with the same name without prompting
    #[arg(short, long, default_value = "false")]
    all: bool,
}

#[derive(Clone, Parser, Debug)]
pub struct RmProjectArgs {
    /// Projects to remove
    #[arg(required(true))]
    projects: Vec<String>,

    /// Do not ask for confirmation
    #[arg(short('y'), long("yes"))]
    force: bool,

    /// Do not print purely informational messages
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmProjectOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "terminateJobs")]
    terminate_jobs: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmProjectResult {
    id: String,
}

#[derive(Clone, Parser, Debug)]
pub struct RmdirArgs {
    /// Object IDs or paths
    #[arg()]
    paths: Vec<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct SelectArgs {
    /// Project ID or name
    #[arg()]
    project: Option<String>,

    /// Access level
    #[arg(long, value_enum, default_value = "CONTRIBUTE")]
    level: Option<AccessLevel>,
}

#[derive(Debug)]
enum DescribeObject {
    Analysis {
        analysis_id: String,
    },
    App {
        app_id: String,
    },
    Applet {
        project_id: Option<String>,
        applet_id: String,
    },
    Container {
        container_id: String,
    },
    Database {
        project_id: Option<String>,
        database_id: String,
    },
    File {
        project_id: Option<String>,
        file_id: String,
    },
    Job {
        job_id: String,
    },
    Project {
        project_id: String,
    },
    Record {
        project_id: Option<String>,
        record_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DxErrorResponse {
    error: DxErrorPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DxErrorPayload {
    #[serde(rename = "type")]
    error_type: String,

    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    username: String,

    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmOptions {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    objects: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmResult {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmdirOptions {
    folder: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    recurse: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    partial: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RmdirResult {
    id: String,

    completed: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preauthenticated: Option<bool>,

    #[serde(rename = "stickyIP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sticky_ip: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadResponse {
    url: String,

    headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileCloseOptions {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileCloseResponse {
    id: String,

    detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ProjectPath {
    pub project_id: String,

    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileNewOptions {
    project: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    types: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    parents: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileNewResponse {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileUploadOptions {
    size: usize,

    md5: String,

    index: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileUploadResponse {
    url: String,

    expires: u64,

    headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindAppsOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<FindName>,

    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,

    #[serde(rename = "allVersions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    all_versions: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<bool>,

    #[serde(rename = "billTo")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bill_to: Vec<String>,

    #[serde(rename = "createdBy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    developer: Option<String>,

    #[serde(rename = "authorizedUser")]
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_user: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    starting: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    describe: Option<FindAppsDescribe>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindAppsResponse {
    results: Vec<FindAppsResult>,

    next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindAppsResult {
    id: String,

    describe: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindAppsDescribe {
    fields: HashMap<AppDescribeField, bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindDataResponse {
    results: Vec<FindDataResult>,

    next: Option<FindDataResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FindDataResult {
    project: String,

    id: String,

    describe: Option<FindDataDescribe>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FindDataDescribe {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<ObjectState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<ObjectType>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    types: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    links: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,

    #[serde(rename = "archivalState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    archival_state: Option<ArchivalState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cloudAccount")]
    cloud_account: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindDataOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<ObjectType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<ObjectState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<FindName>,

    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<Visibility>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    id: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    object_type: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    region: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<FindDataScope>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sortBy")]
    sort_by: Option<FindDataSortBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<AccessLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<SearchTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<SearchTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    describe: Option<FindDescribe>,

    #[serde(skip_serializing_if = "Option::is_none")]
    starting: Option<FindDataResult>,

    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "archivalState")]
    archival_state: Option<ArchivalState>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FindDescribe {
    Boolean(bool),

    Mapping(HashMap<String, bool>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchTime {
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindDataSortBy {
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<SortByField>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ordering: Option<SortOrdering>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SortByField {
    #[serde(rename = "created")]
    Created,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SortOrdering {
    #[serde(rename = "ascending")]
    Ascending,

    #[serde(rename = "descending")]
    Descending,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindDataScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    recurse: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Visibility {
    #[serde(rename = "hidden")]
    Hidden,

    #[serde(rename = "visible")]
    Visible,

    #[serde(rename = "either")]
    Either,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindProjectsOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<FindName>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    id: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<AccessLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    starting: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    describe: Option<FindProjectsDescribe>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindProjectsDescribe {
    fields: HashMap<ProjectDescribeField, bool>,
}

#[derive(Debug, Serialize, Deserialize)]
enum FindName {
    #[serde(rename = "glob")]
    Glob(String),

    #[serde(rename = "regexp")]
    Regexp(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindProjectsResponse {
    results: Vec<FindProjectsResult>,

    next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindProjectsResult {
    id: String,

    level: AccessLevel,

    #[serde(rename = "permissionSources")]
    permission_sources: Vec<String>,

    public: bool,

    describe: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    #[serde(rename = "VIEW")]
    View,

    #[serde(rename = "UPLOAD")]
    Upload,

    #[serde(rename = "CONTRIBUTE")]
    Contribute,

    #[serde(rename = "ADMINISTER")]
    Administer,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccessLevel::View => write!(f, "VIEW"),
            AccessLevel::Upload => write!(f, "UPLOAD"),
            AccessLevel::Contribute => write!(f, "CONTRIBUTE"),
            AccessLevel::Administer => write!(f, "ADMINISTER"),
        }
    }
}

impl ValueEnum for AccessLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            AccessLevel::View,
            AccessLevel::Upload,
            AccessLevel::Contribute,
            AccessLevel::Administer,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            AccessLevel::View => PossibleValue::new("VIEW"),
            AccessLevel::Upload => PossibleValue::new("UPLOAD"),
            AccessLevel::Contribute => PossibleValue::new("CONTRIBUTE"),
            AccessLevel::Administer => PossibleValue::new("ADMINISTER"),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListFolderObject {
    id: String,

    describe: Option<ListFolderObjectDescribe>,
}

// TODO: More types
#[derive(Debug, Serialize, Deserialize, EnumString, Clone)]
pub enum ObjectType {
    #[strum(serialize = "applet")]
    #[serde(rename = "applet")]
    Applet,

    #[strum(serialize = "file")]
    #[serde(rename = "file")]
    File,

    #[strum(serialize = "record")]
    #[serde(rename = "record")]
    Record,

    #[strum(serialize = "workflow")]
    #[serde(rename = "workflow")]
    Workflow,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ObjectState {
    #[serde(rename = "opening")]
    Opening,

    #[serde(rename = "open")]
    Open,

    #[serde(rename = "closed")]
    Closed,

    #[serde(rename = "any")]
    Any,
}

impl fmt::Display for ObjectState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ObjectState::Opening => write!(f, "opening"),
            ObjectState::Open => write!(f, "open"),
            ObjectState::Closed => write!(f, "closed"),
            ObjectState::Any => write!(f, "any"),
        }
    }
}

// https://documentation.dnanexus.com/user/objects/archiving-files
// #file-archival-states
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ArchivalState {
    #[serde(rename = "live")]
    Live,

    #[serde(rename = "archival")]
    Archival,

    #[serde(rename = "archived")]
    Archived,

    #[serde(rename = "unarchiving")]
    Unarchiving,

    #[serde(rename = "any")]
    Any,
}

impl fmt::Display for ArchivalState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArchivalState::Live => write!(f, "live"),
            ArchivalState::Archival => write!(f, "archival"),
            ArchivalState::Archived => write!(f, "archived"),
            ArchivalState::Unarchiving => write!(f, "unarchiving"),
            ArchivalState::Any => write!(f, "any"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListFolderObjectDescribe {
    id: String,

    project: String,

    class: ObjectType,

    sponsored: bool,

    name: String,

    types: Vec<String>,

    state: ObjectState,

    hidden: bool,

    links: Vec<String>,

    folder: String,

    tags: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(rename = "createdBy")]
    created_by: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "archivalState")]
    archival_state: Option<ArchivalState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cloudAccount")]
    cloud_account: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListFolderResult {
    objects: Option<Vec<ListFolderObject>>,

    folders: Option<Vec<(String, bool)>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListFolderOptions<'a> {
    folder: &'a str,

    // TODO: handle listing/bool
    //describe: HashMap<ListFolderDescribeField, bool>,
    describe: bool,

    only: Option<ListFolderOptionOnlyValue>,

    #[serde(rename = "includeHidden")]
    include_hidden: bool,

    #[serde(rename = "hasSubfolderFlags")]
    has_subfolder_flags: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum ListFolderOptionOnlyValue {
    #[serde(rename = "folders")]
    Folders,

    #[serde(rename = "objects")]
    Objects,

    #[serde(rename = "all")]
    All,
}

#[derive(Debug, Hash, Serialize, Deserialize, PartialEq, Eq, EnumIter)]
enum ListFolderDescribeField {
    #[serde(rename = "class")]
    Class,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "summary")]
    Summary,

    #[serde(rename = "description")]
    Description,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MakeFolderOptions {
    folder: String,

    parents: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewProjectOptions {
    name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    protected: bool,

    restricted: bool,

    #[serde(rename = "downloadRestricted")]
    download_restricted: bool,

    #[serde(rename = "externalUploadRestricted")]
    external_upload_restricted: bool,

    #[serde(rename = "databaseUIViewOnly")]
    database_ui_view_only: bool,

    #[serde(rename = "containsPHI")]
    contains_phi: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(rename = "billTo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(rename = "monthlyComputeLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    monthly_compute_limit: Option<u64>,

    #[serde(rename = "monthlyEgressBytesLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    monthly_egress_bytes_limit: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewProjectResult {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MakeFolderResult {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    access_token: String,
    token_signature: String,
    token_type: String,
    user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoAmIOptions {
    fields: Option<HashMap<WhoAmIOptionsFields, bool>>,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum WhoAmIOptionsFields {
    #[serde(rename = "clientIp")]
    ClientIp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoAmIResult {
    id: String,

    #[serde(rename = "clientIp")]
    client_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisDescribeOptions {
    fields: HashMap<AnalysisDescribeField, bool>,
}

// TODO: totalEgress, subtotalPriceInfo, subtotalEgressInfo
// https://documentation.dnanexus.com/developer/api/running-analyses/
// workflows-and-analyses#api-method-analysis-xxxx-describe
#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, EnumIter)]
pub enum AnalysisDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "executable")]
    Executable,

    #[serde(rename = "executableName")]
    ExecutableName,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "billTo")]
    BillTo,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "rootExecution")]
    RootExecution,

    #[serde(rename = "parentJob")]
    ParentJob,

    #[serde(rename = "parentJobTry")]
    ParentJobTry,

    #[serde(rename = "parentAnalysis")]
    ParentAnalysis,

    #[serde(rename = "detachedFrom")]
    DetachedFrom,

    #[serde(rename = "detachedFromTry")]
    DetachedFromTry,

    #[serde(rename = "analysis")]
    Analysis,

    #[serde(rename = "stage")]
    Stage,

    #[serde(rename = "stages")]
    Stages,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "workspace")]
    Workspace,

    #[serde(rename = "workflow")]
    Workflow,

    #[serde(rename = "priority")]
    Priority,

    #[serde(rename = "outputReusedFrom")]
    OutputReusedFrom,

    #[serde(rename = "workerReuseDeadlineRunTime")]
    WorkerReuseDeadlineRunTime,

    #[serde(rename = "dependsOn")]
    DependsOn,

    #[serde(rename = "launchedBy")]
    LaunchedBy,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "details")]
    Details,

    #[serde(rename = "runInput")]
    RunInput,

    #[serde(rename = "originalInput")]
    OriginalInput,

    //#[serde(rename = "input")]
    //Input,
    #[serde(rename = "output")]
    Output,

    #[serde(rename = "delayWorkspaceDestruction")]
    DelayWorkspaceDestruction,

    #[serde(rename = "ignoreReuse")]
    IgnoreReuse,

    #[serde(rename = "preserveJobOutputs")]
    PreserveJobOutputs,

    #[serde(rename = "detailedJobMetrics")]
    DetailedJobMetrics,

    #[serde(rename = "costLimit")]
    CostLimit,

    #[serde(rename = "rank")]
    Rank,

    #[serde(rename = "selectedTreeTurnaroundTimeThreshold")]
    SelectedTreeTurnaroundTimeThreshold,

    #[serde(rename = "selectedTreeTurnaroundTimeThresholdFrom")]
    SelectedTreeTurnaroundTimeThresholdFrom,

    #[serde(rename = "treeTurnaroundTime")]
    TreeTurnaroundTime,

    #[serde(rename = "currency")]
    Currency,

    #[serde(rename = "totalPrice")]
    TotalPrice,

    #[serde(rename = "priceComputedAt")]
    PriceComputedAt,

    #[serde(rename = "egressComputedAt")]
    EgressComputedAt,

    #[serde(rename = "totalEgress")]
    TotalEgress,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "executableName")]
    executable_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rootExecution")]
    root_execution: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentJob")]
    parent_job: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentJobTry")]
    parent_job_try: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentAnalysis")]
    parent_analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachedFrom")]
    detached_from: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachedFromTry")]
    detached_from_try: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stages: Option<Vec<AnalysisStage>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<Workflow>,

    priority: Option<String>,

    #[serde(rename = "outputReusedFrom")]
    output_reused_from: Option<String>,

    #[serde(rename = "workerReuseDeadlineRunTime")]
    worker_reuse_deadline_run_time: Option<KitchenSink>,

    #[serde(rename = "dependsOn")]
    depends_on: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "launchedBy")]
    launched_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,

    //run_input: Option<HashMap<String, RunInputValue>>,
    // TODO: cf analysis-GbxgbB8098YzQ0K3FBfFqyB2
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "runInput")]
    run_input: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "originalInput")]
    original_input: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "delayWorkspaceDestruction")]
    delay_workspace_destruction: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ignoreReuse")]
    ignore_reuse: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "preserveJobOutputs")]
    preserve_job_outputs: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detailedJobMetrics")]
    detailed_job_metrics: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "costLimit")]
    cost_limit: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "selectedTreeTurnaroundTimeThreshold")]
    selected_tree_turnaround_time_threshold: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "selectedTreeTurnaroundTimeThresholdFrom")]
    selected_tree_turnaround_time_threshold_trom: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "treeTurnaroundTime")]
    tree_turnaround_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<Currency>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "totalPrice")]
    total_price: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "priceComputedAt")]
    #[serde(default)]
    price_computed_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "egressComputedAt")]
    #[serde(default)]
    egress_computed_at: Option<DateTime<Utc>>,

    #[serde(rename = "totalEgress")]
    total_egress: Option<HashMap<String, u64>>,
}

// Tried to get this to work but abandoned in favor of KitchenSink
// but maybe revisit later to have more something specific?
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunInputValue {
    StringValue(String),

    FileInputValue,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileInputValue {
    Single(FileDescriptor),

    List(Vec<FileDescriptor>),
}

impl fmt::Display for FileInputValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FileInputValue::Single(val) => write!(f, "{}", val),
            FileInputValue::List(vals) => {
                write!(
                    f,
                    "[{}]",
                    vals.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisStage {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<AnalysisStageExecution>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisStageExecution {
    id: String,

    executable: Option<String>,

    #[serde(rename = "executableName")]
    executable_name: Option<String>,

    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "costLimit")]
    cost_limit: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "invoiceMetadata")]
    invoice_metadata: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentJob")]
    parent_job: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "originJob")]
    origin_job: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentAnalysis")]
    parent_analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rootExecution")]
    root_execution: Option<String>,

    // TODO: enum?
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "launchedBy")]
    launched_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachedFrom")]
    detached_from: Option<String>,

    // TODO: enum?
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,

    #[serde(rename = "outputReusedFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    output_reused_from: Option<String>,

    #[serde(rename = "workerReuseDeadlineRunTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_reuse_deadline_run_time: Option<KitchenSink>,

    #[serde(rename = "dependsOn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<Vec<String>>,

    #[serde(rename = "singleContext")]
    #[serde(skip_serializing_if = "Option::is_none")]
    single_context: Option<bool>,

    #[serde(rename = "failureCounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_counts: Option<KitchenSink>,

    #[serde(rename = "stateTransitions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    state_transitions: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    applet: Option<String>,

    #[serde(rename = "ignoreReuse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_reuse: Option<bool>,

    #[serde(rename = "httpsApp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    https_app: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, String>>,

    #[serde(rename = "systemRequirements")]
    #[serde(skip_serializing_if = "Option::is_none")]
    system_requirements: Option<HashMap<String, AppSystemRequirement>>,

    #[serde(rename = "executionPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_policy: Option<KitchenSink>,

    #[serde(rename = "instanceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_type: Option<String>,

    #[serde(rename = "trueInstanceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    true_instance_type: Option<String>,

    #[serde(rename = "finalPriority")]
    #[serde(skip_serializing_if = "Option::is_none")]
    final_priority: Option<String>,

    #[serde(rename = "networkAccess")]
    #[serde(skip_serializing_if = "Option::is_none")]
    network_access: Option<Vec<String>>,

    #[serde(rename = "runInput")]
    #[serde(skip_serializing_if = "Option::is_none")]
    //run_input: Option<HashMap<String, FileInputValue>>,
    run_input: Option<HashMap<String, KitchenSink>>,

    #[serde(rename = "originalInput")]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_input: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "startedRunning")]
    #[serde(default)]
    started_running: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "stoppedRunning")]
    #[serde(default)]
    stopped_running: Option<DateTime<Utc>>,

    #[serde(rename = "delayWorkspaceDestruction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_workspace_destruction: Option<bool>,

    #[serde(rename = "preserveJobOutputs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    preserve_job_outputs: Option<bool>,

    #[serde(rename = "detailedJobMetrics")]
    #[serde(skip_serializing_if = "Option::is_none")]
    detailed_job_metrics: Option<bool>,

    #[serde(rename = "isFree")]
    #[serde(skip_serializing_if = "Option::is_none")]
    is_free: Option<bool>,

    #[serde(rename = "totalPrice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    total_price: Option<f64>,

    #[serde(rename = "totalEgress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    total_egress: Option<HashMap<String, u64>>,

    #[serde(rename = "egressReport")]
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_report: Option<HashMap<String, u64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "priceComputedAt")]
    #[serde(default)]
    price_computed_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "egressComputedAt")]
    #[serde(default)]
    egress_computed_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<Currency>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,

    #[serde(rename = "treeTurnaroundTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tree_turnaround_time: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Workflow {
    id: String,

    project: String,

    class: String,

    name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(rename = "outputFolder")]
    #[serde(skip_serializing_if = "Option::is_none")]
    output_folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    temporary: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<WorkflowState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "costLimit")]
    cost_limit: Option<String>,

    #[serde(rename = "stateTransitions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    state_transitions: Option<Vec<HashMap<String, KitchenSink>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<WorkflowDetails>,

    #[serde(rename = "editVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    edit_version: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stages: Option<Vec<WorkflowStage>>,

    #[serde(rename = "inputSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    input_spec: Option<Vec<WorkflowInputSpec>>,

    #[serde(rename = "outputSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    output_spec: Option<Vec<WorkflowOutputSpec>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowOutputSpec {
    name: String,

    class: String,

    group: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowInputSpec {
    name: String,

    class: String,

    group: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,

    //default: Option<HashMap<String, HashMap<String, String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<KitchenSink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowStage {
    id: String,

    name: String,

    executable: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    accessible: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "executionPolicy")]
    execution_policy: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "systemRequirements")]
    system_requirements: Option<KitchenSink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowDetails {
    #[serde(rename = "originalName")]
    original_name: String,

    #[serde(rename = "sourceCode")]
    source_code: String,

    version: String,

    checksum: String,

    #[serde(rename = "docContents")]
    doc_contents: String,

    #[serde(rename = "execTree")]
    exec_tree: String,

    #[serde(rename = "parseOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_options: Option<HashMap<String, String>>,

    #[serde(rename = "staticInstanceTypeSelection")]
    static_instance_type_selection: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkflowState {
    #[serde(rename = "in_progress")]
    InProgress,

    #[serde(rename = "partially_failed")]
    PartiallyFailed,

    #[serde(rename = "done")]
    Done,

    #[serde(rename = "failed")]
    Failed,

    #[serde(rename = "terminating")]
    Terminating,

    #[serde(rename = "terminated")]
    Terminated,

    #[serde(rename = "closed")]
    Closed,
}

impl fmt::Display for WorkflowState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WorkflowState::InProgress => write!(f, "in_progress"),
            WorkflowState::PartiallyFailed => write!(f, "paritially_failed"),
            WorkflowState::Done => write!(f, "done"),
            WorkflowState::Failed => write!(f, "failed"),
            WorkflowState::Terminating => write!(f, "terminating"),
            WorkflowState::Terminated => write!(f, "terminated"),
            WorkflowState::Closed => write!(f, "closed"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerDescribeOptions {
    fields: Option<HashMap<ContainerDescribeField, bool>>,
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, EnumIter)]
pub enum ContainerDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "region")]
    Region,

    #[serde(rename = "billTo")]
    BillTo,

    #[serde(rename = "type")]
    Type,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "level")]
    Level,

    #[serde(rename = "dataUsage")]
    DataUsage,

    #[serde(rename = "sponsoredDataUsage")]
    SponsoredDataUsage,

    #[serde(rename = "remoteDataUsage")]
    RemoteDataUsage,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "app")]
    App,

    #[serde(rename = "appName")]
    AppName,

    #[serde(rename = "destroyAt")]
    DestroyAt,

    #[serde(rename = "folders")]
    Folders,

    #[serde(rename = "cloudAccount")]
    CloudAccount,
    //https://documentation.dnanexus.com/developer/api/running-analyses/
    //containers-for-execution#api-method-container-xxxx-describe
    //#[serde(rename = "fileUploadParameters")]
    //FileUploadParameters,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    container_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<AccessLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dataUsage")]
    data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sponsoredDataUsage")]
    sponsored_data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "remoteDataUsage")]
    remote_data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "appName")]
    app_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cloudAccount")]
    cloud_account: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "destroyAt")]
    destroy_at: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folders: Option<Vec<String>>,
}

// TODO: Handle all fields at https://documentation.dnanexus.com/developer/
// api/data-containers/projects#project-metadata ?
#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, EnumIter)]
pub enum ProjectDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "region")]
    Region,

    #[serde(rename = "summary")]
    Summary,

    #[serde(rename = "description")]
    Description,

    #[serde(rename = "version")]
    Version,

    #[serde(rename = "changes")]
    Changes,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "cloudAccount")]
    CloudAccount,

    #[serde(rename = "remoteDataUsage")]
    RemoteDataUsage,

    #[serde(rename = "archivedDataUsage")]
    ArchivedDataUsage,

    #[serde(rename = "previewViewerRestricted")]
    PreviewViewerRestricted,

    #[serde(rename = "displayDataProtectionNotice")]
    DisplayDataProtectionNotice,

    #[serde(rename = "billTo")]
    BillTo,

    #[serde(rename = "with")]
    With,

    #[serde(rename = "protected")]
    Protected,

    #[serde(rename = "restricted")]
    Restricted,

    #[serde(rename = "downloadRestricted")]
    DownloadRestricted,

    #[serde(rename = "externalUploadRestricted")]
    ExternalUploadRestricted,

    #[serde(rename = "containsPHI")]
    ContainsPHI,

    #[serde(rename = "databaseUIViewOnly")]
    DatabaseUIViewOnly,

    #[serde(rename = "currency")]
    Currency,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "user")]
    User,

    #[serde(rename = "job")]
    Job,

    #[serde(rename = "executable")]
    Executable,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "level")]
    Level,

    #[serde(rename = "dataUsage")]
    DataUsage,

    #[serde(rename = "storageCost")]
    StorageCost,

    #[serde(rename = "defaultInstanceType")]
    DefaultInstanceType,

    #[serde(rename = "provider")]
    Provider,

    #[serde(rename = "sponsoredDataUsage")]
    SponsoredDataUsage,

    #[serde(rename = "sponsoredUntil")]
    SponsoredUntil,

    #[serde(rename = "pendingTransfer")]
    PendingTransfer,

    #[serde(rename = "totalSponsoredEgressBytes")]
    TotalSponsoredEgressBytes,

    #[serde(rename = "consumedSponsoredEgressBytes")]
    ConsumedSponsoredEgressBytes,

    #[serde(rename = "allowedExecutables")]
    AllowedExecutables,

    #[serde(rename = "atSpendingLimit")]
    AtSpendingLimit,

    #[serde(rename = "folders")]
    Folders,

    #[serde(rename = "objects")]
    Objects,

    #[serde(rename = "permissions")]
    Permissions,

    #[serde(rename = "appCaches")]
    AppCaches,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectDescribeOptions {
    fields: Option<HashMap<ProjectDescribeField, bool>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreatedBy {
    user: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    job: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cloudAccount")]
    cloud_account: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "remoteDataUsage")]
    remote_data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "archivedDataUsage")]
    archived_data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "previewViewerRestricted")]
    preview_viewer_restricted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "displayDataProtectionNotice")]
    display_data_protection_notice: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    with: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restricted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "downloadRestricted")]
    download_restricted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalUploadRestricted")]
    external_upload_restricted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "containsPHI")]
    contains_phi: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "databaseUIViewOnly")]
    database_ui_view_only: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<Currency>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<AccessLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dataUsage")]
    data_usage: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "storageCost")]
    storage_cost: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "defaultInstanceType")]
    default_instance_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sponsoredDataUsage")]
    sponsored_data_usage: Option<f64>,

    #[serde(rename = "sponsoredUntil")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    sponsored_until: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pendingTransfer")]
    pending_transfer: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "totalSponsoredEgressBytes")]
    total_sponsored_egress_bytes: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "consumedSponsoredEgressBytes")]
    consumed_sponsored_egress_bytes: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "allowedExecutables")]
    allowed_executables: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "atSpendingLimit")]
    at_spending_limit: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folders: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    objects: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<HashMap<String, AccessLevel>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "appCaches")]
    app_caches: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Currency {
    #[serde(rename = "dxCode")]
    dx_code: u64,

    code: String,

    symbol: String,

    #[serde(rename = "symbolPosition")]
    symbol_position: String,

    #[serde(rename = "decimalSymbol")]
    decimal_symbol: String,

    #[serde(rename = "groupingSymbol")]
    grouping_symbol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppAccess {
    pub network: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppInputSpec {
    pub name: String,

    pub class: InputOutputClass,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
}

impl fmt::Display for AppInputSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let is_optional = &self.optional.unwrap_or(false);
        write!(
            f,
            "{}{} ({}){}",
            if *is_optional { "[" } else { "" },
            &self.name,
            &self.class,
            if *is_optional { "]" } else { "" },
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppOutputSpec {
    pub name: String,

    pub class: InputOutputClass,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

impl fmt::Display for AppOutputSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let is_optional = &self.optional.unwrap_or(false);
        write!(
            f,
            "{}{} ({}){}",
            if *is_optional { "[" } else { "" },
            &self.name,
            &self.class,
            if *is_optional { "]" } else { "" },
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppSystemRequirement {
    #[serde(rename = "instanceType")]
    instance_type: Option<String>,
}

impl fmt::Display for AppSystemRequirement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{\"instanceType\": \"{}\"}}",
            &self.instance_type.clone().unwrap_or("NA".to_string())
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppBundledDepends {
    pub id: DxFileDescriptor,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stages: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppRunSpec {
    pub interpreter: Interpreter,

    pub distribution: LinuxDistribution,

    pub release: LinuxRelease,

    pub version: LinuxVersion,

    #[serde(rename = "headJobOnDemand")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_job_on_demand: Option<bool>,

    #[serde(rename = "inheritParentRestartOnPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherit_parent_restart_on_policy: Option<bool>,

    #[serde(rename = "bundledDepends")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundled_depends: Option<Vec<AppBundledDepends>>,

    #[serde(rename = "bundledDependsByRegion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundled_depends_by_region:
        Option<HashMap<String, Vec<HashMap<String, KitchenSink>>>>,

    #[serde(default, rename = "systemRequirements")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_requirements: Option<HashMap<String, AppSystemRequirement>>,

    #[serde(rename = "systemRequirementsByRegion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_requirements_by_region: Option<HashMap<String, KitchenSink>>,

    #[serde(default, rename = "executionPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_policy: Option<KitchenSink>,

    #[serde(rename = "timeoutPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_policy: Option<HashMap<String, HashMap<TimeoutUnit, u32>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppDescribeOptions {
    pub fields: HashMap<AppDescribeField, bool>,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum AppDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "billTo")]
    BillTo,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "version")]
    Version,

    #[serde(rename = "aliases")]
    Aliases,

    #[serde(rename = "region")]
    Region,

    #[serde(rename = "applet")]
    Applet,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "installed")]
    Installed,

    #[serde(rename = "openSource")]
    OpenSource,

    #[serde(rename = "ignoreReuse")]
    IgnoreReuse,

    #[serde(rename = "deleted")]
    Deleted,

    #[serde(rename = "installs")]
    Installs,

    #[serde(rename = "isDeveloperFor")]
    IsDeveloperFor,

    #[serde(rename = "authorizedUsers")]
    AuthorizedUsers,

    #[serde(rename = "regionalOptions")]
    RegionalOptions,

    #[serde(rename = "httpsApp")]
    HttpsApp,

    #[serde(rename = "published")]
    Published,

    #[serde(rename = "title")]
    Title,

    #[serde(rename = "summary")]
    Summary,

    #[serde(rename = "description")]
    Description,

    #[serde(rename = "details")]
    Details,

    #[serde(rename = "categories")]
    Categories,

    #[serde(rename = "lineItemPerTest")]
    LineItemPerTest,

    #[serde(rename = "access")]
    Access,

    #[serde(rename = "inputSpec")]
    InputSpec,

    #[serde(rename = "outputSpec")]
    OutputSpec,

    #[serde(rename = "dxapi")]
    DxApi,

    #[serde(rename = "runSpec")]
    RunSpec,

    #[serde(rename = "treeTurnaroundTimeThreshold")]
    TreeTurnaroundTimeThreshold,

    #[serde(rename = "resources")]
    Resources,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    aliases: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    applet: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "ts_milliseconds_option")]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "ts_milliseconds_option")]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "ts_milliseconds_option")]
    published: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    installed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "openSource")]
    open_source: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ignoreReuse")]
    ignore_reuse: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    installs: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "isDeveloperFor")]
    is_developer_for: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "authorizedUsers")]
    authorized_users: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "regionalOptions")]
    regional_options: Option<HashMap<String, AppRegionalOptions>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "httpsApp")]
    https_app: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    categories: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lineItemPerTest")]
    line_item_per_test: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<AppAccess>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "inputSpec")]
    input_spec: Option<Vec<AppInputSpec>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "outputSpec")]
    pub output_spec: Option<Vec<AppOutputSpec>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dxapi")]
    dx_api: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "runSpec")]
    run_spec: Option<AppRunSpec>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "treeTurnaroundTimeThreshold")]
    tree_turnaround_time_threshold: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "resources")]
    resources: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppRegionalOptions {
    pub applet: String,

    pub resources: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pricingPolicy")]
    pub pricing_policy: Option<AppPricingPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppPricingPolicy {
    pub unit: String,

    #[serde(rename = "unitPrice")]
    pub unit_price: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppletDescribeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<HashMap<AppletDescribeField, bool>>,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum AppletDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "types")]
    Types,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "hidden")]
    Hidden,

    #[serde(rename = "links")]
    Links,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "sponsored")]
    Sponsored,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "runSpec")]
    RunSpec,

    #[serde(rename = "dxapi")]
    DxApi,

    #[serde(rename = "access")]
    Access,

    #[serde(rename = "title")]
    Title,

    #[serde(rename = "summary")]
    Summary,

    #[serde(rename = "description")]
    Description,

    #[serde(rename = "developerNotes")]
    DeveloperNotes,

    #[serde(rename = "ignoreReuse")]
    IgnoreReuse,

    #[serde(rename = "httpsApps")]
    HttpsApp,

    #[serde(rename = "treeTurnaroundTimeThreshold")]
    TreeTurnaroundTimeThreshold,

    #[serde(rename = "inputSpec")]
    InputSpec,

    #[serde(rename = "outputSpec")]
    OutputSpec,

    #[serde(rename = "sponsoredUntil")]
    SponsoredUntil,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "details")]
    Details,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppletDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dxapi")]
    dx_api: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "developerNotes")]
    developer_notes: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ignoreReuse")]
    ignore_reuse: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "treeTurnaroundTimeThreshold")]
    tree_turnaround_time_threshold: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<AppAccess>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "httpsApps")]
    https_app: Option<AppHttpsApp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "runSpec")]
    run_spec: Option<AppRunSpec>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "inputSpec")]
    input_spec: Option<Vec<AppInputSpec>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "outputSpec")]
    output_spec: Option<Vec<AppOutputSpec>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sponsoredUntil")]
    sponsored_until: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppHttpsApp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_access: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl fmt::Display for AppHttpsApp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //write!(
        //    f,
        //    "{{ports: {}, enabled: {}}}",
        //    &self.ports.map_or("null".to_string(), |ports| ports
        //        .iter()
        //        .map(|v| v.to_string())
        //        .collect::<Vec<_>>()
        //        .join(", ")),
        //    &self.enabled.map_or("null".to_string(), |v| v.to_string())
        //)
        write!(
            f,
            "{{enabled: {}}}",
            &self.enabled.map_or("null".to_string(), |v| v.to_string())
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseDescribeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<HashMap<DatabaseDescribeField, bool>>,

    properties: bool,

    details: bool,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum DatabaseDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "databaseName")]
    DatabaseName,

    #[serde(rename = "uniqueDatabaseName")]
    UniqueDatabaseName,

    #[serde(rename = "types")]
    Types,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "hidden")]
    Hidden,

    #[serde(rename = "links")]
    Links,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "sponsored")]
    Sponsored,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "sponsoredUntil")]
    SponsoredUntil,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "details")]
    Details,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "databaseName")]
    database_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "uniqueDatabaseName")]
    unique_database_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "sponsoredUntil")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    sponsored_until: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDescribeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<FileDescribeField, bool>>,

    pub properties: bool,

    pub details: bool,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum FileDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "types")]
    Types,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "hidden")]
    Hidden,

    #[serde(rename = "links")]
    Links,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "sponsored")]
    Sponsored,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "media")]
    Media,

    #[serde(rename = "size")]
    Size,

    #[serde(rename = "cloudAccount")]
    CloudAccount,

    #[serde(rename = "archivalState")]
    ArchivalState,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "details")]
    Details,

    #[serde(rename = "watermarkId")]
    WatermarkId,

    #[serde(rename = "watermarkVersion")]
    WatermarkVersion,

    #[serde(rename = "resolvedPolicies")]
    ResolvedPolicies,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cloudAccount")]
    cloud_account: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "archivalState")]
    archival_state: Option<ArchivalState>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,

    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "sponsoredUntil")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    sponsored_until: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "watermarkId")]
    watermark_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "watermarkVersion")]
    watermark_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "resolvedPolicies")]
    resolved_policies: Option<HashMap<String, bool>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum KitchenSink {
    StringValue(String),

    IntValue(i64),

    BooleanValue(bool),

    FileValue(FileDescriptor),

    List(Vec<KitchenSink>),

    Mapping(HashMap<String, KitchenSink>),
}

impl fmt::Display for KitchenSink {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KitchenSink::StringValue(val) => {
                write!(f, "\"{val}\"")
            }
            KitchenSink::BooleanValue(val) => write!(f, "{val}"),
            KitchenSink::IntValue(val) => write!(f, "{val}"),
            KitchenSink::FileValue(val) => write!(f, "{val}"),
            KitchenSink::List(vals) => write!(
                f,
                "[{}]",
                vals.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            KitchenSink::Mapping(val) => {
                write!(
                    f,
                    "{{{}}}",
                    val.iter()
                        .map(|(k, v)| format!("\"{k}\": {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

//#[derive(Debug, Serialize, Deserialize)]
//#[serde(untagged)]
//pub enum KitchenSinkValue {
//    StringValue(String),

//    BooleanValue(bool),

//    IntValue(i64),

//    FileValue(FileDescriptor),
//}

//impl fmt::Display for KitchenSinkValue {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        match self {
//            KitchenSinkValue::StringValue(val) => {
//                write!(f, "\"{val}\"")
//            }
//            KitchenSinkValue::BooleanValue(val) => write!(f, "{val}"),
//            KitchenSinkValue::IntValue(val) => write!(f, "{val}"),
//            KitchenSinkValue::FileValue(val) => write!(f, "{val}"),
//        }
//    }
//}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum FileDescriptor {
    Simple(String),

    Dx(DxFileDescriptor),
}

impl fmt::Display for FileDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FileDescriptor::Simple(val) => write!(f, "{val}"),
            FileDescriptor::Dx(dx_file) => {
                write!(f, "{}", dx_file)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DxFileDescriptor {
    #[serde(rename = "$dnanexus_link")]
    dnanexus_link: DxFileDescriptorValue,
}

impl fmt::Display for DxFileDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dnanexus_link)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DxFileDescriptorComplex {
    analysis: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,

    #[serde(rename = "wasInternal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    was_internal: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DxFileDescriptorProject {
    project: String,

    id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum DxFileDescriptorValue {
    FileId(String),

    File(DxFileDescriptorProject),

    Analysis(DxFileDescriptorComplex),
}

impl fmt::Display for DxFileDescriptorValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DxFileDescriptorValue::FileId(file_id) => {
                write!(f, "{file_id}")
            }
            DxFileDescriptorValue::File(val) => {
                write!(f, "{}:{}", val.project, val.id)
            }
            DxFileDescriptorValue::Analysis(val) => {
                write!(f, "{}", val.analysis)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobDescribeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "defaultFields")]
    pub default_fields: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<JobDescribeField, bool>>,

    #[serde(rename = "try")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub try_number: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum JobDescribeField {
    #[serde(rename = "try")]
    Try,

    #[serde(rename = "id")]
    Id,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "executableName")]
    ExecutableName,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "currency")]
    Currency,

    #[serde(rename = "tryCreated")]
    TryCreated,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "startedRunning")]
    StartedRunning,

    #[serde(rename = "stoppedRunning")]
    StoppedRunning,

    #[serde(rename = "egressReport")]
    EgressReport,

    #[serde(rename = "billTo")]
    BillTo,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "rootExecution")]
    RootExecution,

    #[serde(rename = "parentJob")]
    ParentJob,

    #[serde(rename = "parentJobTry")]
    ParentJobTry,

    #[serde(rename = "originJob")]
    OriginJob,

    #[serde(rename = "detachedFrom")]
    DetachedFrom,

    #[serde(rename = "detachedFromTry")]
    DetachedFromTry,

    #[serde(rename = "parentAnalysis")]
    ParentAnalysis,

    #[serde(rename = "analysis")]
    Analysis,

    #[serde(rename = "stage")]
    Stage,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "stateTransitions")]
    StateTransitions,

    #[serde(rename = "workspace")]
    Workspace,

    #[serde(rename = "launchedBy")]
    LaunchedBy,

    #[serde(rename = "function")]
    Function,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "priority")]
    Priority,

    #[serde(rename = "finalPriority")]
    FinalPriority,

    #[serde(rename = "rank")]
    Rank,

    #[serde(rename = "details")]
    Details,

    #[serde(rename = "systemRequirements")]
    SystemRequirements,

    #[serde(rename = "executionPolicy")]
    ExecutionPolicy,

    #[serde(rename = "timeout")]
    Timeout,

    #[serde(rename = "instanceType")]
    InstanceType,

    #[serde(rename = "networkAccess")]
    NetworkAccess,

    #[serde(rename = "delayWorkspaceDestruction")]
    DelayWorkspaceDestruction,

    #[serde(rename = "dependsOn")]
    DependsOn,

    #[serde(rename = "failureReason")]
    FailureReason,

    #[serde(rename = "failureMessage")]
    FailureMessage,

    #[serde(rename = "failureFrom")]
    FailureFrom,

    #[serde(rename = "failureReports")]
    FailureReports,

    #[serde(rename = "failureCounts")]
    FailureCounts,

    #[serde(rename = "runInput")]
    RunInput,

    #[serde(rename = "originalInput")]
    OriginalInput,

    #[serde(rename = "input")]
    Input,

    #[serde(rename = "output")]
    Output,

    #[serde(rename = "region")]
    Region,

    #[serde(rename = "singleContext")]
    SingleContext,

    #[serde(rename = "ignoreReuse")]
    IgnoreReuse,

    #[serde(rename = "httpsApp")]
    HttpsApp,

    #[serde(rename = "preserveJobOutputs")]
    PreserveJobOutputs,

    #[serde(rename = "detailedJobMetrics")]
    DetailedJobMetrics,

    #[serde(rename = "clusterSpec")]
    ClusterSpec,

    #[serde(rename = "clusterID")]
    ClusterID,

    #[serde(rename = "costLimit")]
    CostLimit,

    #[serde(rename = "selectedTreeTurnaroundTimeThreshold")]
    SelectedTreeTurnaroundTimeThreshold,

    #[serde(rename = "selectedTreeTurnaroundTimeThresholdFrom")]
    SelectedTreeTurnaroundTimeThresholdFrom,

    #[serde(rename = "treeTurnaroundTime")]
    TreeTurnaroundTime,

    #[serde(rename = "debugOn")]
    DebugOn,

    #[serde(rename = "isFree")]
    IsFree,

    #[serde(rename = "totalPrice")]
    TotalPrice,

    #[serde(rename = "priceComputedAt")]
    PriceComputedAt,

    #[serde(rename = "totalEgress")]
    TotalEgress,

    #[serde(rename = "egressComputedAt")]
    EgressComputedAt,

    #[serde(rename = "allowSSH")]
    AllowSSH,

    #[serde(rename = "sshHostKey")]
    SshHostKey,

    #[serde(rename = "host")]
    Host,

    #[serde(rename = "sshPort")]
    SshPort,

    #[serde(rename = "clusterSlaves")]
    ClusterSlaves,

    #[serde(rename = "headJobOnDemand")]
    HeadJobOnDemand,

    #[serde(rename = "internetUsageIPs")]
    InternetUsageIPs,

    #[serde(rename = "subtotalEgressInfo")]
    SubtotalEgressInfo,

    #[serde(rename = "applet")]
    Applet,

    #[serde(rename = "app")]
    App,

    #[serde(rename = "resources")]
    Resources,

    #[serde(rename = "projectCache")]
    ProjectCache,

    #[serde(rename = "outputReusedFrom")]
    OutputReusedFrom,

    #[serde(rename = "workerReuseDeadlineRunTime")]
    WorkerReuseDeadlineRunTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "try")]
    try_number: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<Currency>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "executableName")]
    executable_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "tryCreated")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    try_created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "startedRunning")]
    #[serde(default)]
    started_running: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(rename = "stoppedRunning")]
    #[serde(default)]
    stopped_running: Option<DateTime<Utc>>,

    #[serde(rename = "egressReport")]
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_report: Option<HashMap<String, u64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "billTo")]
    bill_to: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rootExecution")]
    root_execution: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "parentJob")]
    parent_job: Option<String>,

    #[serde(rename = "parentJobTry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_job_try: Option<u64>,

    #[serde(rename = "originJob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_job: Option<String>,

    #[serde(rename = "detachedFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    detached_from: Option<String>,

    #[serde(rename = "detachedFromTry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    detached_from_try: Option<u64>,

    #[serde(rename = "parentAnalysis")]
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(rename = "stateTransitions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    state_transitions: Option<Vec<JobStateTransition>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<String>,

    #[serde(rename = "launchedBy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    launched_by: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,

    #[serde(rename = "finalPriority")]
    #[serde(skip_serializing_if = "Option::is_none")]
    final_priority: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,

    #[serde(rename = "systemRequirements")]
    #[serde(skip_serializing_if = "Option::is_none")]
    system_requirements: Option<HashMap<String, AppSystemRequirement>>,

    #[serde(rename = "executionPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    //execution_policy: Option<HashMap<String, KitchenSink>>,
    execution_policy: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,

    #[serde(rename = "instanceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_type: Option<String>,

    #[serde(rename = "networkAccess")]
    #[serde(skip_serializing_if = "Option::is_none")]
    network_access: Option<Vec<String>>,

    #[serde(rename = "delayWorkspaceDestruction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_workspace_destruction: Option<bool>,

    #[serde(rename = "dependsOn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<Vec<String>>,

    #[serde(rename = "failureReason")]
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,

    #[serde(rename = "failureMessage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_message: Option<String>,

    #[serde(rename = "failureFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_from: Option<JobFailureFrom>,

    #[serde(rename = "failureReports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reports: Option<Vec<JobFailureReport>>,

    #[serde(rename = "failureCounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    //failure_counts: Option<HashMap<String, KitchenSinkValue>>,
    failure_counts: Option<KitchenSink>,

    #[serde(rename = "runInput")]
    #[serde(skip_serializing_if = "Option::is_none")]
    //run_input: Option<HashMap<String, FileInputValue>>,
    run_input: Option<HashMap<String, KitchenSink>>,

    #[serde(rename = "originalInput")]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_input: Option<KitchenSink>,

    #[serde(skip_serializing_if = "Option::is_none")]
    //input: Option<HashMap<String, FileInputValue>>,
    input: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<HashMap<String, KitchenSink>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(rename = "singleContext")]
    #[serde(skip_serializing_if = "Option::is_none")]
    single_context: Option<bool>,

    #[serde(rename = "ignoreReuse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_reuse: Option<bool>,

    #[serde(rename = "httpsApp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    https_app: Option<AppHttpsApp>,

    #[serde(rename = "preserveJobOutputs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    preserve_job_outputs: Option<String>,

    #[serde(rename = "detailedJobMetrics")]
    #[serde(skip_serializing_if = "Option::is_none")]
    detailed_job_metrics: Option<bool>,

    // TODO: this will need work
    #[serde(rename = "clusterSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_spec: Option<String>,

    #[serde(rename = "clusterID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_id: Option<String>,

    #[serde(rename = "costLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_limit: Option<f64>,

    #[serde(rename = "selectedTreeTurnaroundTimeThreshold")]
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_tree_turnaround_time_threshold: Option<u64>,

    #[serde(rename = "selectedTreeTurnaroundTimeThresholdFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_tree_turnaround_time_threshold_from: Option<String>,

    #[serde(rename = "treeTurnaroundTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tree_turnaround_time: Option<u64>,

    #[serde(rename = "debugOn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    debug_on: Option<Vec<String>>,

    #[serde(rename = "isFree")]
    #[serde(skip_serializing_if = "Option::is_none")]
    is_free: Option<bool>,

    #[serde(rename = "totalPrice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    total_price: Option<f64>,

    #[serde(rename = "priceComputedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "ts_milliseconds_option")]
    price_computed_at: Option<DateTime<Utc>>,

    #[serde(rename = "totalEgress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    total_egress: Option<HashMap<String, u64>>,

    #[serde(rename = "egressComputedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "ts_milliseconds_option")]
    egress_computed_at: Option<DateTime<Utc>>,

    #[serde(rename = "allowSSH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_ssh: Option<Vec<String>>,

    #[serde(rename = "sshHostKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_host_key: Option<String>,

    #[serde(rename = "host")]
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,

    #[serde(rename = "sshPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_port: Option<String>,

    #[serde(rename = "clusterSlaves")]
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_slaves: Option<Vec<JobClusterSlave>>,

    #[serde(rename = "headJobOnDemand")]
    #[serde(skip_serializing_if = "Option::is_none")]
    head_job_on_demand: Option<bool>,

    #[serde(rename = "internetUsageIPs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    internet_usage_ips: Option<Vec<String>>,

    #[serde(rename = "subtotalPriceInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    subtotal_price_info: Option<JobSubtotalPriceInfo>,

    #[serde(rename = "subtotalEgressInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    subtotal_egress_info: Option<JobSubtotalEgressInfo>,

    // Only if run by an applet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applet: Option<String>,

    // Only if run by an app
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<String>,

    #[serde(rename = "projectCache")]
    #[serde(skip_serializing_if = "Option::is_none")]
    project_cache: Option<String>,

    #[serde(rename = "outputReusedFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    output_reused_from: Option<String>,

    #[serde(rename = "workerReuseDeadlineRunTime")]
    worker_reuse_deadline_run_time: Option<KitchenSink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobStateTransition {
    #[serde(rename = "newState")]
    new_state: String,

    #[serde(rename = "setAt")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    set_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobFailureFrom {
    id: String,

    #[serde(rename = "try")]
    try_number: u64,

    name: String,

    executable: String,

    #[serde(rename = "executableName")]
    executable_name: String,

    function: String,

    #[serde(rename = "failureReason")]
    failure_reason: String,

    #[serde(rename = "failureMessage")]
    failure_message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobFailureReport {
    to: String,

    by: String,

    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobClusterSlave {
    host: String,

    #[serde(rename = "sshPort")]
    ssh_port: String,

    #[serde(rename = "internalIp")]
    internal_ip: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobSubtotalPriceInfo {
    #[serde(rename = "subtotalPrice")]
    subtotal_price: f64,

    #[serde(rename = "priceComputedAt")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    price_computed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobSubtotalEgressInfo {
    #[serde(rename = "subtotalRegionLocalEgress")]
    subtotal_region_local_egress: u64,

    #[serde(rename = "subtotalInternetEgress")]
    subtotal_internet_egress: u64,

    #[serde(rename = "subtotalInterRegionEgress")]
    subtotal_inter_region_egress: u64,

    #[serde(rename = "egressComputedAt")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    egress_computed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordDescribeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    fields: Option<HashMap<RecordDescribeField, bool>>,

    properties: bool,

    details: bool,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumIter)]
pub enum RecordDescribeField {
    #[serde(rename = "id")]
    Id,

    #[serde(rename = "project")]
    Project,

    #[serde(rename = "class")]
    Class,

    #[serde(rename = "size")]
    Size,

    #[serde(rename = "types")]
    Types,

    #[serde(rename = "created")]
    Created,

    #[serde(rename = "state")]
    State,

    #[serde(rename = "hidden")]
    Hidden,

    #[serde(rename = "links")]
    Links,

    #[serde(rename = "name")]
    Name,

    #[serde(rename = "folder")]
    Folder,

    #[serde(rename = "sponsored")]
    Sponsored,

    #[serde(rename = "tags")]
    Tags,

    #[serde(rename = "modified")]
    Modified,

    #[serde(rename = "createdBy")]
    CreatedBy,

    #[serde(rename = "properties")]
    Properties,

    #[serde(rename = "details")]
    Details,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordDescribeResult {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    created: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    modified: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sponsored: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdBy")]
    created_by: Option<CreatedBy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sponsoredUntil")]
    #[serde(with = "ts_milliseconds_option")]
    #[serde(default)]
    sponsored_until: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HashMap<String, KitchenSink>>,
}

#[derive(Debug, PartialEq)]
pub struct DxPath {
    path: String,

    project_id: String,
}

impl fmt::Display for DxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.project_id, self.path)
    }
}

#[derive(Debug, PartialEq)]
pub enum FileOrPath {
    File { file_id: String, project_id: String },

    Path { path: String, project_id: String },
}

// --------------------------------------------------
pub fn build(args: BuildArgs) -> Result<()> {
    let src_dir = Path::new(&args.src);
    if !src_dir.is_dir() {
        bail!(r#""{}" is not a directory"#, src_dir.display());
    }

    let app_json = src_dir.join("dxapp.json");
    if !app_json.is_file() {
        bail!(r#"Cannot find "{}""#, app_json.display())
    }

    let dx_env = get_dx_env()?;
    let app: DxApp = json_parser::parse(&app_json.display().to_string())?;
    let re = Regex::new("^(?:(project-[A-Za-z0-9]{24}):)?(.+)$").unwrap();
    let destination = &args
        .destination
        .clone()
        .unwrap_or(dx_env.cli_wd.to_string());
    let current_project_id = &dx_env.project_context_id.clone();
    let (project_id, mut folder) =
        if let Some(caps) = re.captures(destination) {
            let project_id = match caps.get(1) {
                Some(val) => val.as_str(),
                _ => current_project_id,
            };
            let dirname = caps.get(2).unwrap().as_str();
            (project_id, dirname.to_string())
        } else {
            (current_project_id.as_str(), destination.clone())
        };

    if !folder.starts_with('/') {
        folder = format!("/{folder}")
    }

    println!(
        r#"Building from "{}" to "{project_id}:{folder}""#,
        src_dir.display()
    );

    // Find if there is an existing applet
    let mut options = FindDataOptions {
        class: Some(ObjectType::Applet),
        state: None,
        name: Some(FindName::Regexp(app.name.unwrap_or("".to_string()))),
        visibility: None,
        id: vec![],
        object_type: None,
        tags: vec![],
        region: vec![],
        properties: None,
        link: None,
        scope: Some(FindDataScope {
            project: Some(dx_env.project_context_id.clone()),
            folder: Some("/".to_string()),
            recurse: Some(true),
        }),
        sort_by: None,
        level: None,
        modified: None,
        created: None,
        describe: Some(FindDescribe::Boolean(true)),
        starting: None,
        limit: None,
        archival_state: None,
    };
    let applets = api::find_data(&dx_env, &mut options)?;

    if !applets.is_empty() && !args.force {
        let applet_id = applets
            .first()
            .and_then(|a| a.describe.clone().map(|d| d.id))
            .unwrap_or("NA".to_string());

        bail!(
            "Applet ({}) already exists. Use -f|--force to overwrite",
            applet_id
        );
    }

    // Tar "resources" directory
    let resources_dir = src_dir.join("resources");
    if resources_dir.is_dir()
        && !resources_dir.read_dir()?.collect::<Vec<_>>().is_empty()
    {
        println!(r#"Adding "{}""#, resources_dir.display());
        //let outfile = NamedTempFile::new()?;
        //let outpath = &outfile.path().to_str().unwrap();
        let outpath = Path::new("/Users/kyclark@dnanexus.com/archive.tar.gz");
        let outfile = File::create(outpath)?;
        println!(r#"Writing "{}""#, outpath.display());
        let enc = GzEncoder::new(outfile, Compression::default());
        let mut tarball = Builder::new(enc);
        tarball.append_dir_all(".", resources_dir)?;
        let res = tarball.into_inner()?;
        dbg!(&res);
        // TODO: Something is not closing on the tarball right.

        let destination = ProjectPath {
            project_id: dx_env.project_context_id.to_string(),
            path: "/".to_string().into(),
        };
        let file_id = upload_local_file(
            &dx_env,
            &outpath.display().to_string(),
            &destination,
        )?;
        println!("{} => {file_id}", outpath.display());

        //let folder = "/".to_string();
        //let basename =
        //    outpath.file_name().unwrap().to_string_lossy().to_string();
        //let new_opts = FileNewOptions {
        //    project: project_id.to_string(),
        //    name: Some(basename),
        //    tags: vec![],
        //    types: vec![],
        //    hidden: Some(false),
        //    details: None,
        //    folder: Some(folder),
        //    parents: Some(true),
        //    media: None,
        //    nonce: Some(TextNonce::new().into_string()),
        //};
        //let new_file = api::file_new(&dx_env, &new_opts)?;
        //dbg!(&new_file);

        //let mut fh = BufReader::new(File::open(&outpath)?);
        //for index in 1.. {
        //    println!("Reading file part {index}");
        //    let mut buffer = vec![0; MD5_READ_CHUNK_SIZE];
        //    let bytes_read = fh.read(&mut buffer)?;
        //    if bytes_read == 0 {
        //        break;
        //    }
        //    let md5_sum =
        //        format!("{:x}", md5::compute(&buffer[..bytes_read]));
        //    println!("md5_sum '{md5_sum}'");

        //    let upload_opts = FileUploadOptions {
        //        size: bytes_read,
        //        md5: md5_sum,
        //        index,
        //    };

        //    let upload =
        //        api::file_upload(&dx_env, &new_file.id, &upload_opts)?;

        //    dbg!(&upload);
        //    api::file_upload_part(upload, buffer)?;
        //}

        //println!("Closing file");
        //// TODO: must send bogus JSON for this to work?
        //let close_opts = FileCloseOptions {
        //    id: new_file.id.clone(),
        //};
        //let close = api::file_close(&dx_env, &new_file.id, &close_opts)?;
        //dbg!(&close);
    } else {
        println!("Nothing in resources")
    }

    Ok(())
}

// --------------------------------------------------
pub fn cd(args: CdArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let folder = &args.dirname.clone().map_or("/".to_string(), |name| {
        if name.starts_with('/') {
            name.clone()
        } else {
            Path::new(&dx_env.cli_wd).join(name).display().to_string()
        }
    });

    let options = ListFolderOptions {
        folder,
        only: Some(ListFolderOptionOnlyValue::All),
        describe: false,
        has_subfolder_flags: true,
        include_hidden: false,
    };

    let _ = api::ls(&dx_env, &dx_env.project_context_id, options)?;
    let new_env = DxEnvironment {
        cli_wd: folder.clone(),
        ..dx_env
    };

    dxenv::save_dx_env(&new_env)?;
    println!(
        "Changed working directory to \"{}:{}\"",
        &new_env.project_context_id, &new_env.cli_wd
    );

    Ok(())
}

// --------------------------------------------------
pub fn find_apps(args: FindAppsArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let mut options = FindAppsOptions {
        name: None,
        category: None,
        all_versions: None,
        published: None,
        bill_to: vec![],
        created_by: None,
        developer: None,
        authorized_user: None,
        starting: None,
        limit: None,
        describe: Some(FindAppsDescribe {
            fields: HashMap::from([(AppDescribeField::Name, true)]),
        }),
    };

    if let Some(name) = &args.name {
        options.name = Some(FindName::Regexp(name.clone()));
    } else {
        options.name = Some(FindName::Glob("*".to_string()))
    }

    let apps = api::find_apps(&dx_env, &mut options)?;
    debug!("{:#?}", &apps);
    Ok(())
}

// --------------------------------------------------
pub fn find_data(args: FindDataArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let mut folder = args.path.clone().unwrap_or("".to_string());
    if Path::new(&folder).is_relative() {
        folder = Path::new(&dx_env.cli_wd).join(folder).display().to_string();
    }

    let mut options = FindDataOptions {
        class: None,
        state: None,
        name: None,
        visibility: None,
        id: vec![],
        object_type: None,
        tags: vec![],
        region: vec![],
        properties: None,
        link: None,
        scope: Some(FindDataScope {
            // TODO: What if project_id is explicit in search path?
            project: Some(dx_env.project_context_id.clone()),
            folder: Some(folder),
            recurse: Some(true),
        }),
        sort_by: None,
        level: None,
        modified: None,
        created: None,
        describe: Some(FindDescribe::Boolean(true)),
        starting: None,
        limit: None,
        archival_state: None,
    };

    if let Some(val) = &args.class {
        options.class = Some(ObjectType::from_str(val)?);
    }

    if let Some(val) = &args.name {
        options.name = Some(FindName::Regexp(val.clone()));
    } else {
        options.name = Some(FindName::Glob("*".to_string()))
    }

    debug!("{:#?}", &options);
    let data = api::find_data(&dx_env, &mut options)?;
    debug!("{:#?}", &data);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        let fmt = "{:<} {:<} {:>} {:<}";
        let mut table = Table::new(fmt);

        for row in data {
            if let Some(desc) = row.describe {
                let modified = desc.modified.map_or("NA".to_string(), |ts| {
                    ts.format("%Y-%m-%d %H:%M:%S").to_string()
                });
                let folder = desc.folder.unwrap_or("".to_string());
                let folder = Path::new(&folder);
                let name = format!(
                    "{} ({})",
                    folder
                        .join(desc.name.unwrap_or("".to_string()))
                        .display(),
                    desc.id
                );

                table.add_row(
                    Row::new()
                        .with_cell(
                            desc.state
                                .map_or("NA".to_string(), |s| s.to_string()),
                        )
                        .with_cell(modified)
                        .with_cell(desc.size.map_or("".to_string(), |s| {
                            Size::from_bytes(s).to_string()
                        }))
                        .with_cell(name),
                );
            }
        }

        println!("{table}");
    }
    Ok(())
}

// --------------------------------------------------
pub fn format(args: FormatArgs) -> Result<()> {
    let basename = Path::new(&args.filename)
        .file_name()
        .expect("filename")
        .to_string_lossy();

    if basename == "dxapp.json" {
        let app: DxApp = json_parser::parse(&args.filename)?;
        json_parser::write_file(&app, &args.output)?;
    } else if basename == "dxasset.json" {
        let asset: DxAsset = json_parser::parse(&args.filename)?;
        json_parser::write_file(&asset, &args.output)?;
    } else {
        println!("Input file must be dxapp.json or dxasset.json")
    }
    Ok(())
}

// --------------------------------------------------
pub fn lint(args: LintArgs) -> Result<()> {
    let basename = Path::new(&args.filename)
        .file_name()
        .expect("filename")
        .to_string_lossy();

    if basename == "dxapp.json" {
        let app: DxApp = json_parser::parse(&args.filename)?;
        let suggestions = json_parser::lint_app(&app);
        if suggestions.is_empty() {
            println!("No suggestions");
        } else {
            println!("{}", suggestions.join("\n"));
        }
    } else if basename == "dxasset.json" {
        let asset: DxAsset = json_parser::parse(&args.filename)?;
        let suggestions = json_parser::lint_asset(&asset);
        if suggestions.is_empty() {
            println!("No suggestions");
        } else {
            println!("{}", suggestions.join("\n"));
        }
    } else {
        println!("Input file must be dxapp.json or dxasset.json")
    }
    Ok(())
}

// --------------------------------------------------
pub fn logout() -> Result<()> {
    let dx_env = get_dx_env()?;
    api::logout(&dx_env)?;
    let new_env = DxEnvironment {
        auth_token: "".to_string(),
        auth_token_type: "".to_string(),
        ..dx_env
    };
    save_dx_env(&new_env)?;
    Ok(())
}

// --------------------------------------------------
pub fn ls(args: LsArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let paths = if args.paths.is_empty() {
        vec![dx_env.cli_wd.to_string()]
    } else {
        args.paths
    };

    for path in paths {
        match resolve_path(&dx_env, &path) {
            Err(e) => eprintln!("{e}"),
            Ok(dx_path) => {
                let files = find_files_by_path(
                    &dx_env,
                    &dx_path.path,
                    &dx_path.project_id,
                )?;

                if !files.is_empty() {
                    if args.long {
                        //         1    2    3    4    5
                        let fmt = "{:<} {:<} {:>} {:<} {:<}";
                        let mut table = Table::new(fmt);
                        table.add_row(
                            Row::new()
                                .with_cell("State") // 1
                                .with_cell("Modified") // 2
                                .with_cell("Size") // 3
                                .with_cell("Name") // 4
                                .with_cell("ID"), // 5
                        );

                        for file in files {
                            if let Some(desc) = file.describe {
                                let modified = desc.modified.map_or(
                                    "NA".to_string(),
                                    |ts| {
                                        ts.format("%Y-%m-%d %H:%M:%S")
                                            .to_string()
                                    },
                                );

                                table.add_row(
                                    Row::new()
                                        .with_cell(
                                            desc.archival_state.map_or(
                                                "".to_string(),
                                                |s| s.to_string(),
                                            ),
                                        )
                                        .with_cell(modified)
                                        .with_cell(desc.size.map_or(
                                            "NA".to_string(),
                                            |s| {
                                                if args.human {
                                                    Size::from_bytes(s)
                                                        .to_string()
                                                } else {
                                                    s.to_string()
                                                }
                                            },
                                        ))
                                        .with_cell(
                                            desc.name
                                                .unwrap_or("".to_string()),
                                        )
                                        .with_cell(desc.id),
                                );
                            }
                        }
                        println!("{}", table);
                    } else {
                        for file in files {
                            if let Some(desc) = file.describe {
                                println!(
                                    "{} : {}",
                                    desc.name.unwrap_or("".to_string()),
                                    desc.id
                                );
                            }
                        }
                    }
                }

                if dx_path.path.starts_with("/") {
                    let desc_opts = ProjectDescribeOptions {
                        fields: Some(HashMap::from([(
                            ProjectDescribeField::Name,
                            true,
                        )])),
                    };

                    let project = api::describe_project(
                        &dx_env,
                        &dx_path.project_id,
                        &desc_opts,
                    )?;

                    println!(
                        "{}",
                        Cyan.paint(format!(
                            "{} ({}):{}",
                            project.name.unwrap_or("".to_string()),
                            dx_path.project_id,
                            dx_path.path
                        ))
                    );

                    let options = ListFolderOptions {
                        folder: &dx_path.path,
                        only: Some(ListFolderOptionOnlyValue::All),
                        describe: true,
                        has_subfolder_flags: true,
                        include_hidden: args.all,
                    };

                    let results: ListFolderResult =
                        api::ls(&dx_env, &dx_path.project_id, options)?;

                    debug!("{:#?}", &results);

                    if args.long {
                        if let Some(folders) = results.folders {
                            for (name, _has_subdir) in folders {
                                println!("{}", Cyan.paint(name));
                            }
                        }

                        if let Some(objects) = results.objects {
                            //         1    2    3    4    5
                            let fmt = "{:<} {:<} {:>} {:<} {:<}";
                            let mut table = Table::new(fmt);
                            table.add_row(
                                Row::new()
                                    .with_cell("State") // 1
                                    .with_cell("Modified") // 2
                                    .with_cell("Size") // 3
                                    .with_cell("Name") // 4
                                    .with_cell("ID"), // 5
                            );

                            for obj in objects {
                                if let Some(desc) = obj.describe {
                                    let modified = desc.modified.map_or(
                                        "NA".to_string(),
                                        |ts| {
                                            ts.format("%Y-%m-%d %H:%M:%S")
                                                .to_string()
                                        },
                                    );

                                    table.add_row(
                                        Row::new()
                                            .with_cell(desc.state)
                                            .with_cell(modified)
                                            .with_cell(desc.size.map_or(
                                                "NA".to_string(),
                                                |s| {
                                                    if args.human {
                                                        Size::from_bytes(s)
                                                            .to_string()
                                                    } else {
                                                        s.to_string()
                                                    }
                                                },
                                            ))
                                            .with_cell(desc.name)
                                            .with_cell(desc.id),
                                    );
                                }
                            }

                            println!("{}:", Cyan.paint(dx_path.path));
                            println!("{}", table);
                        }
                    } else {
                        if let Some(folders) = results.folders {
                            for (name, _has_subdir) in folders {
                                println!("{}", Cyan.paint(name));
                            }
                        }

                        if let Some(objects) = results.objects {
                            for obj in objects {
                                if args.brief {
                                    println!("  {}", obj.id);
                                } else {
                                    if let Some(desc) = obj.describe {
                                        println!("  {}", desc.name);
                                    }
                                }
                            }
                        } else {
                            println!("Empty directory");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// --------------------------------------------------
fn find_project(
    dx_env: &DxEnvironment,
    project: &str,
) -> Result<Vec<FindProjectsResult>> {
    let fields = HashMap::from([(ProjectDescribeField::Name, true)]);
    let mut options = FindProjectsOptions {
        name: None,
        id: vec![],
        level: None,
        starting: None,
        describe: Some(FindProjectsDescribe { fields }),
    };

    let re = Regex::new("^project-[A-Za-z0-9]{24}$").unwrap();
    if re.is_match(project) {
        options.id = vec![project.to_string()];
    } else {
        options.name = Some(FindName::Regexp(project.to_string()));
    }

    api::find_projects(&dx_env, options)
}

// --------------------------------------------------
fn find_files_by_path(
    dx_env: &DxEnvironment,
    path: &str,
    project_id: &str,
) -> Result<Vec<FindDataResult>> {
    let file_re = Regex::new("^file-[A-Za-z0-9]{24}$").unwrap();
    let (folder, name) = if file_re.is_match(&path) {
        ("/".to_string(), path.to_string())
    } else {
        let p = Path::new(&path);
        let parent = p.parent().map_or("/".to_string(), |dirname| {
            dirname.to_string_lossy().to_string()
        });
        let basename = p.file_name().map_or(path.to_string(), |name| {
            name.to_string_lossy().to_string()
        });
        (parent, basename)
    };

    let mut options = FindDataOptions {
        class: Some(ObjectType::File),
        state: None,
        name: Some(FindName::Glob(name)),
        visibility: None,
        id: vec![],
        object_type: None,
        tags: vec![],
        region: vec![],
        properties: None,
        link: None,
        scope: Some(FindDataScope {
            project: Some(project_id.to_string()),
            folder: Some(folder),
            recurse: Some(false),
        }),
        sort_by: None,
        level: None,
        modified: None,
        created: None,
        describe: Some(FindDescribe::Boolean(true)),
        starting: None,
        limit: None,
        archival_state: None,
    };

    api::find_data(dx_env, &mut options)
}

// --------------------------------------------------
pub fn login(args: LoginArgs) -> Result<()> {
    let dx_user: String = if let Ok(user) = env::var("DX_USERNAME") {
        user
    } else if let Some(user) = dxenv::get_dx_username() {
        user
    } else {
        "".to_string()
    };

    let username = Text::new("Username:")
        .with_initial_value(&dx_user)
        .prompt()
        .unwrap();

    let password = Password::new("Password:")
        .without_confirmation()
        .prompt()
        .unwrap();

    let auth_token = api::login(&username, &password, args.token.clone())?;

    // First time login there is no dx_env.json
    let dx_env = match get_dx_env() {
        Ok(cur_env) => DxEnvironment {
            auth_token: auth_token.access_token.to_string(),
            auth_token_type: "Bearer".to_string(),
            ..cur_env
        },
        _ => DxEnvironment {
            apiserver_protocol: "https".to_string(),
            username: username.clone(),
            cli_wd: "/".to_string(),
            apiserver_host: "api.dnanexus.com".to_string(),
            project_context_id: "".to_string(),
            project_context_name: "".to_string(),
            apiserver_port: 443,
            auth_token: auth_token.access_token.to_string(),
            auth_token_type: "Bearer".to_string(),
        },
    };

    save_dx_env(&dx_env)?;
    select_project(SelectArgs {
        project: None,
        level: None,
    })?;
    Ok(())
}

// --------------------------------------------------
pub fn mkdir(args: MkdirArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let project_id = dx_env.project_context_id.clone();

    debug!("{:?}", &args);

    for folder in &args.paths {
        let folder = if !&folder.starts_with("/") {
            format!("/{folder}")
        } else {
            folder.clone()
        };

        let options = MakeFolderOptions {
            folder: folder.clone(),
            parents: args.parents,
        };

        match api::mkdir(&dx_env, &project_id, options) {
            Ok(_) => println!(r#"Created folder "{folder}""#),
            Err(e) => eprintln!("{e}"),
        }
    }

    Ok(())
}

// --------------------------------------------------
pub fn print_env(_args: EnvArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    println!("API server protocol   {}", dx_env.apiserver_protocol);
    println!("API server host       {}", dx_env.apiserver_host);
    println!("API server port       {}", dx_env.apiserver_port);
    println!("Current workspace     {}", dx_env.project_context_name);
    println!("Current workspace     {}", dx_env.project_context_id);
    println!("Current folder        {}", dx_env.cli_wd);
    println!("Current user          {}", dx_env.username);
    Ok(())
}

// --------------------------------------------------
pub fn select_project(args: SelectArgs) -> Result<()> {
    let level = &args.level.clone().or(Some(AccessLevel::Contribute));
    let level_display = format!("{}", &level.as_ref().unwrap());
    let dx_env = get_dx_env()?;
    let fields = HashMap::from([(ProjectDescribeField::Name, true)]);

    let mut options = FindProjectsOptions {
        name: None,
        id: vec![],
        level: level.clone(),
        starting: None,
        describe: Some(FindProjectsDescribe { fields }),
    };

    let re = Regex::new("^project-[A-Za-z0-9]{24}$").unwrap();
    if let Some(project) = &args.project {
        if re.is_match(project) {
            options.id = vec![project.clone()];
        } else {
            options.name = Some(FindName::Regexp(project.clone()));
        }
    } else {
        options.name = Some(FindName::Glob("*".to_string()))
    }

    let projects = api::find_projects(&dx_env, options)?;
    let num_projects = projects.len();

    let mut lookup: HashMap<String, FindProjectsResult> = HashMap::new();
    for project in projects {
        let display = format!(
            "{} ({}) [{}]",
            project.describe.get("name").unwrap_or(&"NA".to_string()),
            project.id,
            project.level
        );
        lookup.insert(display, project);
    }

    let mut choices: Vec<&String> = lookup.keys().collect();
    choices.sort();

    let selected = if num_projects == 1 {
        Ok(choices.pop().unwrap())
    } else {
        let prompt = format!(
            "{} available project{} ({} or higher)",
            num_projects,
            if num_projects == 1 { "" } else { "s" },
            level_display,
        );

        choices.sort();
        Select::new(&prompt, choices).prompt()
    };

    match selected {
        Ok(key) => {
            let project = lookup.get(key).unwrap();
            let name = project.describe.get("name").unwrap().clone();
            let dx_env = get_dx_env()?;
            let new_env = DxEnvironment {
                project_context_id: project.id.clone(),
                project_context_name: name.clone(),
                ..dx_env
            };
            save_dx_env(&new_env)?;
            println!("Selected project \"{}\"", project.id);
            Ok(())
        }
        _ => bail!("Failed to select project"),
    }
}

// --------------------------------------------------
pub fn tree(args: TreeArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let path = args.path.clone().unwrap_or(dx_env.cli_wd.clone());
    let dx_path = resolve_path(&dx_env, &path)?;
    let mut root = Tree::new(dx_path.path.clone());
    let tree = mk_tree(
        &mut root,
        &dx_env,
        &dx_path.project_id,
        &dx_path.path,
        &args,
    )?;

    let desc_opts = ProjectDescribeOptions {
        fields: Some(HashMap::from([(ProjectDescribeField::Name, true)])),
    };

    let project =
        api::describe_project(&dx_env, &dx_path.project_id, &desc_opts)?;

    println!(
        "{} {}:{}",
        project.name.unwrap_or("".to_string()),
        dx_path.project_id,
        dx_path.path
    );
    println!("{}", tree);

    Ok(())
}

// --------------------------------------------------
fn mk_tree(
    root: &mut Tree<String>,
    dx_env: &DxEnvironment,
    project_id: &str,
    folder: &str,
    args: &TreeArgs,
) -> Result<Tree<String>> {
    let ls_opts = ListFolderOptions {
        folder,
        only: Some(ListFolderOptionOnlyValue::All),
        describe: true,
        has_subfolder_flags: true,
        include_hidden: true,
    };
    let ls: ListFolderResult = api::ls(dx_env, project_id, ls_opts)?;

    if let Some(folders) = &ls.folders {
        for (subdir, _) in folders {
            let path = Path::new(subdir);
            let dirname = path
                .file_name()
                .expect("filename")
                .to_string_lossy()
                .to_string();
            let mut new_root = Tree::new(dirname.clone());
            root.push(mk_tree(
                &mut new_root,
                dx_env,
                project_id,
                subdir,
                args,
            )?);
        }
    }

    if let Some(objects) = &ls.objects {
        for object in objects {
            if let Some(desc) = &object.describe {
                if args.long {
                    let fmt = "{:<} {:<} {:>} {:<} ({:<})";
                    let mut table = Table::new(fmt);
                    let modified =
                        desc.modified.map_or("NA".to_string(), |ts| {
                            ts.format("%Y-%m-%d %H:%M:%S").to_string()
                        });

                    table.add_row(
                        Row::new()
                            .with_cell(desc.state.to_string())
                            .with_cell(modified)
                            .with_cell(desc.size.map_or(
                                "NA".to_string(),
                                |s| {
                                    if args.human {
                                        Size::from_bytes(s).to_string()
                                    } else {
                                        s.to_string()
                                    }
                                },
                            ))
                            .with_cell(desc.name.clone())
                            .with_cell(desc.id.clone()),
                    );
                    root.push(format!("{}", table));
                } else {
                    root.push(desc.name.clone());
                }
            }
        }
    }

    Ok(root.clone())
}

// --------------------------------------------------
pub fn pwd() -> Result<()> {
    let dx_env = get_dx_env()?;

    println!(
        "{} {}:{}",
        &dx_env.project_context_name,
        &dx_env.project_context_id,
        &dx_env.cli_wd
    );

    Ok(())
}

// --------------------------------------------------
pub fn describe(args: DescribeArgs) -> Result<()> {
    let dx_env = get_dx_env()?;

    for id in &args.ids {
        match get_describe_object_type(&id) {
            Some(DescribeObject::Analysis { analysis_id }) => {
                describe_analysis(&dx_env, analysis_id, &args.json)?
            }
            Some(DescribeObject::App { app_id }) => {
                describe_app(&dx_env, app_id, &args.json)?
            }
            Some(DescribeObject::Applet {
                project_id,
                applet_id,
            }) => {
                describe_applet(&dx_env, project_id, applet_id, &args.json)?
            }
            Some(DescribeObject::Container { container_id }) => {
                describe_container(&dx_env, container_id, &args.json)?
            }
            Some(DescribeObject::File {
                project_id,
                file_id,
            }) => describe_file(&dx_env, project_id, file_id, &args.json)?,
            Some(DescribeObject::Job { job_id }) => {
                describe_job(&dx_env, job_id, args.try_number, &args.json)?
            }
            Some(DescribeObject::Project { project_id }) => {
                describe_project(&dx_env, project_id, &args.json)?
            }
            Some(DescribeObject::Record {
                project_id,
                record_id,
            }) => {
                describe_record(&dx_env, project_id, record_id, &args.json)?
            }
            Some(DescribeObject::Database {
                project_id,
                database_id,
            }) => describe_database(
                &dx_env,
                project_id,
                database_id,
                &args.json,
            )?,
            _ => println!("TODO: handle \"{}\"", &id),
        }
    }

    //} else if Some((project_id, file_id)) =
    //    extract_project_object_ids(&file_re, &id, &current_project_id)
    //{
    //} else {
    //}
    //else if user_re.is_match(&id) {
    //} else {
    //    None
    //};

    Ok(())
}

// --------------------------------------------------
pub fn download(args: DownloadArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    let outdir = &args.dir.clone().unwrap_or(".".to_string());
    let outdir = PathBuf::from(&outdir);
    if !outdir.is_dir() {
        fs::create_dir_all(&outdir)?;
    }

    for path in &args.paths {
        match resolve_path(&dx_env, path) {
            Err(e) => eprintln!("{e}"),
            Ok(dx_path) => {
                // Handle folders
                let parent = Path::new(&dx_path.path)
                    .parent()
                    .map_or(dx_env.cli_wd.to_string(), |val| {
                        val.to_string_lossy().to_string()
                    });

                let options = ListFolderOptions {
                    folder: &parent,
                    only: Some(ListFolderOptionOnlyValue::Folders),
                    describe: true,
                    has_subfolder_flags: true,
                    include_hidden: args.all,
                };

                let results: ListFolderResult =
                    api::ls(&dx_env, &dx_path.project_id, options)?;

                if let Some(folders) = results.folders {
                    let matches: Vec<_> = folders
                        .iter()
                        // tuple with (dirname, has_subdir)
                        .map(|t| t.0.clone())
                        .filter(|name| name == &dx_path.path)
                        .collect();

                    if let Some(dir) = matches.first() {
                        // TODO: make a separate "download-dir" action?
                        if !args.recursive {
                            bail!("Use recursive flag to download diretory");
                        }

                        let mut find_opts = FindDataOptions {
                            class: Some(ObjectType::File),
                            state: None,
                            name: None,
                            visibility: None,
                            id: vec![],
                            object_type: None,
                            tags: vec![],
                            region: vec![],
                            properties: None,
                            link: None,
                            scope: Some(FindDataScope {
                                project: Some(dx_path.project_id.clone()),
                                folder: Some(dir.clone()),
                                recurse: Some(true),
                            }),
                            sort_by: None,
                            level: None,
                            modified: None,
                            created: None,
                            describe: Some(FindDescribe::Boolean(true)),
                            starting: None,
                            limit: None,
                            archival_state: None,
                        };

                        let outdir =
                            &args.dir.clone().unwrap_or(".".to_string());
                        let files = api::find_data(&dx_env, &mut find_opts)?;
                        for file in files {
                            if let Some(desc) = file.describe {
                                let folder =
                                    desc.folder.unwrap_or(path.clone());

                                let folder = folder
                                    .strip_prefix("/")
                                    .unwrap_or(&folder);

                                let local_dir =
                                    Path::new(&outdir).join(folder);

                                if let Err(e) = download_file(
                                    &dx_env,
                                    &file.id,
                                    &local_dir,
                                    args.clone(),
                                ) {
                                    eprintln!("{e}");
                                }
                            }
                        }
                    }
                }

                // Handle file(s)
                let files = find_files_by_path(
                    &dx_env,
                    &dx_path.path,
                    &dx_path.project_id,
                )?;

                if let Some(file_id) = select_file_from_list(&files, false) {
                    if let Err(e) = download_file(
                        &dx_env,
                        &file_id,
                        &outdir,
                        args.clone(),
                    ) {
                        eprintln!("{e}");
                    }
                }
            }
        }
    }

    Ok(())
}

// --------------------------------------------------
fn select_file_from_list(
    files: &Vec<FindDataResult>,
    allow_all: bool,
) -> Option<String> {
    if files.len() > 1 {
        let fmt = "{:<} {:<} {:>} {:<} {:<}";
        let mut table = Table::new(fmt);
        for desc in files.iter().filter_map(|f| f.describe.clone()) {
            let modified = desc.modified.map_or("NA".to_string(), |ts| {
                ts.format("%Y-%m-%d %H:%M:%S").to_string()
            });

            table.add_row(
                Row::new()
                    .with_cell(
                        desc.archival_state
                            .clone()
                            .map_or("".to_string(), |s| s.to_string()),
                    )
                    .with_cell(modified)
                    .with_cell(desc.size.map_or("NA".to_string(), |s| {
                        Size::from_bytes(s).to_string()
                    }))
                    .with_cell(desc.name.clone().unwrap_or("".to_string()))
                    .with_cell(desc.id.clone()),
            );
        }

        if allow_all {
            table.add_row(
                Row::new()
                    .with_cell("all".to_string())
                    .with_cell("".to_string())
                    .with_cell("".to_string())
                    .with_cell("".to_string())
                    .with_cell("".to_string()),
            );
        }

        let message = "Please select a file (Ctrl-C to exit):";
        let table = table.to_string();
        let choices: Vec<_> = table.lines().collect();

        Select::new(message, choices).prompt().ok().map(|chosen| {
            if chosen.trim() == "all" {
                "all".to_string()
            } else {
                let file_re = Regex::new("(file-[A-Za-z0-9]{24})$").unwrap();
                file_re
                    .captures(chosen)
                    .map(|cap| cap.get(1).unwrap().as_str().to_string())
                    .unwrap()
            }
        })
    } else {
        files.first().map(|file| file.id.clone())
    }
}

// --------------------------------------------------
pub fn download_file(
    dx_env: &DxEnvironment,
    file_id: &str,
    outdir: &PathBuf,
    args: DownloadArgs,
) -> Result<()> {
    if !outdir.is_dir() {
        fs::create_dir_all(outdir)?;
    }

    let dl_options = DownloadOptions {
        duration: None,
        filename: None,
        project: None,
        preauthenticated: None,
        sticky_ip: None,
    };

    let desc_opts = FileDescribeOptions {
        project: None,
        fields: Some(HashMap::from([(FileDescribeField::Name, true)])),
        details: true,
        properties: true,
    };

    let desc = api::describe_file(dx_env, file_id, &desc_opts)?;
    let filename = &desc.name.clone().unwrap_or(desc.id);
    let local_path = match &args.output {
        Some(val) => {
            if val == "-" {
                val.clone()
            } else {
                outdir.join(val.clone()).display().to_string()
            }
        }
        _ => outdir
            .join(desc.name.unwrap_or(file_id.to_string()))
            .display()
            .to_string(),
    };

    if local_path != "-" {
        let path = Path::new(&local_path);
        if path.exists() && !args.force {
            bail!(r#"Use force to overwrite "{local_path}""#);
        }
    }

    let download = api::download(dx_env, file_id, &dl_options)?;
    let outfile = open_outfile(&local_path)?;
    api::download_file(&download, outfile, filename, args.quiet)?;
    Ok(())
}

// --------------------------------------------------
#[test]
fn test_resolve_path() {
    let project_id1 = "project-GbxZVz8071x9yvpXgxV4gVjK".to_string();
    let project_id2 = "project-Gbxgky00Z4Y2kf4K204x8V26".to_string();

    let dx_env1 = DxEnvironment {
        apiserver_protocol: "".to_string(),
        username: "".to_string(),
        cli_wd: "/".to_string(),
        apiserver_host: "".to_string(),
        project_context_id: project_id1.clone(),
        project_context_name: "test".to_string(),
        apiserver_port: 20,
        auth_token_type: "".to_string(),
        auth_token: "".to_string(),
    };

    // Use env project_id by default
    let res = resolve_path(&dx_env1, "/");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Use env project_id by default, folder is "/"
    let res = resolve_path(&dx_env1, "");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Use env project_id by default, folder is "/"
    let res = resolve_path(&dx_env1, ":");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Handle file ID, project_id from env
    let res = resolve_path(&dx_env1, "file-Gbxj0k006jzv14J9J4Yp4vgG");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "file-Gbxj0k006jzv14J9J4Yp4vgG".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Handle project_id:file_id
    let res = resolve_path(
        &dx_env1,
        &format!("{project_id2}:file-Gbxj0k006jzv14J9J4Yp4vgG"),
    );
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "file-Gbxj0k006jzv14J9J4Yp4vgG".to_string(),
            project_id: project_id2.clone(),
        }
    );

    // Use env project_id by default, handle leading ":"
    let res = resolve_path(&dx_env1, ":/foo");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/foo".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Use explicit project id, folder
    let res = resolve_path(&dx_env1, &format!("{project_id2}:/foo"));
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/foo".to_string(),
            project_id: project_id2.clone(),
        }
    );

    // Use explicit project id, default folder is "/"
    let res = resolve_path(&dx_env1, &project_id2);
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/".to_string(),
            project_id: project_id2.clone(),
        }
    );

    // Use explicit project id, default folder is "/"
    let res = resolve_path(&dx_env1, &format!("{project_id2}:"));
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/".to_string(),
            project_id: project_id2.clone(),
        }
    );

    let dx_env2 = DxEnvironment {
        apiserver_protocol: "".to_string(),
        username: "".to_string(),
        cli_wd: "/foo/bar".to_string(),
        apiserver_host: "".to_string(),
        project_context_id: project_id2.clone(),
        project_context_name: "test".to_string(),
        apiserver_port: 20,
        auth_token_type: "".to_string(),
        auth_token: "".to_string(),
    };

    // Use env project_id/working_dir
    let res = resolve_path(&dx_env2, "");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/foo/bar".to_string(),
            project_id: project_id2.clone(),
        }
    );

    // Use env working dir and append to path
    let res = resolve_path(&dx_env2, "baz.txt");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/foo/bar/baz.txt".to_string(),
            project_id: project_id2.clone(),
        }
    );

    let res = resolve_path(&dx_env2, &format!("{project_id2}:baz.txt"));
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/foo/bar/baz.txt".to_string(),
            project_id: project_id2.clone(),
        }
    );

    let res = resolve_path(&dx_env2, &format!("{project_id1}:/baz.txt"));
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "/baz.txt".to_string(),
            project_id: project_id1.clone(),
        }
    );

    // Use env project id
    let res = resolve_path(&dx_env2, "file-Gbxj0k006jzv14J9J4Yp4vgG");
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        DxPath {
            path: "file-Gbxj0k006jzv14J9J4Yp4vgG".to_string(),
            project_id: project_id2.clone(),
        }
    );
}

// --------------------------------------------------
pub fn resolve_path(dx_env: &DxEnvironment, path: &str) -> Result<DxPath> {
    // Separate any project_id from path, use env if none

    let mut path = path.to_string();

    // Default project_id comes from env
    let mut project_id = dx_env.project_context_id.to_string();

    // The incoming path may start with project_id
    // If so, use that and remove it from the path
    let project_re =
        Regex::new("^(project-[A-Za-z0-9]{24})(:(.*))?").unwrap();

    if let Some(caps) = project_re.captures(&path) {
        project_id = caps.get(1).unwrap().as_str().to_string();
        path = caps
            .get(3)
            .map_or("".to_string(), |m| m.as_str().to_string());
    }

    // Remove leading ":"
    // This should match even the empty string, in which case
    // default path comes from env
    let path_re = Regex::new("^:?(.+)?").unwrap();
    if let Some(caps) = path_re.captures(&path) {
        path = caps
            .get(1)
            .map_or(dx_env.cli_wd.to_string(), |m| m.as_str().to_string());
    }

    // If remaining path does not look like a file ID, see if it's relative
    let file_re = Regex::new("^file-[A-Za-z0-9]{24}$").unwrap();
    if !file_re.is_match(&path) {
        // Treat the identifier as a path like "/foo/bar.txt"
        if Path::new(&path).is_relative() {
            path = Path::new(&dx_env.cli_wd)
                .join(path)
                .to_string_lossy()
                .to_string();
        }
    }

    return Ok(DxPath {
        path: path.to_string(),
        project_id: project_id.to_string(),
    });
}

// --------------------------------------------------
pub fn is_file_or_path(
    dx_env: &DxEnvironment,
    path: &str,
) -> Result<FileOrPath> {
    // Goal of this function is to guess whether a path
    // is a file or something that might be a file or dir
    // without making any API calls to resolve

    let mut path = path.to_string();

    // Default project_id comes from env
    let mut project_id = dx_env.project_context_id.to_string();

    // The incoming path may start with project_id
    // If so, use that and remove it from the path
    let project_re =
        Regex::new("^(project-[A-Za-z0-9]{24})(:(.*))?").unwrap();

    if let Some(caps) = project_re.captures(&path) {
        project_id = caps.get(1).unwrap().as_str().to_string();
        path = caps
            .get(3)
            .map_or("".to_string(), |m| m.as_str().to_string());
    }

    // Remove leading ":"
    // This should match even the empty string, in which case
    // default path comes from env
    let path_re = Regex::new("^:?(.+)?").unwrap();
    if let Some(caps) = path_re.captures(&path) {
        path = caps
            .get(1)
            .map_or(dx_env.cli_wd.to_string(), |m| m.as_str().to_string());
    }

    // If remaining path looks like a file ID, return that
    let file_re = Regex::new("^file-[A-Za-z0-9]{24}$").unwrap();
    if file_re.is_match(&path) {
        return Ok(FileOrPath::File {
            file_id: path.to_string(),
            project_id: project_id.to_string(),
        });
    }

    // Treat the identifier as a path like "/foo/bar.txt"
    let mut path = Path::new(&path).to_path_buf();
    if path.is_relative() {
        path = Path::new(&dx_env.cli_wd).join(path);
    }

    Ok(FileOrPath::Path {
        path: path.to_string_lossy().to_string(),
        project_id: project_id.to_string(),
    })

    //if let Some(basename) = path.file_name() {
    //    let dirname = path
    //        .parent()
    //        .unwrap_or(Path::new("/"))
    //        .to_string_lossy()
    //        .to_string();

    //    // Look for a file "bar.txt" in a folder "/foo" ...
    //    let mut opts = FindDataOptions {
    //        class: Some(ObjectType::File),
    //        state: None,
    //        name: Some(FindName::Regexp(
    //            basename.to_string_lossy().to_string(),
    //        )),
    //        visibility: None,
    //        id: vec![],
    //        object_type: None,
    //        tags: vec![],
    //        region: vec![],
    //        properties: None,
    //        link: None,
    //        scope: Some(FindDataScope {
    //            project: Some(project_id),
    //            folder: Some(dirname),
    //            recurse: Some(false),
    //        }),
    //        sort_by: None,
    //        level: None,
    //        modified: None,
    //        created: None,
    //        describe: Some(FindDescribe::Boolean(true)),
    //        starting: None,
    //        limit: None,
    //        archival_state: None,
    //    };

    //    // If found, return the file ID
    //    let data = api::find_data(dx_env, &mut opts)?;
    //    if data.len() == 1 {
    //        if let Some(val) = data.first() {
    //            return Ok(FileOrDirectory::File {
    //                name: val.id.clone(),
    //                project_id: Some("".to_string()),
    //            });
    //        }
    //    }
    //}

    //// Try looking for a folder with the given name
    //let ls_opts = ListFolderOptions {
    //    folder: "/",
    //    only: Some(ListFolderOptionOnlyValue::Folders),
    //    describe: true,
    //    has_subfolder_flags: true,
    //    include_hidden: true,
    //};

    //let list: ListFolderResult =
    //    api::ls(dx_env, &dx_env.project_context_id, ls_opts)?;
    //let wanted = path.display().to_string();

    //if let Some(folders) = list.folders {
    //    let matches: Vec<_> = folders
    //        .iter()
    //        .map(|t| t.0.clone())
    //        .filter(|name| name == &wanted)
    //        .collect();

    //    if matches.len() == 1 {
    //        if let Some(dir) = matches.first() {
    //            return Ok(FileOrDirectory::Directory {
    //                name: dir.to_string(),
    //                project_id: Some(project_id.to_string()),
    //            });
    //        }
    //    }
    //}

    //bail!(r#"Cannot find file or directory "{wanted}""#);
}

// --------------------------------------------------
pub fn wizard(args: WizardArgs) -> Result<()> {
    let choices = vec!["DxApp", "DxAsset", "WDL"];

    match Select::new("Output:", choices).prompt() {
        Ok(output) => match output {
            "DxApp" => wizard_applet(args.name, args.json_template),
            "DxAsset" => wizard_asset(args.name, args.json_template),
            _ => wizard_wdl(args.name, args.json_template),
        },
        _ => Ok(()),
    }
}

// --------------------------------------------------
pub fn wizard_applet(
    name: Option<String>,
    json_template: Option<String>,
) -> Result<()> {
    let dx_env = get_dx_env()?;
    let options = ProjectDescribeOptions {
        fields: Some(HashMap::from([(ProjectDescribeField::Region, true)])),
    };
    let project =
        api::describe_project(&dx_env, &dx_env.project_context_id, &options)?;

    let template: Result<Option<DxApp>> = match json_template {
        Some(filename) => {
            let json = fs::read_to_string(filename)?;
            let app: DxApp = serde_json::from_str(&json)?;
            Ok(Some(app))
        }
        _ => Ok(None),
    };
    let template = template.unwrap();

    let preamble = ">>> Basic Metadata <<<

Please enter basic metadata fields to describes your applet. 
Starred (*) values are required.
At the end of this wizard, the files necessary for building 
your applet will be generated from the answers you provide.

The name of your applet must be unique on the DNAnexus platform.
After creation, you will be able to publish new versions using 
the same applet name.

Applet names are restricted to alphanumeric characters
(a-z, A-Z, 0-9), and the characters \".\", \"_\", and \"-\".
    ";

    println!("{preamble}");

    //let default_name =
    //    &name
    //        .unwrap_or(template.map_or("".to_string(), |t| {
    //            t.name.unwrap_or("".to_string())
    //        }));

    let applet_name = normalize(
        Text::new("Applet Name*:")
            .with_initial_value(&name.unwrap_or("".to_string()))
            .prompt()
            .unwrap(),
    )?;

    // TODO: Why are applet name/source dir linked?
    let dir = &applet_name.clone();
    let dir = Path::new(dir);
    if dir.exists() {
        bail!("\"{applet_name}\" exists, cannot create directory");
    }
    fs::create_dir(dir)?;

    let title = Text::new("Title:")
        .with_default(&applet_name.clone())
        .prompt()
        .unwrap();

    let summary = Text::new("Summary:").prompt().unwrap();

    let version = Text::new("Version:")
        .with_default("0.1.0")
        .prompt()
        .unwrap();

    let timeout = get_timeout()?;

    let language =
        Select::new("Programming Language:", ["bash", "python3"].to_vec())
            .prompt()
            .unwrap();

    let allow_internet_access =
        Select::new("Allow Internet Access:", ["No", "Yes"].to_vec())
            .prompt()
            .unwrap()
            == "Yes";

    let allow_parent_project_access = Select::new(
        "Allow Access to Parent Project:",
        ["No", "Yes"].to_vec(),
    )
    .prompt()
    .unwrap()
        == "Yes";

    let types = VALID_INSTANCE_TYPE.to_vec();
    let starting_cursor = &types
        .iter()
        .position(|v| v == &"mem1_ssd1_v2_x4")
        .unwrap_or(0);

    let instance_type = Select::new("Default Instance Type:", types)
        .with_starting_cursor(*starting_cursor)
        .prompt()
        .unwrap();

    let region_names = VALID_REGION.to_vec();
    let project_region = project.region.unwrap_or("*".to_string());
    let starting_cursor = &region_names
        .iter()
        .position(|v| v == &project_region)
        .unwrap_or(0);
    let region_name = Select::new("Region:", region_names)
        .with_starting_cursor(*starting_cursor)
        .prompt()
        .unwrap();

    let sys_req = SystemRequirements {
        instance_type: instance_type.to_string(),
        cluster_spec: None,
    };

    let regional_options = HashMap::from([(
        region_name.to_string(),
        RegionalOptions {
            resources: None,
            system_requirements: HashMap::from([("*".to_string(), sys_req)]),
        },
    )]);

    let input_spec: Vec<InputSpec> = match &template {
        Some(app_template) => app_template.input_spec.clone(),
        _ => get_inputs()?,
    };

    let output_spec: Vec<OutputSpec> = match &template {
        Some(app_template) => app_template.output_spec.clone(),
        _ => get_outputs(&input_spec)?,
    };

    let interpreter = Interpreter::from_str(language)?;
    let run_file = match interpreter {
        Interpreter::Bash => "run.sh",
        _ => "run.py",
    };

    let run_spec = RunSpec {
        interpreter: Some(interpreter.clone()),
        file: Some(format!("src/{run_file}")),
        distribution: LinuxDistribution::Ubuntu,
        release: Some(LinuxRelease::V20_04),
        version: Some(LinuxVersion::V0),
        code: None,
        head_job_on_demand: None,
        restartable_entry_points: None,
        asset_depends: None,
        exec_depends: vec![],
        timeout_policy: Some(HashMap::from([(
            "*".to_string(),
            HashMap::from([timeout]),
        )])),
    };

    let access = AccessSpec {
        network: if allow_internet_access {
            vec!["*".to_string()]
        } else {
            vec![]
        },
        project: if allow_parent_project_access {
            Some("CONTRIBUTE".to_string())
        } else {
            None
        },
        all_projects: None,
        developer: None,
        project_creation: None,
    };

    let app = DxApp {
        name: Some(applet_name.clone()),
        title,
        dxapi: Some("1.0.0".to_string()),
        summary: if summary.is_empty() {
            None
        } else {
            Some(summary)
        },
        description: None,
        version: Some(version),
        developer_notes: None,
        types: vec![],
        bill_to: None,
        open_source: None,
        categories: vec![],
        developers: vec![],
        authorized_users: vec![],
        input_spec: input_spec.clone(),
        output_spec: output_spec.clone(),
        run_spec,
        https_app: None,
        access: Some(access),
        regional_options: Some(regional_options),
        details: None,
        ignore_reuse: None,
    };

    fs::write(dir.join("dxapp.json"), serde_json::to_string_pretty(&app)?)?;
    fs::write(dir.join("Readme.md"), readme_template(&applet_name))?;
    fs::write(
        dir.join("Readme.developer.md"),
        readme_dev_template(&applet_name),
    )?;

    let src_dir = &dir.join("src");
    fs::create_dir(src_dir)?;

    let resources_dir = &dir.join("resources");
    fs::create_dir(resources_dir)?;

    // TODO: Python2.7?
    let template = match interpreter {
        Interpreter::Bash => {
            bash_template(&applet_name, &input_spec, &output_spec)
        }
        _ => python_template(&applet_name, &input_spec, &output_spec),
    };

    fs::write(src_dir.join(run_file), template)?;
    println!("See output in \"{}\"", dir.display());

    Ok(())
}

// --------------------------------------------------
fn get_inputs() -> Result<Vec<InputSpec>> {
    println!(">>> Input Specification <<<");

    let classes: Vec<String> =
        InputOutputClass::iter().map(|v| v.to_string()).collect();
    let mut input_spec: Vec<InputSpec> = vec![];

    for num in 1.. {
        let name_prompt =
            &format!("{} input name* <ENTER to finish>:", Ordinal(num));

        let taken: Vec<_> =
            input_spec.iter().map(|v| v.name.as_str()).collect();

        let name = get_identifier(name_prompt, &taken, None)?;

        if name.is_empty() {
            break;
        }

        let label = Text::new("Label:").prompt().ok();

        let class = Select::new("Input Class", classes.clone())
            .prompt()
            .unwrap();
        let class = InputOutputClass::from_str(&class)?;

        let optional =
            Select::new("Is this value optional?", ["No", "Yes"].to_vec())
                .prompt()
                .unwrap()
                == "Yes";

        let default: Option<serde_json::Value> = if optional {
            Some(get_default(&class)?)
        } else {
            None
        };

        input_spec.push(InputSpec {
            name,
            label,
            class,
            optional: Some(optional),
            default,
            patterns: vec![],
            help: None,
            choices: vec![],
            input_type: None,
            group: None,
            suggestions: vec![],
        });
    }

    Ok(input_spec)
}

// --------------------------------------------------
fn get_outputs(input_spec: &[InputSpec]) -> Result<Vec<OutputSpec>> {
    println!(">>> Output Specification <<<");

    let classes: Vec<String> =
        InputOutputClass::iter().map(|v| v.to_string()).collect();
    let mut output_spec: Vec<OutputSpec> = vec![];

    for num in 1.. {
        let name_prompt =
            &format!("{} output name* <ENTER to finish>:", Ordinal(num));

        // Make name unique across inputs and outputs for WDL
        let mut taken: Vec<_> =
            input_spec.iter().map(|v| v.name.as_str()).collect();
        let mut out_names: Vec<_> =
            output_spec.iter().map(|v| v.name.as_str()).collect();
        taken.append(&mut out_names);

        let name = get_identifier(name_prompt, &taken, None)?;
        if name.is_empty() {
            break;
        }

        let label = Text::new("Label:").prompt().ok();

        let class = Select::new("Output Class", classes.clone())
            .prompt()
            .unwrap();
        let class = InputOutputClass::from_str(&class)?;

        let optional =
            Select::new("Is this value optional?", ["No", "Yes"].to_vec())
                .prompt()
                .unwrap()
                == "Yes";

        output_spec.push(OutputSpec {
            name,
            class,
            label,
            help: None,
            optional: Some(optional),
            patterns: vec![],
        });
    }
    Ok(output_spec)
}

// --------------------------------------------------
pub fn wizard_asset(
    name: Option<String>,
    json_template: Option<String>,
) -> Result<()> {
    // TODO: Also parse a dxasset.json, ADD TESTS
    let template: Result<Option<Vec<ExecDepends>>> = match json_template {
        Some(filename) => {
            let json = fs::read_to_string(&filename)?;
            let app: DxApp = serde_json::from_str(&json)?;
            if !app.run_spec.exec_depends.is_empty() {
                Ok(Some(app.run_spec.exec_depends.clone()))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    };
    let template = template.unwrap();

    let asset_name = get_identifier("Asset Name:", &[], name)?;

    let out_dir =
        get_identifier("Output Directory:", &[], Some(asset_name.clone()))?;
    let out_dir = Path::new(&out_dir);

    if out_dir.is_dir() {
        bail!(r#""{}" already exists."#, out_dir.display())
    } else {
        println!("Creating {}", out_dir.display());
        fs::create_dir(out_dir)?;
    }

    let title = Text::new("Title:").prompt().unwrap();
    let description = Text::new("Description:").prompt().unwrap();
    let version = Text::new("Version:").prompt().unwrap();

    let package_managers: Vec<String> =
        PackageManager::iter().map(|v| v.to_string()).collect();

    let mut exec_depends: Vec<ExecDepends> = vec![];
    //let template_depends = template.run_spec.map(|r| r.exec_depends);

    if let Some(deps) = template {
        exec_depends = deps;
    } else {
        println!(">>> ExecDepends <<<");
        for num in 1.. {
            let name_prompt =
                &format!("{} dependency* <ENTER to finish>:", Ordinal(num));

            // Make name unique across inputs and outputs for WDL
            let taken: Vec<_> =
                exec_depends.iter().map(|v| v.name.as_str()).collect();

            let dependency_name = get_identifier(name_prompt, &taken, None)?;
            if dependency_name.is_empty() {
                break;
            }

            let package_manager =
                Select::new("Package Manager:", package_managers.to_vec())
                    .prompt()
                    .unwrap();

            let asset_version = Text::new("Version:").prompt().unwrap();
            let asset_version = if asset_version.is_empty() {
                None
            } else {
                Some(asset_version)
            };

            // TODO: Add stages?
            // let stages = Text::new("Stages:").prompt().unwrap();
            exec_depends.push(ExecDepends {
                name: dependency_name,
                package_manager: Some(PackageManager::from_str(
                    &package_manager,
                )?),
                version: asset_version,
                stages: vec![],
            });
        }
    }

    let asset = DxAsset {
        name: Some(asset_name),
        title,
        description: Some(description),
        version: Some(version),
        distribution: LinuxDistribution::Ubuntu,
        release: Some(LinuxRelease::V20_04),
        exec_depends,
    };

    fs::write(
        out_dir.join("dxasset.json"),
        serde_json::to_string_pretty(&asset)?,
    )?;

    println!(r#"See output in "{}""#, out_dir.display());

    Ok(())
}

// --------------------------------------------------
pub fn wizard_wdl(
    name: Option<String>,
    json_template: Option<String>,
) -> Result<()> {
    let res: Result<Option<(DxApp, Option<PathBuf>)>> = match json_template {
        Some(filename) => {
            let json = fs::read_to_string(&filename)?;
            let app: DxApp = serde_json::from_str(&json)?;
            let app_dir = Path::new(&filename).parent().expect("app_dir");
            let run_file = match app.run_spec.file {
                Some(ref f) => {
                    let buf = &app_dir.join(f).to_path_buf();
                    Some(buf.clone())
                }
                _ => None,
            };

            Ok(Some((app, run_file)))
        }
        _ => Ok(None),
    };
    let res = res.unwrap();

    let (template, run_file) = match res {
        Some((t, d)) => (Some(t), d),
        None => (None, None),
    };

    let task_name = get_identifier("Task Name:", &[], name)?;
    let out_dir = get_identifier("Output Directory:", &[], None)?;
    let out_dir = Path::new(&out_dir);

    if out_dir.is_dir() {
        bail!(r#""{}" already exists."#, out_dir.display())
    } else {
        println!("Creating {}", out_dir.display());
        fs::create_dir(out_dir)?;
    }

    //let run_file = app
    //    .run_spec
    //    .file
    //    .map(|f| &applet_dir.join(f).to_path_buf().clone());

    let input_spec: Vec<InputSpec> = match &template {
        Some(app) => app.input_spec.clone(),
        _ => get_inputs()?,
    };

    let output_spec: Vec<OutputSpec> = match &template {
        Some(app) => app.output_spec.clone(),
        _ => get_outputs(&input_spec)?,
    };

    let wdl = wdl_template(
        &task_name,
        &input_spec,
        &output_spec,
        run_file.as_ref(),
    )?;

    fs::write(out_dir.join("main.wdl"), wdl)?;

    Ok(())
}

// --------------------------------------------------
pub fn rm(args: RmArgs) -> Result<()> {
    let dx_env = get_dx_env()?;

    for path in &args.paths {
        match resolve_path(&dx_env, &path) {
            Err(e) => eprintln!("{e}"),
            Ok(dx_path) => {
                let options = ListFolderOptions {
                    folder: &Path::new(&dx_path.path)
                        .parent()
                        .expect("parent")
                        .display()
                        .to_string(),
                    only: Some(ListFolderOptionOnlyValue::Folders),
                    describe: true,
                    has_subfolder_flags: true,
                    include_hidden: args.all,
                };

                let list: ListFolderResult =
                    api::ls(&dx_env, &dx_path.project_id, options)?;

                let mut found_folder = false;
                if let Some(folders) = list.folders {
                    let matches: Vec<_> = folders
                        .iter()
                        .map(|t| t.0.clone())
                        .filter(|name| name == &dx_path.path)
                        .collect();

                    // There can only be one folder by a name
                    if let Some(folder) = matches.first() {
                        found_folder = true;
                        if !args.recursive {
                            bail!(
                                r#"Use recursive to remove folder "{folder}""#
                            );
                        }

                        let rm_opts = RmdirOptions {
                            folder: folder.clone(),
                            recurse: Some(true),
                            force: Some(true),
                            partial: None,
                        };

                        let res = api::rmdir(
                            &dx_env,
                            &dx_path.project_id,
                            &rm_opts,
                        )?;

                        if !res.completed.unwrap_or(true) {
                            println!(r#"Unable to remove "{folder}"!"#);
                        }
                    }
                }

                // Files
                let files = find_files_by_path(
                    &dx_env,
                    &dx_path.path,
                    &dx_path.project_id,
                )?;

                if files.is_empty() && !found_folder {
                    println!(r#"No files or folders named "{path}""#);
                } else {
                    let selected = if args.all {
                        Some("all".to_string())
                    } else {
                        select_file_from_list(&files, true)
                    };

                    let objects = selected.map_or(vec![], |file| {
                        if file == "all" {
                            files
                                .iter()
                                .filter_map(|f| f.describe.clone())
                                .map(|desc| desc.id)
                                .collect()
                        } else {
                            vec![file]
                        }
                    });

                    if !objects.is_empty() {
                        let options = RmOptions {
                            objects,
                            force: Some(args.force),
                        };

                        if let Err(e) =
                            api::rm(&dx_env, &dx_path.project_id, &options)
                        {
                            eprintln!("{e}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// --------------------------------------------------
pub fn rmdir(args: RmdirArgs) -> Result<()> {
    let dx_env = get_dx_env()?;

    for path in &args.paths {
        let dest = resolve_path(&dx_env, path)?;

        let options = RmdirOptions {
            folder: dest.path,
            recurse: Some(true),
            force: None,
            partial: Some(true),
        };

        loop {
            let res = api::rmdir(&dx_env, &dest.project_id, &options)?;
            // Limit of 10K items to delete, so may need to repeat
            if res.completed.unwrap_or(true) {
                break;
            }
        }
    }

    Ok(())
}

// --------------------------------------------------
pub fn rm_project(args: RmProjectArgs) -> Result<()> {
    let dx_env = get_dx_env()?;

    for project in args.projects {
        let found = find_project(&dx_env, &project)?;

        let num_found = found.len();
        match num_found {
            0 => println!(r#"Project "{project}" cannot be found"#),
            1 => {
                let options = RmProjectOptions {
                    terminate_jobs: None,
                };
                let project = found.first().unwrap();
                let project_id = &project.id;
                let confirm = if args.force {
                    Ok(true)
                } else {
                    let name = project
                        .describe
                        .get("name")
                        .map_or("NA".to_string(), String::from);

                    Confirm::new(&format!(
                        r#"Will delete project "{name}" ({project_id})"#
                    ))
                    .with_default(false)
                    .prompt()
                };

                match confirm {
                    Ok(true) => {
                        let removed =
                            api::rm_project(&dx_env, &project_id, &options)?;
                        println!(r#"Removed project "{}""#, removed.id);
                    }
                    Ok(false) => println!("Will not delete"),
                    _ => println!("Try again"),
                }
            }
            _ => {
                println!(
                    r#"Found {num_found} projects matching "{project}""#
                );
                for project in found {
                    let name = project
                        .describe
                        .get("name")
                        .map_or("NA".to_string(), String::from);
                    println!("- {} {}", project.id, name);
                }
            }
        }
    }

    Ok(())
}

// --------------------------------------------------
fn readme_template(applet_name: &str) -> String {
    let lines = vec![
        "<!-- dx-header -->".to_string(),
        format!("# {applet_name} (DNAnexus Platform App)"),
        "".to_string(),
        "This is the source code for an app that runs on the DNAnexus Platform.".to_string(),
        "For more information about how to run or modify it, see".to_string(),
        "https://documentation.dnanexus.com/.".to_string(),
        "<!-- /dx-header -->".to_string(),
        "".to_string(),
        "<!-- Insert a description of your app here -->".to_string(),
        "".to_string(),
        "<!--".to_string(),
        "TODO: This app directory was automatically generated by a wizard.".to_string(),
        "Please edit this Readme.md file to include essential documentation about".to_string(),
        "your app that would be helpful to users. (Also see the".to_string(),
        "Readme.developer.md.) Once you're done, you can remove these TODO".to_string(),
        "comments.".to_string(),
        "".to_string(),
        "For more info, see https://documentation.dnanexus.com/developer.".to_string(),
        "-->".to_string(),
    ];

    lines.join("\n")
}

// --------------------------------------------------
fn readme_dev_template(applet_name: &str) -> String {
    let lines = vec![
        format!("# {applet_name}"),
        "".to_string(),
        "<!--".to_string(),
        "TODO: Please edit this Readme.developer.md file to include information".to_string(),
        "for developers or advanced users, for example:".to_string(),
        "".to_string(),
        "* Information about app internals and implementation details".to_string(),
        "* How to report bugs or contribute to development".to_string(),
"-->".to_string(),
    ];

    lines.join("\n")
}

// --------------------------------------------------
// TODO: Add tests
fn python_template(
    applet_name: &str,
    inputs: &[InputSpec],
    outputs: &[OutputSpec],
) -> String {
    let mut lines: Vec<String> = vec![
        "#!/usr/bin/env python".to_string(),
        r#"""""#.to_string(),
        format!("{applet_name}"),
        r#"""""#.to_string(),
        "".to_string(),
        "import os".to_string(),
        "import dxpy".to_string(),
        "".to_string(),
        "@dxpy.entry_point('main')".to_string(),
        format!(
            "def main({}):",
            inputs
                .iter()
                .map(|v| v.name.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        r#"    """ Entry Point """"#.to_string(),
        "".to_string(),
    ];

    if !inputs.is_empty() {
        lines.push("    # Inputs".to_string());
        for input in inputs.iter() {
            match input.class {
                InputOutputClass::Applet => lines.push(format!(
                    "    {} = dxpy.DXApplet({})",
                    input.name, input.name
                )),
                InputOutputClass::ArrayApplet => lines.push(format!(
                    "    {} = [dxpy.DXApplet(item) for item in {}]",
                    input.name, input.name
                )),
                InputOutputClass::ArrayFile => {
                    lines.push(format!(
                        "    {} = [dxpy.DXFile(item) for item in {}]",
                        input.name, input.name
                    ));
                    lines.push(format!(
                        "    for i, file in enumerate({}):",
                        input.name,
                    ));
                    lines.push(format!(
                        "{}dxpy.download_dxfile(file.get_id(), f'{}-{{i}}')",
                        " ".repeat(8),
                        input.name
                    ));
                }
                InputOutputClass::ArrayRecord => lines.push(format!(
                    "    {} = [dxpy.DXRecord(item) for item in {}]",
                    input.name, input.name
                )),
                InputOutputClass::File => {
                    lines.push(format!(
                        "    {} = dxpy.DXFile({})",
                        input.name, input.name
                    ));
                    lines.push(format!(
                        "    dxpy.download_dxfile({}.get_id(), '{}')",
                        input.name, input.name
                    ));
                }
                InputOutputClass::Record => lines.push(format!(
                    "    {} = dxpy.DXRecord({})",
                    input.name, input.name
                )),
                _ => (),
            }
        }
        lines.push("".to_string());
    }

    lines.push("    # Add your code here".to_string());
    lines.push("".to_string());
    lines.push("    # Outputs".to_string());
    lines.push("    output = {}".to_string());

    for output in outputs.iter() {
        match output.class {
            InputOutputClass::Applet => lines.push(format!(
                "    output['{}'] = dxpy.dxlink({}_id)",
                output.name, output.name
            )),
            InputOutputClass::ArrayApplet => {
                lines.push(format!("    output['{}'] = [", output.name));
                lines.push(format!(
                    "{}dxpy.dxlink(item) for item in {}_ids",
                    " ".repeat(8),
                    output.name
                ));
                lines.push("    ]".to_string());
            }
            InputOutputClass::ArrayFile => {
                lines.push(format!("    {}_ids = [", output.name));
                lines.push(format!(
                    "{}dxpy.upload_local_file(file) for file in {}",
                    " ".repeat(8),
                    output.name
                ));
                lines.push("    ]".to_string());
                lines.push(format!("    output['{}'] = [", output.name));
                lines.push(format!(
                    "{}dxpy.dxlink(item) for item in {}_ids",
                    " ".repeat(8),
                    output.name
                ));
                lines.push("    ]".to_string());
            }
            InputOutputClass::ArrayRecord => {
                lines.push(format!("    output['{}'] = [", output.name));
                lines.push(format!(
                    "{}dxpy.dxlink(item) for item in {}",
                    " ".repeat(8),
                    output.name
                ));
                lines.push("    ]".to_string());
            }
            InputOutputClass::File => {
                lines.push(format!(
                    "    {}_id = dxpy.upload_local_file('{}')",
                    output.name, output.name
                ));
                lines.push(format!(
                    "    output['{}'] = dxpy.dxlink({}_id)",
                    output.name, output.name
                ));
            }
            InputOutputClass::Record => lines.push(format!(
                "    output['{}'] = dxpy.dxlink({})",
                output.name, output.name
            )),
            _ => lines.push(format!(
                "    output['{}'] = {}",
                output.name, output.name
            )),
        }
    }

    lines.push("    return output".to_string());
    lines.push("".to_string());
    lines.push("dxpy.run()".to_string());
    lines.push("".to_string());
    lines.join("\n")
}

// --------------------------------------------------
fn wdl_template(
    applet_name: &str,
    inputs: &[InputSpec],
    outputs: &[OutputSpec],
    run_file: Option<&PathBuf>,
) -> Result<String> {
    let mut lines: Vec<String> = vec![
        "version 1.0".to_string(),
        "".to_string(),
        format!("task {applet_name} {{"),
        "    input {".to_string(),
    ];

    // Inputs
    for input in inputs {
        lines.push(format!(
            "{}{}{} {}",
            " ".repeat(8),
            &input.class.wdl_class(),
            input.optional.map_or("".to_string(), |val| if val {
                "?".to_string()
            } else {
                "".to_string()
            }),
            input.name
        ));
    }
    lines.push("    }".to_string());

    lines.push("".to_string());
    lines.push("    command <<<".to_string());
    let commands: String = match run_file {
        Some(f) => {
            let fh = BufReader::new(File::open(f)?);
            let spaces = " ".repeat(8);
            fh.lines().map_while(Result::ok).fold(
                String::new(),
                |mut output, line| {
                    let _ = writeln!(output, "{spaces}{line}");
                    output
                },
            )
        }
        _ => "".to_string(),
    };
    lines.push(commands);
    lines.push("    >>>".to_string());
    lines.push("".to_string());

    // Runtime
    lines.push("    runtime {".to_string());
    lines.push(format!(r#"{}docker: """#, " ".repeat(8)));
    lines.push(format!(r#"{}dx_instance_type: """#, " ".repeat(8)));
    lines.push("    }".to_string());
    lines.push("".to_string());

    // Outputs
    lines.push("    output {".to_string());
    for output in outputs {
        lines.push(format!(
            r#"{}{}{} {} = """#,
            " ".repeat(8),
            &output.class.wdl_class(),
            output.optional.map_or("".to_string(), |val| if val {
                "?".to_string()
            } else {
                "".to_string()
            }),
            output.name
        ));
    }
    lines.push("    }".to_string());
    lines.push("}".to_string());
    lines.push("".to_string());

    Ok(lines.join("\n"))
}

// --------------------------------------------------
// TODO: Expand tests
fn bash_template(
    applet_name: &str,
    inputs: &[InputSpec],
    outputs: &[OutputSpec],
) -> String {
    let mut lines: Vec<String> = vec![
        "#!/usr/bin/env bash".to_string(),
        format!("# {applet_name}"),
        "".to_string(),
        "set -exo pipefail".to_string(),
        "".to_string(),
        "main() {".to_string(),
    ];

    if !inputs.is_empty() {
        lines.push("    # Inputs".to_string());
        for input in inputs.iter() {
            lines.push(format!(
                r#"    echo "Value of {}: \"${{{}}}\"""#,
                input.name, input.name
            ));
        }

        lines.push("".to_string());

        for input in inputs.iter() {
            match input.class {
                InputOutputClass::File => lines.push(format!(
                    r#"    dx download "${}" -o "{}_name""#,
                    input.name, input.name
                )),
                InputOutputClass::ArrayFile => {
                    lines.push(format!(
                        "    for i in ${{{}[@]}}; do",
                        input.name
                    ));
                    lines.push(format!(
                        r#"        dx download "${{{}[${{i}}]}}" -o "{}-${{i}}""#,
                        input.name, input.name,
                    ));
                    lines.push("    done".to_string());
                }
                _ => (),
            }
        }

        lines.push("".to_string());
    }

    lines.push("    # Add your code here".to_string());

    if !outputs.is_empty() {
        lines.push("".to_string());
        lines.push("    # Outputs".to_string());
        for output in outputs {
            match output.class {
                InputOutputClass::File => {
                    lines.push(format!(
                        r#"    {}_id=$(dx upload "{}_name" --brief)"#,
                        output.name, output.name
                    ));
                    lines.push(format!(
                    r#"    dx-jobutil-add-output {} "${{{}_id}}" --class=file"#,
                    output.name, output.name
                ));
                }
                InputOutputClass::ArrayFile => {
                    lines.push(format!(
                        "    for i in ${{{}[@]}}; do",
                        output.name
                    ));
                    lines.push(format!(
                        r#"{}${{{}[$i]}}=$(dx upload "{}-${{i}}" --brief)"#,
                        " ".repeat(8),
                        output.name,
                        output.name
                    ));
                    lines.push("    done".to_string());
                    lines.push(format!(
                    r#"    dx-jobutil-add-output {} "${{{}[@]}}" --class "array:file""#,
                    output.name, output.name,
                ));
                }
                _ => (),
            }
        }
    }

    lines.push("}".to_string());
    lines.push("".to_string());
    lines.join("\n")
}

// --------------------------------------------------
fn get_identifier(
    message: &str,
    taken: &[&str],
    initial_value: Option<String>,
) -> Result<String> {
    loop {
        let prompt = match initial_value {
            Some(ref val) => Text::new(message).with_initial_value(val),
            _ => Text::new(message),
        };
        let name = prompt.prompt().unwrap();
        if name.is_empty() {
            return Ok(name);
        }

        match normalize(name) {
            Err(e) => println!("{e}"),
            Ok(name) => {
                if taken.iter().any(|v| v == &name) {
                    println!("\"{name}\" is already taken");
                } else {
                    return Ok(name);
                }
            }
        }
    }
}

// --------------------------------------------------
fn get_timeout() -> Result<(TimeoutUnit, u32)> {
    let re = Regex::new(r"^(\d+)([hmd])$").unwrap();

    loop {
        let val = Text::new("Timeout <ENTER> to exit:")
            .with_default("48h")
            .prompt()
            .unwrap();

        if val.is_empty() {
            bail!("Could not get timeout")
        }

        match re.captures(&val) {
            Some(caps) => {
                let num: u32 = caps[1].parse()?;
                let unit = TimeoutUnit::from_str(&caps[2])?;
                return Ok((unit, num));
            }
            _ => println!("\"{val}\" is not a valid timeout"),
        }
    }
}

// --------------------------------------------------
fn get_default(class: &InputOutputClass) -> Result<serde_json::Value> {
    loop {
        let val = Text::new("Default Value <ENTER> to quit:")
            .prompt()
            .unwrap();

        if val.is_empty() {
            break;
        }

        let parsed: Result<serde_json::Value> = match class {
            InputOutputClass::Float => {
                val.parse::<f64>().map_err(|e| anyhow!(e)).map(|v| v.into())
            }
            InputOutputClass::Int => {
                val.parse::<u64>().map_err(|e| anyhow!(e)).map(|v| v.into())
            }
            _ => Ok(val.into()),
        };

        match parsed {
            Ok(v) => return Ok(v),
            Err(e) => println!("{e}"),
        }
    }

    bail!("Unable to get default value")
}

// --------------------------------------------------
pub fn new_project(args: NewProjectArgs) -> Result<String> {
    let project_name = args
        .project_name
        .unwrap_or_else(|| Text::new("Project name:").prompt().unwrap());

    let dx_env = get_dx_env()?;
    let options = NewProjectOptions {
        name: project_name.clone(),
        summary: None,
        description: None,
        protected: false,
        restricted: false,
        download_restricted: false,
        external_upload_restricted: false,
        database_ui_view_only: args.database_ui_view_only,
        contains_phi: args.phi,
        tags: None,
        properties: None,
        bill_to: args.bill_to,
        region: args.region,
        monthly_compute_limit: args.monthly_compute_limit,
        monthly_egress_bytes_limit: args.monthly_egress_bytes_limit,
    };

    match api::new_project(&dx_env, options) {
        Ok(res) => {
            if args.brief {
                println!("{}", res.id);
            } else {
                println!(r#"Created project "{}""#, res.id);
            }

            if args.select {
                let new_env = DxEnvironment {
                    project_context_id: res.id.clone(),
                    project_context_name: project_name.clone(),
                    ..dx_env
                };
                save_dx_env(&new_env)?;
            }
        }
        Err(e) => eprintln!("{e}"),
    }
    Ok("".to_string())
}

// --------------------------------------------------
fn normalize(val: String) -> Result<String> {
    let char_start = Regex::new(r"^[A-Za-z]").unwrap();

    match char_start.find(&val) {
        Some(_) => {
            let spaces = Regex::new(r"\s").unwrap();
            let bad_chars = Regex::new(r"[^a-zA-Z0-9_.-]").unwrap();
            Ok(bad_chars
                .replace_all(&spaces.replace(&val, "_"), "")
                .to_string())
        }
        _ => bail!("Value \"{val}\" must begin with a character"),
    }
}

// --------------------------------------------------
fn get_describe_object_type(id: &str) -> Option<DescribeObject> {
    let analysis_re = Regex::new("^analysis-[A-Za-z0-9]{24}$").unwrap();

    let project_re = Regex::new("^project-[A-Za-z0-9]{24}$").unwrap();

    let file_re =
        Regex::new("^(?:(project-[A-Za-z0-9]{24}):)?(file-[A-Za-z0-9]{24})$")
            .unwrap();

    let record_re = Regex::new(
        "^(?:(project-[A-Za-z0-9]{24}):)?(record-[A-Za-z0-9]{24})$",
    )
    .unwrap();

    let database_re = Regex::new(
        "^(?:(project-[A-Za-z0-9]{24}):)?(database-[A-Za-z0-9]{24})$",
    )
    .unwrap();

    let applet_re = Regex::new(
        "^(?:(project-[A-Za-z0-9]{24}):)?(applet-[A-Za-z0-9]{24})$",
    )
    .unwrap();

    let app_re = Regex::new("^app-[A-Za-z0-9]{24}$").unwrap();

    let container_re = Regex::new("^container-[A-Za-z0-9]{24}$").unwrap();

    let job_re = Regex::new("^job-[A-Za-z0-9]{24}$").unwrap();

    //let user_re = Regex::new("^user-[A-Za-z0-9]{24}$").unwrap();

    if analysis_re.is_match(id) {
        Some(DescribeObject::Analysis {
            analysis_id: id.to_string(),
        })
    } else if project_re.is_match(id) {
        Some(DescribeObject::Project {
            project_id: id.to_string(),
        })
    } else if file_re.is_match(id) {
        extract_project_object_ids(&file_re, id).map(
            |(project_id, file_id)| DescribeObject::File {
                project_id,
                file_id,
            },
        )
    } else if job_re.is_match(id) {
        Some(DescribeObject::Job {
            job_id: id.to_string(),
        })
    } else if record_re.is_match(id) {
        extract_project_object_ids(&record_re, id).map(
            |(project_id, record_id)| DescribeObject::Record {
                project_id,
                record_id,
            },
        )
    } else if database_re.is_match(id) {
        extract_project_object_ids(&database_re, id).map(
            |(project_id, database_id)| DescribeObject::Database {
                project_id,
                database_id,
            },
        )
    } else if applet_re.is_match(id) {
        extract_project_object_ids(&applet_re, id).map(
            |(project_id, applet_id)| DescribeObject::Applet {
                project_id,
                applet_id,
            },
        )
    } else if app_re.is_match(id) {
        Some(DescribeObject::App {
            app_id: id.to_string(),
        })
    } else if container_re.is_match(id) {
        Some(DescribeObject::Container {
            container_id: id.to_string(),
        })
    } else {
        None
    }
}

// --------------------------------------------------
fn extract_project_object_ids(
    re: &Regex,
    id: &str,
) -> Option<(Option<String>, String)> {
    re.captures(id).map(|caps| {
        (
            caps.get(1).map(|v| v.as_str().to_string()),
            caps.get(2).unwrap().as_str().to_string(),
        )
    })
}

// --------------------------------------------------
pub fn describe_database(
    dx_env: &DxEnvironment,
    project_id: Option<String>,
    database_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = DatabaseDescribeOptions {
        project: project_id.map(|v| v.to_string()),
        fields: Some(
            DatabaseDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
        details: true,
        properties: true,
    };

    let db = api::describe_database(dx_env, &database_id, &options)?;

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&db)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(db.id));

        // TODO: More rows
        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(db.class.unwrap_or("NA".to_string())),
        );

        println!("{table}");
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_record(
    dx_env: &DxEnvironment,
    project_id: Option<String>,
    record_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = RecordDescribeOptions {
        project: project_id.map(|v| v.to_string()),
        fields: Some(
            RecordDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
        details: true,
        properties: true,
    };

    let record = api::describe_record(dx_env, &record_id, &options)?;

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(record.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(record.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(record.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Project")
                .with_cell(record.project.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Folder")
                .with_cell(record.folder.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("State")
                .with_cell(record.state.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Visibility").with_cell(
            record.hidden.map_or(
                "NA",
                |v| {
                    if v {
                        "hidden"
                    } else {
                        "visible"
                    }
                },
            ),
        ));

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                record
                    .tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            record.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(
            Row::new().with_cell("Links").with_cell(
                record
                    .links
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            record.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Created By").with_cell(
            record.created_by.map_or("NA".to_string(), |c| c.user),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            record.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Size").with_cell(
            record.size.map_or("NA".to_string(), |s| {
                Size::from_bytes(s).to_string()
            }),
        ));

        println!("{}", table);
    }
    Ok(())
}

// --------------------------------------------------
pub fn describe_file(
    dx_env: &DxEnvironment,
    project_id: Option<String>,
    file_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = FileDescribeOptions {
        project: project_id.map(|v| v.to_string()),
        fields: Some(
            FileDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
        details: true,
        properties: true,
    };

    let file = api::describe_file(dx_env, &file_id, &options)?;

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&file)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(file.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(file.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(file.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Project")
                .with_cell(file.project.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Folder")
                .with_cell(file.folder.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("State")
                .with_cell(file.state.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Visibility").with_cell(
            file.hidden.map_or(
                "NA",
                |v| {
                    if v {
                        "hidden"
                    } else {
                        "visible"
                    }
                },
            ),
        ));

        table.add_row(
            Row::new().with_cell("Types").with_cell(
                file.types
                    .and_then(|t| (!t.is_empty()).then(|| t.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                file.tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            file.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(
            Row::new().with_cell("Outgoing Links").with_cell(
                file.links
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            file.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new().with_cell("Created By").with_cell(
                file.created_by.map_or("NA".to_string(), |c| c.user),
            ),
        );

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            file.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Media Type")
                .with_cell(file.media.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Size").with_cell(
            file.size.map_or("NA".to_string(), |s| {
                Size::from_bytes(s).to_string()
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Cloud Account")
                .with_cell(file.cloud_account.unwrap_or("NA".to_string())),
        );

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_analysis(
    dx_env: &DxEnvironment,
    analysis_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = AnalysisDescribeOptions {
        fields: AnalysisDescribeField::iter()
            .map(|e| (e, true))
            .collect::<HashMap<_, _>>(),
    };

    let analysis = api::describe_analysis(dx_env, &analysis_id, &options)?;
    debug!("{:#?}", &analysis);

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&analysis)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        let currency = analysis.currency;

        // TODO: Add more rows
        table.add_row(Row::new().with_cell("ID").with_cell(&analysis.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(&analysis.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Job Name")
                .with_cell(&analysis.name.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Executable Name").with_cell(
            &analysis.executable_name.unwrap_or("NA".to_string()),
        ));

        table.add_row(
            Row::new()
                .with_cell("Executable")
                .with_cell(&analysis.executable.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Project Context")
                .with_cell(&analysis.project.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Billed To")
                .with_cell(&analysis.bill_to.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Workspace")
                .with_cell(&analysis.workspace.unwrap_or("NA".to_string())),
        );

        if let Some(workflow) = analysis.workflow {
            table.add_row(
                Row::new().with_cell("Workflow").with_cell(&workflow.id),
            );
        }

        table.add_row(
            Row::new()
                .with_cell("Output Folder")
                .with_cell(&analysis.folder.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Priority")
                .with_cell(&analysis.priority.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("State")
                .with_cell(&analysis.state.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new().with_cell("Root Execution").with_cell(
                &analysis.root_execution.unwrap_or("NA".to_string()),
            ),
        );

        table.add_row(
            Row::new()
                .with_cell("Parent Job")
                .with_cell(&analysis.parent_job.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Preserve Job Outputs Folder")
                .with_cell(
                    &analysis
                        .preserve_job_outputs
                        .map_or("-".to_string(), |v| v.to_string()),
                ),
        );

        table.add_row(
            Row::new()
                .with_cell("Launched By")
                .with_cell(&analysis.launched_by.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            &analysis.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            analysis.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new().with_cell("Depends On").with_cell(
                analysis
                    .depends_on
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                analysis
                    .tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            analysis.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(Row::new().with_cell("Total Price").with_cell(
            format_price(analysis.total_price, &currency.clone()),
        ));

        table.add_row(
            Row::new().with_cell("Tree TAT").with_cell(
                &analysis
                    .tree_turnaround_time
                    .map_or("-".to_string(), |v| v.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Detached From").with_cell(
                &analysis.detached_from.unwrap_or("NA".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Rank").with_cell(
            &analysis.rank.map_or("-".to_string(), |v| v.to_string()),
        ));

        table.add_row(
            Row::new().with_cell("Detailed Job Metrics").with_cell(
                &analysis
                    .detailed_job_metrics
                    .map_or("-".to_string(), |v| v.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Detached From Try").with_cell(
                &analysis
                    .detached_from_try
                    .map_or("NA".to_string(), |v| v.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Currency").with_cell(
                &currency
                    .clone()
                    .map_or("-".to_string(), |v| v.code.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Total Egress").with_cell(
                &analysis
                    .total_egress
                    .map_or("NA".to_string(), |v| format!("{:?}", v)),
            ),
        );

        table.add_row(Row::new().with_cell("Egress Computed At").with_cell(
            &analysis.egress_computed_at.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Cost Limit")
                .with_cell(format_price(analysis.cost_limit, &currency)),
        );

        if let Some(stages) = analysis.stages {
            for (stage_num, stage) in stages.iter().enumerate() {
                table.add_row(
                    Row::new()
                        .with_cell(format!("Stage {stage_num}"))
                        .with_cell(&stage.id),
                );

                if let Some(execution) = &stage.execution {
                    if let Some(executable) = &execution.executable {
                        table.add_row(
                            Row::new()
                                .with_cell("  Executable")
                                .with_cell(&executable),
                        );
                    }

                    if let Some(job_id) = &execution.origin_job {
                        table.add_row(
                            Row::new()
                                .with_cell("  Execution")
                                .with_cell(job_id),
                        );
                    }
                }
            }
        }

        // TODO: Fix this if switching to KitchenSink
        //if let Some(input) = analysis.run_input {
        //    table.add_row(Row::new().with_cell("Input").with_cell(""));
        //    for (name, val) in input.iter() {
        //        table.add_row(
        //            Row::new().with_cell(format!("  {name}")).with_cell(val),
        //        );
        //    }
        //}

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_app(
    dx_env: &DxEnvironment,
    app_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = AppDescribeOptions {
        fields: AppDescribeField::iter()
            .map(|e| (e, true))
            .collect::<HashMap<_, _>>(),
    };

    let app = api::describe_app(dx_env, &app_id, &options)?;
    debug!("{:#?}", &app);

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&app)?);
    } else {
        // TODO: Add Details, Regional Options
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);

        table.add_row(Row::new().with_cell("ID").with_cell(app.id));

        table.add_row(
            Row::new()
                .with_cell("Title")
                .with_cell(app.title.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Summary")
                .with_cell(app.summary.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new().with_cell("Categories").with_cell(
                app.categories
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(app.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Billed To")
                .with_cell(app.bill_to.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(app.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Version")
                .with_cell(app.version.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Created By")
                .with_cell(app.created_by.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            app.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Published").with_cell(
            app.published.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            app.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Created From")
                .with_cell(app.applet.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Installed").with_cell(
            app.installed.map_or(
                "NA",
                |v| {
                    if v {
                        "hidden"
                    } else {
                        "visible"
                    }
                },
            ),
        ));

        table.add_row(Row::new().with_cell("Open Source").with_cell(
            app.open_source.map_or("NA", |v| {
                if v {
                    "hidden"
                } else {
                    "visible"
                }
            }),
        ));

        table.add_row(Row::new().with_cell("Deleted").with_cell(
            app.deleted.map_or(
                "NA",
                |v| {
                    if v {
                        "hidden"
                    } else {
                        "visible"
                    }
                },
            ),
        ));

        table.add_row(Row::new().with_cell("Input").with_cell(
            app.input_spec.map_or("-".to_string(), |input| {
                input
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ));

        table.add_row(Row::new().with_cell("Output").with_cell(
            app.output_spec.map_or("-".to_string(), |output| {
                output
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ));

        if let Some(run_spec) = &app.run_spec {
            table.add_row(
                Row::new()
                    .with_cell("Interpreter")
                    .with_cell(&run_spec.interpreter),
            );

            if let Some(bundles) = &run_spec.bundled_depends {
                table.add_row(
                    Row::new().with_cell("Bundled Depends").with_cell(
                        bundles
                            .iter()
                            .map(|b| {
                                format!("{} ({})", b.name, b.id.dnanexus_link)
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }

            if let Some(reqs) = &run_spec.system_requirements {
                table.add_row(
                    Row::new().with_cell("System Requirements").with_cell(
                        reqs.iter()
                            .map(|(k, v)| format!("{{\"{k}\": {v}}}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }
        }

        table.add_row(
            Row::new()
                .with_cell("Resources")
                .with_cell(app.resources.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Num. Installs")
                .with_cell(app.installs.unwrap_or(0)),
        );

        table.add_row(
            Row::new().with_cell("Authorized Users").with_cell(
                app.authorized_users
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(
            Row::new()
                .with_cell("Region")
                .with_cell(app.region.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Ignore Reuse").with_cell(
            app.ignore_reuse.map_or("NA".to_string(), |v| v.to_string()),
        ));

        table.add_row(
            Row::new().with_cell("Is Developer For").with_cell(
                app.is_developer_for
                    .map_or("NA".to_string(), |v| v.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Line Item Per Test").with_cell(
                app.line_item_per_test
                    .map_or("NA".to_string(), |v| v.to_string()),
            ),
        );

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_applet(
    dx_env: &DxEnvironment,
    project_id: Option<String>,
    applet_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = AppletDescribeOptions {
        project: project_id,
        fields: Some(
            AppletDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
    };

    let applet = api::describe_applet(dx_env, &applet_id, &options)?;
    debug!("{:#?}", &applet);

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&applet)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(applet.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(applet.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(applet.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Project")
                .with_cell(applet.project.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Folder")
                .with_cell(applet.folder.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("State")
                .with_cell(applet.state.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Visibility").with_cell(
            applet.hidden.map_or(
                "NA",
                |v| {
                    if v {
                        "hidden"
                    } else {
                        "visible"
                    }
                },
            ),
        ));

        table.add_row(
            Row::new().with_cell("Types").with_cell(
                applet
                    .types
                    .and_then(|t| (!t.is_empty()).then(|| t.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            applet.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                applet
                    .tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Outgoing Links").with_cell(
                applet
                    .links
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            applet.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Created By").with_cell(
            applet.created_by.map_or("NA".to_string(), |c| c.user),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            applet.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Title")
                .with_cell(applet.title.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Summary")
                .with_cell(applet.summary.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Access").with_cell(
            applet.access.map_or("-".to_string(), |a| {
                format!(
                    "network: {}",
                    if a.network.is_empty() {
                        "[]".to_string()
                    } else {
                        a.network.join(", ")
                    }
                )
            }),
        ));

        table.add_row(Row::new().with_cell("Input").with_cell(
            applet.input_spec.map_or("-".to_string(), |input| {
                input
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ));

        table.add_row(Row::new().with_cell("Output").with_cell(
            applet.output_spec.map_or("-".to_string(), |output| {
                output
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("API Version")
                .with_cell(applet.dx_api.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new().with_cell("Ignore Reuse").with_cell(
                applet
                    .ignore_reuse
                    .map_or("NA".to_string(), |v| v.to_string()),
            ),
        );

        if let Some(run_spec) = &applet.run_spec {
            table.add_row(
                Row::new()
                    .with_cell("Interpreter")
                    .with_cell(&run_spec.interpreter),
            );

            if let Some(bundles) = &run_spec.bundled_depends {
                table.add_row(
                    Row::new().with_cell("Bundled Depends").with_cell(
                        bundles
                            .iter()
                            .map(|b| {
                                format!("{} ({})", b.name, b.id.dnanexus_link)
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }

            if let Some(reqs) = &run_spec.system_requirements {
                table.add_row(
                    Row::new().with_cell("System Requirements").with_cell(
                        reqs.iter()
                            .map(|(k, v)| format!("{{\"{k}\": {v}}}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }
        }

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_container(
    dx_env: &DxEnvironment,
    container_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = ContainerDescribeOptions {
        fields: Some(
            ContainerDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
    };

    //let url = format!("https://api.dnanexus.com/{container_id}/describe",);
    //let container: Result<ContainerDescribeResult> =
    //    api::describe(&url, &dx_env.auth_token, &options)?;

    let container = api::describe_container(dx_env, &container_id, &options)?;

    debug!("{:#?}", &container);

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&container)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(container.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(container.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(container.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Billed To")
                .with_cell(container.bill_to.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Access Level").with_cell(
            container.level.map_or("NA".to_string(), |l| l.to_string()),
        ));

        table.add_row(
            Row::new()
                .with_cell("Region")
                .with_cell(container.region.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            container.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            container.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Data Usage").with_cell(format!(
            "{:0.02} GB",
            container.data_usage.unwrap_or(0.0)
        )));

        table.add_row(
            Row::new()
                .with_cell("Sponsored Data Usage")
                .with_cell(format!(
                    "{:0.02} GB",
                    container.sponsored_data_usage.unwrap_or(0.0)
                )),
        );

        table.add_row(Row::new().with_cell("Remove Data Usage").with_cell(
            format!("{:0.02} GB", container.remote_data_usage.unwrap_or(0.0)),
        ));

        table.add_row(
            Row::new().with_cell("Container Type").with_cell(
                container.container_type.unwrap_or("NA".to_string()),
            ),
        );

        table.add_row(
            Row::new()
                .with_cell("Associated App ID")
                .with_cell(container.app.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Associated App")
                .with_cell(container.app_name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new().with_cell("Cloud Account").with_cell(
                container.cloud_account.unwrap_or("NA".to_string()),
            ),
        );

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_project(
    dx_env: &DxEnvironment,
    project_id: String,
    show_json: &bool,
) -> Result<()> {
    let options = ProjectDescribeOptions {
        fields: Some(
            ProjectDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
    };
    let project = api::describe_project(dx_env, &project_id, &options)?;

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&project)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);

        table.add_row(Row::new().with_cell("ID").with_cell(project.id));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(project.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Name")
                .with_cell(project.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Summary")
                .with_cell(project.summary.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Description")
                .with_cell(project.description.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Billed To")
                .with_cell(project.bill_to.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Access Level").with_cell(
            project.level.map_or("NA".to_string(), |l| l.to_string()),
        ));

        table.add_row(
            Row::new()
                .with_cell("Region")
                .with_cell(project.region.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Protected")
                .with_cell(project.protected.unwrap()),
        );

        table.add_row(
            Row::new()
                .with_cell("Contains PHI")
                .with_cell(project.contains_phi.unwrap()),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            project.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Created By").with_cell(
            project.created_by.map_or("NA".to_string(), |c| c.user),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            project.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Data Usage").with_cell(format!(
            "{:0.02} GB",
            project.data_usage.unwrap_or(0.0)
        )));

        table.add_row(Row::new().with_cell("Storage Cost").with_cell(
            format!(
                "{}{:0.03}/month",
                project.currency.map_or("$".to_string(), |c| c.symbol),
                project.storage_cost.unwrap_or(0.0)
            ),
        ));

        table.add_row(Row::new().with_cell("Sponsored Usage").with_cell(
            format!(
                "{:0.02} GB",
                project.sponsored_data_usage.unwrap_or(0.0)
            ),
        ));

        table.add_row(Row::new().with_cell("Sponsored Egress").with_cell(
            format!(
                "{:0.02} GB",
                project.total_sponsored_egress_bytes.unwrap_or(0.0)
            ),
        ));

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                project
                    .tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            project.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(
            Row::new()
                .with_cell("Cloud Account")
                .with_cell(project.cloud_account.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Remote Data Usage")
                .with_cell(project.remote_data_usage.unwrap_or(0.0)),
        );

        table.add_row(
            Row::new()
                .with_cell("Download Restricted")
                .with_cell(project.download_restricted.unwrap()),
        );

        table.add_row(
            Row::new()
                .with_cell("Archived Data Usage")
                .with_cell(project.archived_data_usage.unwrap_or(0.0)),
        );

        table.add_row(
            Row::new()
                .with_cell("Preview Viewer Restricted")
                .with_cell(project.preview_viewer_restricted.unwrap()),
        );

        table.add_row(
            Row::new()
                .with_cell("Display Data Protection Notice")
                .with_cell(project.display_data_protection_notice.unwrap()),
        );

        table.add_row(
            Row::new().with_cell("Default Instance Type").with_cell(
                project.default_instance_type.unwrap_or("NA".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Provider").with_cell(
            project.provider.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        println!("{}", table);
    }

    Ok(())
}

// --------------------------------------------------
pub fn describe_job(
    dx_env: &DxEnvironment,
    job_id: String,
    try_number: Option<u64>,
    show_json: &bool,
) -> Result<()> {
    let options = JobDescribeOptions {
        default_fields: None,
        fields: Some(
            JobDescribeField::iter()
                .map(|e| (e, true))
                .collect::<HashMap<_, _>>(),
        ),
        try_number,
    };

    let job = api::describe_job(dx_env, &job_id, &options)?;

    if *show_json {
        println!("{}", serde_json::to_string_pretty(&job)?);
    } else {
        let fmt = "{:<}    {:<}";
        let mut table = Table::new(fmt);
        table.add_row(Row::new().with_cell("ID").with_cell(&job.id));

        table.add_row(Row::new().with_cell("Try").with_cell(
            &job.try_number.map_or("NA".to_string(), |v| v.to_string()),
        ));

        table.add_row(
            Row::new()
                .with_cell("Class")
                .with_cell(job.class.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Job Name")
                .with_cell(job.name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Executable Name")
                .with_cell(job.executable_name.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Project Context")
                .with_cell(job.project.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Region")
                .with_cell(job.region.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Billed To")
                .with_cell(job.bill_to.unwrap_or("NA".to_string())),
        );

        if let Some(applet) = job.applet {
            table.add_row(Row::new().with_cell("Applet").with_cell(applet));
        }

        if let Some(app) = &job.app {
            table.add_row(Row::new().with_cell("App").with_cell(app));

            table.add_row(
                Row::new()
                    .with_cell("Resources")
                    .with_cell(job.resources.unwrap_or("NA".to_string())),
            );

            table.add_row(
                Row::new()
                    .with_cell("Project Cache")
                    .with_cell(job.project_cache.unwrap_or("NA".to_string())),
            );
        }

        table.add_row(
            Row::new()
                .with_cell("Instance Type")
                .with_cell(job.instance_type.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Priority")
                .with_cell(job.priority.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("State")
                .with_cell(job.state.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Root Execution")
                .with_cell(job.root_execution.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Origin Job")
                .with_cell(job.origin_job.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Parent Job")
                .with_cell(job.parent_job.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Parent Analysis")
                .with_cell(job.parent_analysis.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Analysis")
                .with_cell(job.analysis.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Stage")
                .with_cell(job.stage.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Function")
                .with_cell(job.function.unwrap_or("-".to_string())),
        );

        if let Some(input) = job.run_input {
            table.add_row(Row::new().with_cell("Input").with_cell(""));
            for (name, val) in input.iter() {
                table.add_row(
                    Row::new().with_cell(format!("  {name}")).with_cell(val),
                );
            }
        }

        if let Some(output) = job.output {
            table.add_row(Row::new().with_cell("Output").with_cell(""));
            for (name, val) in output.iter() {
                table.add_row(
                    Row::new().with_cell(format!("  {name}")).with_cell(val),
                );
            }
        }

        table.add_row(
            Row::new()
                .with_cell("Output Folder")
                .with_cell(job.folder.unwrap_or("-".to_string())),
        );

        table.add_row(
            Row::new()
                .with_cell("Preserve Job Outputs Folder")
                .with_cell(
                    job.preserve_job_outputs
                        .map_or("-".to_string(), |v| v.to_string()),
                ),
        );

        table.add_row(
            Row::new()
                .with_cell("Launched By")
                .with_cell(job.launched_by.unwrap_or("NA".to_string())),
        );

        table.add_row(Row::new().with_cell("Created").with_cell(
            job.created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Try Created").with_cell(
            job.try_created.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Started Running").with_cell(
            job.started_running.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Stopped Running").with_cell(
            job.stopped_running.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(Row::new().with_cell("Last Modified").with_cell(
            job.modified.map_or("NA".to_string(), |d| {
                d.format("%Y-%m-%d %H:%M:%S").to_string()
            }),
        ));

        table.add_row(
            Row::new().with_cell("Depends On").with_cell(
                job.depends_on
                    .map_or("NA".to_string(), |vals| vals.join(", ")),
            ),
        );

        table.add_row(
            Row::new().with_cell("Tags").with_cell(
                job.tags
                    .and_then(|v| (!v.is_empty()).then(|| v.join(", ")))
                    .unwrap_or("-".to_string()),
            ),
        );

        table.add_row(Row::new().with_cell("Properties").with_cell(
            job.properties.map_or("-".to_string(), |p| {
                if p.is_empty() {
                    "-".to_string()
                } else {
                    let pairs: Vec<String> =
                        p.iter().map(|(k, v)| format!("{k} = {v}")).collect();
                    pairs.join(", ")
                }
            }),
        ));

        table.add_row(
            Row::new().with_cell("Tree TAT").with_cell(
                job.tree_turnaround_time
                    .map_or("-".to_string(), |v| v.to_string()),
            ),
        );

        let currency = job.currency;

        if let Some(reqs) = &job.system_requirements {
            table.add_row(
                Row::new().with_cell("System Requirements").with_cell(
                    reqs.iter()
                        .map(|(k, v)| format!("{{\"{k}\": {v}}}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            );
        }

        table.add_row(
            Row::new()
                .with_cell("Cost Limit")
                .with_cell(format_price(job.cost_limit, &currency)),
        );

        table.add_row(
            Row::new()
                .with_cell("Detached From")
                .with_cell(job.detached_from.unwrap_or("NA".to_string())),
        );

        table.add_row(
            Row::new().with_cell("Output Reused From").with_cell(
                job.output_reused_from.unwrap_or("NA".to_string()),
            ),
        );

        table.add_row(
            Row::new()
                .with_cell("Worker Reused Deadline Run Time")
                .with_cell(
                    job.worker_reuse_deadline_run_time
                        .map_or("NA".to_string(), |val| val.to_string()),
                ),
        );

        table.add_row(
            Row::new().with_cell("Single Context").with_cell(
                job.single_context
                    .map_or("NA".to_string(), |val| val.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Failure Counts").with_cell(
                job.failure_counts
                    .map_or("NA".to_string(), |val| val.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Ignore Reuse").with_cell(
                job.ignore_reuse
                    .map_or("NA".to_string(), |val| val.to_string()),
            ),
        );

        if let Some(https_app) = &job.https_app {
            table.add_row(
                Row::new().with_cell("HTTPS App").with_cell(https_app),
            );
        }

        table.add_row(Row::new().with_cell("Rank").with_cell(
            job.rank.map_or("NA".to_string(), |val| val.to_string()),
        ));

        table.add_row(
            Row::new().with_cell("Detached From Try").with_cell(
                job.detached_from_try
                    .map_or("NA".to_string(), |val| val.to_string()),
            ),
        );

        table.add_row(
            Row::new().with_cell("Execution Policy").with_cell(
                job.execution_policy
                    .map_or("NA".to_string(), |val| val.to_string()),
            ),
        );

        println!("{table}");
    }

    Ok(())
}

// --------------------------------------------------
fn parse_project_path(
    dx_env: &DxEnvironment,
    destination: &Option<String>,
) -> ProjectPath {
    let destination = destination.clone().unwrap_or(dx_env.cli_wd.clone());
    let current_project_id = dx_env.project_context_id.clone();
    let re = Regex::new("^(project-[A-Za-z0-9]{24})?:?(.*)$").unwrap();

    //let (project_id, mut path) = match re.captures(&destination) {
    //    Some(caps) => (
    //        caps.get(1).map_or(current_project_id, |v| {
    //            v.as_str().to_string().clone()
    //        }),
    //        caps.get(2).unwrap().as_str().to_string(),
    //    ),
    //    _ => (current_project_id, destination.clone()),
    //};

    let (project_id, mut path) = if let Some(caps) = re.captures(&destination)
    {
        let project_id = match caps.get(1) {
            Some(val) => val.as_str(),
            _ => &current_project_id,
        };
        let dirname = caps.get(2).unwrap().as_str();
        (project_id, dirname.to_string())
    } else {
        (current_project_id.as_str(), destination.clone())
    };

    if !path.starts_with('/') {
        path = format!("/{path}")
    }

    ProjectPath {
        project_id: project_id.to_string(),
        path: PathBuf::from(path),
    }
}

// --------------------------------------------------
pub fn upload(args: UploadArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    dbg!(&args);

    let destination = parse_project_path(&dx_env, &args.path);

    for file in &args.files {
        let file_id = upload_local_file(&dx_env, file, &destination)?;
        println!("{file} => {file_id}");
    }

    Ok(())
}

// --------------------------------------------------
pub fn upload_local_file(
    dx_env: &DxEnvironment,
    filename: &str,
    destination: &ProjectPath,
) -> Result<String> {
    let metadata = fs::metadata(filename)?;
    if metadata.len() == 0 {
        bail!(r#"File "{filename}" is empty"#);
    }

    let local_basename = Path::new(filename).file_name().unwrap();
    let basename = destination
        .path
        .file_name()
        .unwrap_or(local_basename)
        .to_string_lossy()
        .to_string();

    // Why was I doing this?
    //let folder = destination
    //    .path
    //    .parent()
    //    .unwrap_or(&destination.path)
    //    .to_string_lossy()
    //    .to_string();

    let new_opts = FileNewOptions {
        project: destination.project_id.clone(),
        name: Some(basename),
        tags: vec![],
        types: vec![],
        hidden: Some(false),
        details: None,
        folder: Some(destination.path.display().to_string()),
        parents: Some(true),
        media: None,
        nonce: Some(TextNonce::new().into_string()),
    };

    let new_file = api::file_new(dx_env, &new_opts)?;
    let mut buffer = vec![0; MD5_READ_CHUNK_SIZE];
    let mut fh = BufReader::new(File::open(filename)?);

    for index in 1.. {
        let bytes_read = fh.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let bytes = &buffer[..bytes_read];
        let upload_opts = FileUploadOptions {
            size: bytes_read,
            md5: format!("{:x}", md5::compute(bytes)),
            index,
        };

        let upload = api::file_upload(dx_env, &new_file.id, &upload_opts)?;
        api::file_upload_part(upload, bytes.to_vec())?;
        buffer.clear();
    }

    // TODO: must send bogus JSON for this to work?
    let close_opts = FileCloseOptions {
        id: new_file.id.clone(),
    };

    api::file_close(dx_env, &new_file.id, &close_opts)?;

    Ok(new_file.id.to_string())
}

// --------------------------------------------------
pub fn watch(args: WatchArgs) -> Result<()> {
    let dx_env = get_dx_env()?;
    println!("{args:#?}");

    let desc_opts = JobDescribeOptions {
        default_fields: None,
        fields: Some(HashMap::from([(
            JobDescribeField::OutputReusedFrom,
            true,
        )])),
        try_number: None,
    };

    let job = api::describe_job(&dx_env, &args.job_id, &desc_opts)?;

    dbg!(&job);

    let job_id = job.output_reused_from.unwrap_or(args.job_id);

    let watch_opts = WatchOptions {
        num_recent_messages: args.num_recent_messages,
        recurse_jobs: Some(false),
        tail: Some(false),
        levels: args.level,
    };

    let res = api::watch(&dx_env, &job_id, &watch_opts)?;
    println!(">>>");
    println!("{res:#?}");
    println!("<<<");
    Ok(())
}

// --------------------------------------------------
pub fn whoami(_args: WhoamiArgs) -> Result<()> {
    // TODO: I can only get the user ID to return,
    // so what else would I display?
    let dx_env = get_dx_env()?;
    let options = WhoAmIOptions {
        fields: Some(HashMap::from([(WhoAmIOptionsFields::ClientIp, true)])),
    };
    let res = api::whoami(&dx_env, &options)?;
    println!("{}", res.id);
    Ok(())
}

// --------------------------------------------------
fn format_price(price: Option<f64>, currency: &Option<Currency>) -> String {
    match price {
        Some(val) => {
            let symbol = match currency {
                Some(c) => c.symbol.to_string(),
                _ => "".to_string(),
            };
            format!("{symbol}{:.2}", val)
        }
        _ => "NA".to_string(),
    }
}

// --------------------------------------------------
pub fn open_outfile(filename: &str) -> Result<Box<dyn io::Write>> {
    match filename {
        "-" => Ok(Box::new(io::stdout())),
        out_name => Ok(Box::new(File::create(out_name)?)),
    }
}

// --------------------------------------------------
#[cfg(test)]
mod tests {
    use crate::{
        bash_template,
        json_parser::{InputOutputClass, InputSpec, OutputSpec},
        normalize, parse_project_path, python_template, wdl_template,
        AnalysisDescribeResult, AppDescribeResult, AppletDescribeResult,
        ContainerDescribeResult, DatabaseDescribeResult, DxEnvironment,
        FileDescribeResult, JobDescribeResult, ProjectDescribeResult,
        ProjectPath, RecordDescribeResult,
    };
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn make_all_inputs() -> Vec<InputSpec> {
        vec![
            InputSpec {
                name: "applet_input".to_string(),
                label: Some("Applet Input".to_string()),
                class: InputOutputClass::Applet,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("applet help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "boolean_input".to_string(),
                label: Some("Boolean Input".to_string()),
                class: InputOutputClass::Boolean,
                optional: Some(false),
                default: Some(serde_json::Value::Bool(true)),
                patterns: vec![],
                help: Some("Boolean help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "file_input".to_string(),
                label: Some("File Input".to_string()),
                class: InputOutputClass::File,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("file help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "float_input".to_string(),
                label: Some("Float Input".to_string()),
                class: InputOutputClass::Float,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("float help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "hash_input".to_string(),
                label: Some("Hash Input".to_string()),
                class: InputOutputClass::Hash,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("hash help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "int_input".to_string(),
                label: Some("Int Input".to_string()),
                class: InputOutputClass::Int,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("int help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "record_input".to_string(),
                label: Some("Record Input".to_string()),
                class: InputOutputClass::Record,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("record help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "string_input".to_string(),
                label: Some("String Input".to_string()),
                class: InputOutputClass::String,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("string help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_applet_input".to_string(),
                label: Some("Array Applet Input".to_string()),
                class: InputOutputClass::ArrayApplet,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array applet help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_boolean_input".to_string(),
                label: Some("Array Boolean Input".to_string()),
                class: InputOutputClass::ArrayBoolean,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array boolean help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_file_input".to_string(),
                label: Some("Array File Input".to_string()),
                class: InputOutputClass::ArrayFile,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array file help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_float_input".to_string(),
                label: Some("Array Float Input".to_string()),
                class: InputOutputClass::ArrayFloat,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array float help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_int_input".to_string(),
                label: Some("Array Int Input".to_string()),
                class: InputOutputClass::ArrayInt,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array int help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_record_input".to_string(),
                label: Some("Array Record Input".to_string()),
                class: InputOutputClass::ArrayRecord,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array record help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
            InputSpec {
                name: "array_string_input".to_string(),
                label: Some("Array String Input".to_string()),
                class: InputOutputClass::ArrayString,
                optional: Some(false),
                default: None,
                patterns: vec![],
                help: Some("array string help".to_string()),
                choices: vec![],
                input_type: None,
                group: None,
                suggestions: vec![],
            },
        ]
    }

    fn make_all_outputs() -> Vec<OutputSpec> {
        vec![
            OutputSpec {
                name: "applet_output".to_string(),
                class: InputOutputClass::Applet,
                label: Some("Applet Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_applet_output".to_string(),
                class: InputOutputClass::ArrayApplet,
                label: Some("Array File Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_boolean_output".to_string(),
                class: InputOutputClass::ArrayBoolean,
                label: Some("Array Boolean Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_file_output".to_string(),
                class: InputOutputClass::ArrayFile,
                label: Some("Array File Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_float_output".to_string(),
                class: InputOutputClass::ArrayFloat,
                label: Some("Array Float Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_int_output".to_string(),
                class: InputOutputClass::ArrayInt,
                label: Some("Array Int Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_record_output".to_string(),
                class: InputOutputClass::ArrayRecord,
                label: Some("Array Record Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "array_string_output".to_string(),
                class: InputOutputClass::ArrayString,
                label: Some("Array String Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "boolean_output".to_string(),
                class: InputOutputClass::Boolean,
                label: Some("Boolean Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "file_output".to_string(),
                class: InputOutputClass::File,
                label: Some("File Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "float_output".to_string(),
                class: InputOutputClass::Float,
                label: Some("Float Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "hash_output".to_string(),
                class: InputOutputClass::Hash,
                label: Some("Hash Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "int_output".to_string(),
                class: InputOutputClass::Int,
                label: Some("Int Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "record_output".to_string(),
                class: InputOutputClass::Record,
                label: Some("Record Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
            OutputSpec {
                name: "string_output".to_string(),
                class: InputOutputClass::String,
                label: Some("String Output".to_string()),
                help: Some("help".to_string()),
                optional: Some(false),
                patterns: vec![],
            },
        ]
    }

    #[test]
    fn test_wdl_template_none() -> Result<()> {
        let expected = fs::read_to_string(
            "tests/expected/applets/wdl_template_none.txt",
        )?;
        let res = wdl_template("empty_wdl", &[], &[], None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected);
        Ok(())
    }

    #[test]
    fn test_wdl_template_all() -> Result<()> {
        let inputs = make_all_inputs();
        let outputs = make_all_outputs();
        let expected = fs::read_to_string(
            "tests/expected/applets/wdl_template_all.txt",
        )?;
        let res = wdl_template("empty_wdl", &inputs, &outputs, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected);
        Ok(())
    }

    #[test]
    fn test_wdl_template_all_commands() -> Result<()> {
        let inputs = make_all_inputs();
        let outputs = make_all_outputs();
        let expected = fs::read_to_string(
            "tests/expected/applets/wdl_template_all_commands.txt",
        )?;
        let path =
            Path::new("tests/expected/applets/commands.sh").to_path_buf();
        let res = wdl_template("empty_wdl", &inputs, &outputs, Some(&path));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expected);
        Ok(())
    }

    #[test]
    fn test_bash_template_none() -> Result<()> {
        let expected = fs::read_to_string(
            "tests/expected/applets/bash_template_none.txt",
        )?;
        assert_eq!(bash_template("Empty Bash Applet", &[], &[]), expected);
        Ok(())
    }

    #[test]
    fn test_bash_template_all() -> Result<()> {
        let inputs = make_all_inputs();
        let outputs = make_all_outputs();
        let expected = fs::read_to_string(
            "tests/expected/applets/bash_template_all.txt",
        )?;
        assert_eq!(
            bash_template("Bash Applet with All Args", &inputs, &outputs),
            expected
        );
        Ok(())
    }

    #[test]
    fn test_python_template_none() -> Result<()> {
        let expected = fs::read_to_string(
            "tests/expected/applets/python_template_none.txt",
        )?;
        assert_eq!(
            python_template("Empty Python Applet", &[], &[]),
            expected
        );
        Ok(())
    }

    #[test]
    fn test_python_template_all() -> Result<()> {
        let inputs = make_all_inputs();
        let outputs = make_all_outputs();
        let expected = fs::read_to_string(
            "tests/expected/applets/python_template_all.txt",
        )?;
        assert_eq!(
            python_template("Python Applet with All Args", &inputs, &outputs),
            expected
        );
        Ok(())
    }

    #[test]
    fn test_normalize() -> Result<()> {
        let val = normalize("123foo".to_string());
        assert!(val.is_err());
        assert_eq!(
            val.unwrap_err().to_string(),
            "Value \"123foo\" must begin with a character"
        );

        let val = normalize("Foo Bar".to_string());
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), "Foo_Bar".to_string());

        let val = normalize("foo_bar~!@#$%^&*()+.123".to_string());
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), "foo_bar.123".to_string());

        Ok(())
    }

    #[test]
    fn test_parse_analysis_json1() -> Result<()> {
        let file = "tests/inputs/desc-analysis-GFfkqz0054JJG8p1GBpv7qGX.json";
        let json = fs::read_to_string(file)?;
        let analysis: AnalysisDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(
            analysis.id,
            "analysis-GFfkqz0054JJG8p1GBpv7qGX".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_parse_analysis_json2() -> Result<()> {
        let file = "tests/inputs/desc-analysis-GbxgbB8098YzQ0K3FBfFqyB2.json";
        let json = fs::read_to_string(file)?;
        let analysis: AnalysisDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(
            analysis.id,
            "analysis-GbxgbB8098YzQ0K3FBfFqyB2".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_parse_app_json() -> Result<()> {
        let file = "tests/inputs/desc-app-GJzjbP00vyjyXPpkFv7bxf1F.json";
        let json = fs::read_to_string(file)?;
        let app: AppDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(app.id, "app-GJzjbP00vyjyXPpkFv7bxf1F".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_applet_json() -> Result<()> {
        let file = "tests/inputs/desc-applet-GZ2BF8Q0jZ5qj3bQBX5BFjjZ.json";
        let json = fs::read_to_string(file)?;
        let applet: AppletDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(applet.id, "applet-GZ2BF8Q0jZ5qj3bQBX5BFjjZ".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_container_json() -> Result<()> {
        let file =
            "tests/inputs/desc-container-GJzjbP008QGyXPpkFv7bxf1G.json";
        let json = fs::read_to_string(file)?;
        let container: ContainerDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(
            container.id,
            "container-GJzjbP008QGyXPpkFv7bxf1G".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_parse_database_json() -> Result<()> {
        let file = "tests/inputs/desc-database-GZ6vP1801xf4fXjB3YVX011f.json";
        let json = fs::read_to_string(file)?;
        let db: DatabaseDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(db.id, "database-GZ6vP1801xf4fXjB3YVX011f".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_file_json() -> Result<()> {
        let file = "tests/inputs/desc-file-GFfbj0Q054J4ypqJ8vQjF4V7.json";
        let json = fs::read_to_string(file)?;
        let file: FileDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(file.id, "file-GFfbj0Q054J4ypqJ8vQjF4V7".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_job_json() -> Result<()> {
        let file = "tests/inputs/desc-job-GFfkqz0054JJG8p1GBpv7qGb.json";
        let json = fs::read_to_string(file)?;
        let job: JobDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(job.id, "job-GFfkqz0054JJG8p1GBpv7qGb".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_project_json() -> Result<()> {
        let file = "tests/inputs/desc-project-GYgj4800jZ5YqgZ24ZzJpZvq.json";
        let json = fs::read_to_string(file)?;
        let project: ProjectDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(
            project.id,
            "project-GYgj4800jZ5YqgZ24ZzJpZvq".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_parse_record_json() -> Result<()> {
        let file = "tests/inputs/desc-record-GZ6vQPj0b5pJfbQ3XffQB1BJ.json";
        let json = fs::read_to_string(file)?;
        let record: RecordDescribeResult = serde_json::from_str(&json)?;
        assert_eq!(record.id, "record-GZ6vQPj0b5pJfbQ3XffQB1BJ".to_string());
        Ok(())
    }

    #[test]
    fn test_parse_project_path() -> Result<()> {
        let dx_env = DxEnvironment {
            apiserver_protocol: "https".to_string(),
            username: "test_user".to_string(),
            cli_wd: "/foo".to_string(),
            apiserver_host: "api.dnanexus.com".to_string(),
            project_context_id: "project-GXY0PK0071xJpG156BFyXpJF"
                .to_string(),
            project_context_name: "test".to_string(),
            apiserver_port: 443,
            auth_token_type: "Bearer".to_string(),
            auth_token: "XXXX".to_string(),
        };

        assert_eq!(
            parse_project_path(&dx_env, &None),
            ProjectPath {
                project_id: "project-GXY0PK0071xJpG156BFyXpJF".to_string(),
                path: PathBuf::from("/foo")
            }
        );

        assert_eq!(
            parse_project_path(&dx_env, &Some("/".to_string())),
            ProjectPath {
                project_id: "project-GXY0PK0071xJpG156BFyXpJF".to_string(),
                path: PathBuf::from("/")
            }
        );

        assert_eq!(
            parse_project_path(
                &dx_env,
                &Some("project-GYgj4800jZ5YqgZ24ZzJpZvq".to_string())
            ),
            ProjectPath {
                project_id: "project-GYgj4800jZ5YqgZ24ZzJpZvq".to_string(),
                path: PathBuf::from("/")
            }
        );

        assert_eq!(
            parse_project_path(
                &dx_env,
                &Some("project-GYgj4800jZ5YqgZ24ZzJpZvq:/".to_string())
            ),
            ProjectPath {
                project_id: "project-GYgj4800jZ5YqgZ24ZzJpZvq".to_string(),
                path: PathBuf::from("/")
            }
        );

        assert_eq!(
            parse_project_path(
                &dx_env,
                &Some("project-GYgj4800jZ5YqgZ24ZzJpZvq:/bar".to_string())
            ),
            ProjectPath {
                project_id: "project-GYgj4800jZ5YqgZ24ZzJpZvq".to_string(),
                path: PathBuf::from("/bar")
            }
        );

        Ok(())
    }
}
