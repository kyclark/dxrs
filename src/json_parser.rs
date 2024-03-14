use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io,
    io::{Read, Write},
};
use strum_macros::{EnumIter, EnumString};

pub const VALID_ACCESS_SPEC_OPTIONS: &[&str] =
    &["", "VIEW", "UPLOAD", "CONTRIBUTE", "ADMINISTER"];

pub const VALID_CATEGORIES: &[&str] = &[
    "Annotation",
    "Assembly",
    "Debugging",
    "Export",
    "Import",
    "Mappings Manipulation",
    "Read Manipulation",
    "Read Mapping",
    "Reports",
    "RNA-Seq",
    "Statistics",
    "Structural Variation",
    "Variation Calling",
];

pub const VALID_REGION: &[&str] = &[
    "*",
    "aws:us-east-1",
    "aws:eu-central-1",
    "aws:ap-southeast-2",
    "aws:eu-west-2",
    "aws:eu-west-2-g",
    "azure:westus",
    "azure:westeurope",
];

pub const VALID_INSTANCE_TYPE: &[&str] = &[
    "mem1_ssd1_x2",
    "mem1_ssd1_x4",
    "mem1_ssd1_x8",
    "mem1_ssd1_x16",
    "mem1_ssd1_x32",
    "mem1_ssd1_x36",
    "mem1_ssd1_v2_x2",
    "mem1_ssd1_v2_x4",
    "mem1_ssd1_v2_x8",
    "mem1_ssd1_v2_x16",
    "mem1_ssd1_v2_x36",
    "mem1_ssd1_v2_x72",
    "mem1_ssd2_x2",
    "mem1_ssd2_x4",
    "mem1_ssd2_x8",
    "mem1_ssd2_x16",
    "mem1_ssd2_x36",
    "mem1_ssd2_v2_x2",
    "mem1_ssd2_v2_x4",
    "mem1_ssd2_v2_x8",
    "mem1_ssd2_v2_x16",
    "mem1_ssd2_v2_x36",
    "mem1_ssd2_v2_x72",
    "mem1_hdd2_x8",
    "mem1_hdd2_x32",
    "mem3_ssd1_v2_x16",
    "mem3_ssd1_v2_x32",
    "mem3_ssd1_v2_x48",
    "mem3_ssd1_v2_x64",
    "mem3_ssd1_v2_x96",
    "mem3_ssd2_x4",
    "mem3_ssd2_x8",
    "mem3_ssd2_x16",
    "mem3_ssd2_x32",
    "mem3_ssd2_v2_x2",
    "mem3_ssd2_v2_x4",
    "mem3_ssd2_v2_x8",
    "mem3_ssd2_v2_x16",
    "mem3_ssd2_v2_x32",
    "mem3_ssd2_v2_x64",
    "mem3_ssd3_x2",
    "mem3_ssd3_x4",
    "mem3_ssd3_x8",
    "mem3_ssd3_x12",
    "mem3_ssd3_x24",
    "mem3_ssd3_x48",
    "mem3_ssd3_x96",
    "mem3_hdd2_x2",
    "mem3_hdd2_x4",
    "mem3_hdd2_x8",
    "mem3_hdd2_v2_x2",
    "mem3_hdd2_v2_x4",
    "mem3_hdd2_v2_x8",
    "azure:mem1_ssd1_x4",
    "azure:mem1_ssd1_x8",
    "azure:mem1_ssd1_x16",
    "azure:mem2_ssd1_x1",
    "azure:mem2_ssd1_x2",
    "azure:mem2_ssd1_x4",
    "azure:mem2_ssd1_x8",
    "azure:mem2_ssd1_x16",
    "azure:mem3_ssd1_x2",
    "azure:mem3_ssd1_x4",
    "azure:mem3_ssd1_x8",
    "azure:mem3_ssd1_x16",
    "azure:mem3_ssd1_x20",
    "azure:mem4_ssd1_x2",
    "azure:mem4_ssd1_x4",
    "azure:mem4_ssd1_x8",
    "azure:mem4_ssd1_x16",
    "azure:mem4_ssd1_x32",
    "azure:mem5_ssd2_x64*",
    "azure:mem5_ssd2_x128*",
    "mem1_ssd1_gpu2_x8",
    "mem1_ssd1_gpu2_x32",
    "mem2_ssd1_gpu_x16",
    "mem2_ssd1_gpu_x32",
    "mem2_ssd1_gpu_x48",
    "mem2_ssd1_gpu_x64",
    "mem3_ssd1_gpu_x8",
    "mem3_ssd1_gpu_x32",
    "mem3_ssd1_gpu_x64",
    "azure:mem3_ssd2_gpu4_x64",
    "mem2_ssd1_x2",
    "mem2_ssd1_x4",
    "mem2_ssd1_x8",
    "mem2_ssd1_v2_x2",
    "mem2_ssd1_v2_x4",
    "mem2_ssd1_v2_x8",
    "mem2_ssd1_v2_x16",
    "mem2_ssd1_v2_x32",
    "mem2_ssd1_v2_x48",
    "mem2_ssd1_v2_x64",
    "mem2_ssd1_v2_x96",
    "mem2_hdd2_x1",
    "mem2_hdd2_x2",
    "mem2_hdd2_x4",
    "mem2_hdd2_v2_x2",
    "mem2_hdd2_v2_x4",
    "mem3_ssd1_x2",
    "mem3_ssd1_x4",
    "mem3_ssd1_x8",
    "mem3_ssd1_x16",
    "mem3_ssd1_x32",
    "mem3_ssd1_v2_x2",
    "mem3_ssd1_v2_x4",
    "mem3_ssd1_v2_x8",
    "mem4_ssd1_x128",
];

pub const VALID_CLUSTER_SPEC_TYPE: &[&str] =
    &["", "generic", "dxspark", "apachespark"];

pub const VALID_CLUSTER_SPEC_VERSION: &[&str] = &["", "2.4.4", "3.2.0"];

// --------------------------------------------------
#[derive(Debug, Serialize, Deserialize, EnumString, Clone)]
pub enum Interpreter {
    #[strum(serialize = "python3")]
    #[serde(rename = "python3")]
    Python3,

    #[strum(serialize = "python2.7")]
    #[serde(rename = "python2.7")]
    Python27,

    #[strum(serialize = "bash")]
    #[serde(rename = "bash")]
    Bash,
}

impl fmt::Display for Interpreter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Interpreter::Python3 => write!(f, "python3"),
            Interpreter::Python27 => write!(f, "python2.7"),
            Interpreter::Bash => write!(f, "bash"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, EnumString)]
pub enum LinuxDistribution {
    #[strum(serialize = "Ubuntu")]
    Ubuntu,
}

impl fmt::Display for LinuxDistribution {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LinuxDistribution::Ubuntu => write!(f, "Ubuntu"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, EnumString)]
pub enum LinuxVersion {
    #[strum(serialize = "0")]
    #[serde(rename = "0")]
    V0,

    #[strum(serialize = "1")]
    #[serde(rename = "1")]
    V1,
}

impl fmt::Display for LinuxVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LinuxVersion::V0 => write!(f, "0"),
            LinuxVersion::V1 => write!(f, "1"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, EnumString)]
pub enum LinuxRelease {
    #[strum(serialize = "14.04")]
    #[serde(rename = "14.04")]
    V14_04,

    #[strum(serialize = "16.04")]
    #[serde(rename = "16.04")]
    V16_04,

    #[strum(serialize = "20.04")]
    #[serde(rename = "20.04")]
    V20_04,
}

impl fmt::Display for LinuxRelease {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LinuxRelease::V14_04 => write!(f, "14.04"),
            LinuxRelease::V16_04 => write!(f, "16.04"),
            LinuxRelease::V20_04 => write!(f, "20.04"),
        }
    }
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Hash,
    Eq,
    PartialEq,
    EnumString,
    EnumIter,
)]
pub enum PackageManager {
    #[strum(serialize = "apt")]
    #[serde(rename = "apt")]
    Apt,

    #[strum(serialize = "cpan")]
    #[serde(rename = "cpan")]
    Cpan,

    #[strum(serialize = "cran")]
    #[serde(rename = "cran")]
    Cran,

    #[strum(serialize = "gem")]
    #[serde(rename = "gem")]
    Gem,

    #[strum(serialize = "pip")]
    #[serde(rename = "pip")]
    Pip,
}

impl fmt::Display for PackageManager {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PackageManager::Apt => write!(f, "apt"),
            PackageManager::Cpan => write!(f, "cpan"),
            PackageManager::Cran => write!(f, "cran"),
            PackageManager::Gem => write!(f, "gem"),
            PackageManager::Pip => write!(f, "pip"),
        }
    }
}

#[derive(
    Debug, Serialize, Deserialize, EnumIter, EnumString, PartialEq, Clone,
)]
pub enum InputOutputClass {
    #[strum(serialize = "applet")]
    #[serde(rename = "applet")]
    Applet,

    #[strum(serialize = "boolean")]
    #[serde(rename = "boolean")]
    Boolean,

    #[strum(serialize = "file")]
    #[serde(rename = "file")]
    File,

    #[strum(serialize = "float")]
    #[serde(rename = "float")]
    Float,

    #[strum(serialize = "hash")]
    #[serde(rename = "hash")]
    Hash,

    #[strum(serialize = "int")]
    #[serde(rename = "int")]
    Int,

    #[strum(serialize = "record")]
    #[serde(rename = "record")]
    Record,

    #[strum(serialize = "string")]
    #[serde(rename = "string")]
    String,

    #[strum(serialize = "array:applet")]
    #[serde(rename = "array:applet")]
    ArrayApplet,

    #[strum(serialize = "array:boolean")]
    #[serde(rename = "array:boolean")]
    ArrayBoolean,

    #[strum(serialize = "array:file")]
    #[serde(rename = "array:file")]
    ArrayFile,

    #[strum(serialize = "array:float")]
    #[serde(rename = "array:float")]
    ArrayFloat,

    #[strum(serialize = "array:int")]
    #[serde(rename = "array:int")]
    ArrayInt,

    #[strum(serialize = "array:record")]
    #[serde(rename = "array:record")]
    ArrayRecord,

    #[strum(serialize = "array:string")]
    #[serde(rename = "array:string")]
    ArrayString,
}

impl InputOutputClass {
    pub fn wdl_class(&self) -> &'static str {
        match self {
            InputOutputClass::Applet => "Applet",
            InputOutputClass::ArrayApplet => "Array[Applet]",
            InputOutputClass::ArrayBoolean => "Array[Boolean]",
            InputOutputClass::ArrayFile => "Array[File]",
            InputOutputClass::ArrayFloat => "Array[Float]",
            InputOutputClass::ArrayInt => "Array[Int]",
            InputOutputClass::ArrayRecord => "Array[Record]",
            InputOutputClass::ArrayString => "Array[String]",
            InputOutputClass::Boolean => "Boolean",
            InputOutputClass::File => "File",
            InputOutputClass::Float => "Float",
            InputOutputClass::Hash => "Hash",
            InputOutputClass::Int => "Int",
            InputOutputClass::Record => "Record",
            InputOutputClass::String => "String",
        }
    }
}

impl fmt::Display for InputOutputClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputOutputClass::Applet => write!(f, "applet"),
            InputOutputClass::ArrayApplet => write!(f, "array:applet"),
            InputOutputClass::ArrayBoolean => write!(f, "array:boolean"),
            InputOutputClass::ArrayFile => write!(f, "array:file"),
            InputOutputClass::ArrayFloat => write!(f, "array:float"),
            InputOutputClass::ArrayInt => write!(f, "array:int"),
            InputOutputClass::ArrayRecord => write!(f, "array:record"),
            InputOutputClass::ArrayString => write!(f, "array:string"),
            InputOutputClass::Boolean => write!(f, "boolean"),
            InputOutputClass::File => write!(f, "file"),
            InputOutputClass::Float => write!(f, "float"),
            InputOutputClass::Hash => write!(f, "hash"),
            InputOutputClass::Int => write!(f, "int"),
            InputOutputClass::Record => write!(f, "record"),
            InputOutputClass::String => write!(f, "string"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, EnumString)]
pub enum TimeoutUnit {
    #[strum(serialize = "minute", serialize = "m")]
    #[serde(rename = "minutes")]
    Minutes,

    #[strum(serialize = "hours", serialize = "h")]
    #[serde(rename = "hours")]
    Hours,

    #[strum(serialize = "days", serialize = "d")]
    #[serde(rename = "days")]
    Days,
}

impl fmt::Display for TimeoutUnit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TimeoutUnit::Minutes => write!(f, "minutes"),
            TimeoutUnit::Hours => write!(f, "hours"),
            TimeoutUnit::Days => write!(f, "days"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DxAsset {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    pub title: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    pub distribution: LinuxDistribution,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<LinuxRelease>,

    #[serde(default, rename = "execDepends")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exec_depends: Vec<ExecDepends>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DxApp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    pub title: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dxapi: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "developerNotes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer_notes: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,

    #[serde(rename = "billTo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_to: Option<String>,

    #[serde(rename = "openSource")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_source: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub developers: Vec<String>,

    #[serde(default, rename = "authorizedUsers")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorized_users: Vec<String>,

    #[serde(rename = "inputSpec")]
    pub input_spec: Vec<InputSpec>,

    #[serde(rename = "outputSpec")]
    pub output_spec: Vec<OutputSpec>,

    #[serde(rename = "runSpec")]
    pub run_spec: RunSpec,

    #[serde(rename = "httpsApp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_app: Option<HttpsApp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessSpec>,

    #[serde(rename = "regionalOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regional_options: Option<HashMap<String, RegionalOptions>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, serde_json::Value>>,

    #[serde(rename = "ignoreReuse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reuse: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionalOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<String>,

    #[serde(rename = "systemRequirements")]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub system_requirements: HashMap<String, SystemRequirements>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemRequirements {
    #[serde(rename = "instanceType")]
    pub instance_type: String,

    #[serde(rename = "clusterSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_spec: Option<ClusterSpec>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterSpec {
    #[serde(rename = "type")]
    pub cluster_type: String,

    pub version: String,

    #[serde(rename = "initialInstanceCount")]
    pub initial_instance_count: u32,

    pub ports: String,

    #[serde(rename = "bootstrapScript")]
    pub bootstrap_script: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessSpec {
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,

    // TODO: enum?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    // TODO: enum?
    #[serde(rename = "allProjects")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_projects: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<bool>,

    #[serde(rename = "projectCreation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_creation: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsApp {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u32>,

    #[serde(rename = "sharedAccess")]
    pub shared_access: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InputSpec {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    pub class: InputOutputClass,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,

    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<InputSpecSuggestion>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InputSpecSuggestion {
    pub name: String,

    pub project: String,

    pub path: String,

    pub region: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    pub name: String,

    pub class: InputOutputClass,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<Interpreter>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    pub distribution: LinuxDistribution,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<LinuxRelease>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<LinuxVersion>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    #[serde(rename = "headJobOnDemand")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_job_on_demand: Option<bool>,

    #[serde(rename = "restartableEntryPoints")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restartable_entry_points: Option<String>,

    #[serde(rename = "assetDepends")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_depends: Option<HashMap<String, String>>,

    #[serde(default, rename = "execDepends")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exec_depends: Vec<ExecDepends>,

    #[serde(rename = "timeoutPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_policy: Option<HashMap<String, HashMap<TimeoutUnit, u32>>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExecDepends {
    pub name: String,

    #[serde(alias = "packageManager")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<PackageManager>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
}

// --------------------------------------------------
pub fn parse<T: for<'a> Deserialize<'a>>(filename: &str) -> Result<T> {
    match File::open(filename) {
        Err(e) => bail!("Failed to open \"{filename}\": {e}"),

        Ok(mut file) => {
            let mut contents = String::new();
            let _ = &file.read_to_string(&mut contents)?;
            Ok(serde_json::from_str::<T>(&contents)?)
        }
    }
}

// --------------------------------------------------
pub fn write_file<T: Serialize>(object: &T, filename: &str) -> Result<()> {
    let fh = open_output(filename)?;
    serde_json::to_writer_pretty(fh, object)?;
    Ok(())
}

// --------------------------------------------------
fn open_output(filename: &str) -> Result<Box<dyn Write>> {
    match filename {
        "-" => Ok(Box::new(io::stdout())),
        filename => Ok(Box::new(File::create(filename)?)),
    }
}

// --------------------------------------------------
pub fn lint_asset(asset: &DxAsset) -> Vec<String> {
    let mut suggestions: Vec<String> = vec![];

    if let Some(s) = lint_version(&asset.version) {
        suggestions.push(s);
    }

    suggestions
}

// --------------------------------------------------
pub fn lint_app(app: &DxApp) -> Vec<String> {
    let mut suggestions: Vec<String> = vec![];

    if let Some(s) = lint_version(&app.version) {
        suggestions.push(s);
    }

    if let Some(s) = lint_app_categories(&app.categories) {
        suggestions.push(s);
    }

    if let Some(s) = lint_app_release_version(&app.run_spec) {
        suggestions.push(s);
    }

    if let Some(access_spec) = &app.access {
        let mut res = lint_app_access_spec(access_spec);
        if !res.is_empty() {
            suggestions.append(&mut res);
        }
    }

    if let Some(regional_options) = &app.regional_options {
        let mut res = lint_app_regional_options(regional_options);
        if !res.is_empty() {
            suggestions.append(&mut res);
        }
    }

    suggestions
}

// --------------------------------------------------
fn lint_app_categories(categories: &[String]) -> Option<String> {
    let bad: Vec<String> = categories
        .iter()
        .filter(|cat| !VALID_CATEGORIES.contains(&cat.as_str()))
        .cloned()
        .collect();

    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "Invalid categor{}: {}",
            if bad.len() > 1 { "ies" } else { "y" },
            bad.join(", ")
        ))
    }
}

// --------------------------------------------------
fn lint_app_release_version(run_spec: &RunSpec) -> Option<String> {
    if run_spec.release == Some(LinuxRelease::V20_04)
        && run_spec.version == Some(LinuxVersion::V1)
    {
        Some("runSpec.version should be 0 if release is 20.04".to_string())
    } else {
        None
    }
}

// --------------------------------------------------
fn lint_app_regional_options(
    opts: &HashMap<String, RegionalOptions>,
) -> Vec<String> {
    let mut suggestions = vec![];

    for (region_name, opt) in opts.iter() {
        if !VALID_REGION.contains(&region_name.as_str()) {
            suggestions.push(format!("Invalid region \"{region_name}\""));
        }

        let mut s = lint_app_system_requirements(&opt.system_requirements);
        suggestions.append(&mut s);
    }

    suggestions
}

// --------------------------------------------------
fn lint_app_system_requirements(
    req: &HashMap<String, SystemRequirements>,
) -> Vec<String> {
    let mut suggestions = vec![];

    for (_, req) in req.iter() {
        let instance = &req.instance_type;

        if !VALID_INSTANCE_TYPE.contains(&instance.as_str()) {
            suggestions.push(format!("Invalid instance type \"{instance}\""));
        }

        if let Some(cluster_spec) = &req.cluster_spec {
            let mut s = lint_app_cluster_spec(cluster_spec);
            suggestions.append(&mut s);
        }
    }

    suggestions
}

// --------------------------------------------------
fn lint_app_cluster_spec(cluster_spec: &ClusterSpec) -> Vec<String> {
    let mut suggestions = vec![];

    if cluster_spec.initial_instance_count < 1 {
        suggestions.push(
            "initialInstanceCount should be greater than zero".to_string(),
        );
    }

    let version = &cluster_spec.version;
    if !VALID_CLUSTER_SPEC_VERSION.contains(&version.as_str()) {
        suggestions
            .push(format!("Invalid cluster spec version \"{version}\""));
    }

    let cluster_type = &cluster_spec.cluster_type;
    if !VALID_CLUSTER_SPEC_TYPE.contains(&cluster_type.as_str()) {
        suggestions
            .push(format!("Invalid cluster spec type \"{cluster_type}\""));
    }

    suggestions
}

// --------------------------------------------------
fn lint_app_access_spec(access: &AccessSpec) -> Vec<String> {
    let mut res = vec![];

    if let Some(project) = &access.project {
        if !VALID_ACCESS_SPEC_OPTIONS.contains(&project.as_str()) {
            res.push(format!("Invalid project access \"{project}\""));
        }
    }

    if let Some(all_projects) = &access.all_projects {
        if !VALID_ACCESS_SPEC_OPTIONS.contains(&all_projects.as_str()) {
            res.push(format!(
                "Invalid allProjects access \"{all_projects}\""
            ));
        }
    }

    res
}

// --------------------------------------------------
pub fn lint_version(version: &Option<String>) -> Option<String> {
    version.as_ref().and_then(|v| {
        let re = Regex::new(r"^\d+\.\d+\.\d+$").unwrap();
        if re.is_match(v) {
            None
        } else {
            Some(format!("Version \"{v}\" should be SemVar"))
        }
    })
}

// --------------------------------------------------
#[cfg(test)]
mod tests {

    use super::{
        lint_app_access_spec, lint_app_categories, lint_app_cluster_spec,
        lint_app_regional_options, lint_app_release_version,
        lint_app_system_requirements, parse, AccessSpec, ClusterSpec, DxApp,
        DxAsset, Interpreter, LinuxDistribution, LinuxRelease, LinuxVersion,
        RegionalOptions, RunSpec, SystemRequirements,
    };
    use anyhow::{bail, Result};
    use std::collections::HashMap;

    #[test]
    fn test_lint_app_categories() {
        assert!(
            lint_app_categories(&["Annotation".to_string()]).is_none()
        );

        let res = lint_app_categories(&["Bad".to_string()]);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), "Invalid category: Bad");

        let res = lint_app_categories(&["Bad1".to_string(),
            "Bad2".to_string()]);
        assert!(res.is_some());
        assert_eq!(res.unwrap(), "Invalid categories: Bad1, Bad2");
    }

    #[test]
    fn test_lint_app_release_version() {
        let run_spec1 = RunSpec {
            interpreter: Some(Interpreter::Python3),
            file: Some("run.sh".to_string()),
            distribution: LinuxDistribution::Ubuntu,
            release: Some(LinuxRelease::V16_04),
            version: Some(LinuxVersion::V0),
            code: None,
            head_job_on_demand: None,
            restartable_entry_points: None,
            asset_depends: None,
            exec_depends: vec![],
            timeout_policy: None,
        };

        assert!(lint_app_release_version(&run_spec1).is_none());

        let run_spec2 = RunSpec {
            version: Some(LinuxVersion::V1),
            ..run_spec1
        };

        assert!(lint_app_release_version(&run_spec2).is_none());

        let run_spec3 = RunSpec {
            release: Some(LinuxRelease::V20_04),
            version: Some(LinuxVersion::V0),
            ..run_spec2
        };

        assert!(lint_app_release_version(&run_spec3).is_none());

        let run_spec4 = RunSpec {
            release: Some(LinuxRelease::V20_04),
            version: Some(LinuxVersion::V1),
            ..run_spec3
        };

        let res = lint_app_release_version(&run_spec4);
        assert!(res.is_some());
        assert_eq!(
            res.unwrap(),
            "runSpec.version should be 0 if release is 20.04".to_string()
        );
    }

    #[test]
    fn test_lint_app_access_spec() {
        let access_spec1 = AccessSpec {
            network: vec![],
            project: Some("VIEW".to_string()),
            all_projects: Some("ADMINISTER".to_string()),
            developer: None,
            project_creation: None,
        };

        assert!(lint_app_access_spec(&access_spec1).is_empty());

        let access_spec2 = AccessSpec {
            project: Some("BAD".to_string()),
            ..access_spec1
        };

        let res = lint_app_access_spec(&access_spec2);

        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid project access \"BAD\"".to_string()]);

        let access_spec3 = AccessSpec {
            project: Some("UPLOAD".to_string()),
            all_projects: Some("BAD".to_string()),
            ..access_spec2
        };

        let res = lint_app_access_spec(&access_spec3);

        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid allProjects access \"BAD\"".to_string()]);
    }

    #[test]
    fn test_lint_app_regional_options() {
        let req = SystemRequirements {
            instance_type: "mem1_ssd1_x2".to_string(),
            cluster_spec: None,
        };

        let opt = RegionalOptions {
            resources: None,
            system_requirements: HashMap::from([("*".to_string(), req)]),
        };

        let res = lint_app_regional_options(&HashMap::from([(
            "aws:us-east-1".to_string(),
            opt,
        )]));
        assert!(res.is_empty());

        let req = SystemRequirements {
            instance_type: "mem1_ssd1_x2".to_string(),
            cluster_spec: None,
        };

        let opt = RegionalOptions {
            resources: None,
            system_requirements: HashMap::from([("*".to_string(), req)]),
        };

        let res = lint_app_regional_options(&HashMap::from([(
            "BAD".to_string(),
            opt,
        )]));
        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid region \"BAD\"".to_string()]);
    }

    #[test]
    fn test_lint_app_system_requirements() {
        let req1 = SystemRequirements {
            instance_type: "mem1_ssd1_x2".to_string(),
            cluster_spec: None,
        };

        let res = lint_app_system_requirements(&HashMap::from([(
            "*".to_string(),
            req1,
        )]));

        assert!(res.is_empty());

        let req2 = SystemRequirements {
            instance_type: "BAD".to_string(),
            cluster_spec: None,
        };

        let res = lint_app_system_requirements(&HashMap::from([(
            "*".to_string(),
            req2,
        )]));

        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid instance type \"BAD\""]);
    }

    #[test]
    fn test_lint_app_cluster_spec() {
        let spec1 = ClusterSpec {
            cluster_type: "generic".to_string(),
            version: "2.4.4".to_string(),
            initial_instance_count: 1,
            ports: "".to_string(),
            bootstrap_script: "".to_string(),
        };

        assert!(lint_app_cluster_spec(&spec1).is_empty());

        let spec2 = ClusterSpec {
            cluster_type: "BAD".to_string(),
            ..spec1
        };

        let res = lint_app_cluster_spec(&spec2);
        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid cluster spec type \"BAD\""]);

        let spec3 = ClusterSpec {
            cluster_type: "dxspark".to_string(),
            version: "BAD".to_string(),
            ..spec2
        };

        let res = lint_app_cluster_spec(&spec3);
        assert!(!res.is_empty());
        assert_eq!(res, ["Invalid cluster spec version \"BAD\""]);

        let spec4 = ClusterSpec {
            initial_instance_count: 0,
            version: "3.2.0".to_string(),
            ..spec3
        };

        let res = lint_app_cluster_spec(&spec4);
        assert!(!res.is_empty());
        assert_eq!(res, ["initialInstanceCount should be greater than zero"]);
    }

    #[test]
    fn parse_bad_app_fails() -> Result<()> {
        match parse::<DxApp>("./tests/inputs/json_app/bad.json") {
            Err(_) => Ok(()),
            _ => bail!("Expected failure on bad.json"),
        }
    }

    #[test]
    fn parse_empty_app_fails() -> Result<()> {
        match parse::<DxApp>("./tests/inputs/json_app/empty.json") {
            Err(_) => Ok(()),
            _ => bail!("Expected failure on empty.json"),
        }
    }

    #[test]
    fn parse_app_minimal() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/minimal.json")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file1() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.1")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file2() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.2")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file3() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.3")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file4() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.4")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file5() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.5")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file6() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.6")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file7() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.7")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file8() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.8")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file9() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.9")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file10() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.10")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file11() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.11")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file12() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.12")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file13() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.13")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file14() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.14")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file15() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.15")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file16() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.16")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_app_file17() -> Result<()> {
        parse::<DxApp>("./tests/inputs/json_app/dxapp.json.17")?;
        Ok(())
    }

    // --------------------------------------------------
    #[test]
    fn parse_asset_file1() -> Result<()> {
        parse::<DxAsset>("./tests/inputs/json_asset/dxasset1.json")?;
        Ok(())
    }

    //#[test]
    //fn outfile() -> TestResult {
    //    let expected = fs::read_to_string("./tests/outputs/dxapp.json.1")?;
    //    let outfile = NamedTempFile::new()?;
    //    let outpath = &outfile.path().to_str().unwrap();

    //    Command::cargo_bin(PRG)?
    //        .args(&["./tests/inputs/dxapp.json.1", "-o", outpath])
    //        .assert()
    //        .success();

    //    let contents = fs::read_to_string(&outpath)?;
    //    assert_eq!(&expected, &contents);

    //    Ok(())
    //}
}
