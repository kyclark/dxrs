use crate::dxenv::DxEnvironment;
use crate::{
    AnalysisDescribeOptions, AnalysisDescribeResult, AppDescribeOptions,
    AppDescribeResult, AppletDescribeOptions, AppletDescribeResult,
    AuthToken, ContainerDescribeOptions, ContainerDescribeResult,
    Credentials, DatabaseDescribeOptions, DatabaseDescribeResult,
    DownloadOptions, DownloadResponse, DxErrorResponse, FileCloseOptions,
    FileCloseResponse, FileDescribeOptions, FileDescribeResult,
    FileNewOptions, FileNewResponse, FileUploadOptions, FileUploadResponse,
    FindAppsOptions, FindAppsResponse, FindAppsResult, FindDataOptions,
    FindDataResponse, FindDataResult, FindProjectsOptions,
    FindProjectsResponse, FindProjectsResult, JobDescribeOptions,
    JobDescribeResult, ListFolderOptions, ListFolderResult,
    MakeFolderOptions, MakeFolderResult, NewProjectOptions, NewProjectResult,
    ProjectDescribeOptions, ProjectDescribeResult, RecordDescribeOptions,
    RecordDescribeResult, RmOptions, RmProjectOptions, RmProjectResult,
    RmResult, RmdirOptions, RmdirResult, WatchOptions, WhoAmIOptions,
    WhoAmIResult,
};

//WatchResult,

use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use log::debug;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, StatusCode,
};
use serde::Serialize;
use sha256::digest;
use std::io::Write;
//use textnonce::TextNonce;

//use futures_util::{SinkExt, StreamExt};
//use http::Uri;
//use tokio::net::TcpListener;
//use tokio_websockets::{ClientBuilder, Error, Message, ServerBuilder};

#[derive(Debug, Serialize)]
struct LogoutPayload {
    #[serde(rename = "tokenSignature")]
    token_signature: String,
}

const API_SERVER_PROTOCOL: &str = "https";
const API_SERVER: &str = "api.dnanexus.com";
const AUTH_SERVER: &str = "https://auth.dnanexus.com";

// --------------------------------------------------
#[tokio::main]
pub async fn describe_analysis(
    dx_env: &DxEnvironment,
    analysis_id: &str,
    options: &AnalysisDescribeOptions,
) -> Result<AnalysisDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, analysis_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_app(
    dx_env: &DxEnvironment,
    app_id: &str,
    options: &AppDescribeOptions,
) -> Result<AppDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, app_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_applet(
    dx_env: &DxEnvironment,
    applet_id: &str,
    options: &AppletDescribeOptions,
) -> Result<AppletDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, applet_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        //StatusCode::OK => Ok(res.json::<AppletDescribeResult>().await?),
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
//#[tokio::main]
//pub async fn describe<'a, T: serde::Serialize, R: serde::Deserialize<'a>>(
//    url: &str,
//    auth_token: &str,
//    options: &T,
//) -> Result<R> {
//    let client = Client::new();
//    let req = client.post(url).bearer_auth(&auth_token).json(&options);
//    let res = req.send().await?;

//    match res.status() {
//        StatusCode::OK => {
//            let t = &res.text().await?;
//            debug!("{}", &t);
//            Ok(serde_json::from_str(&t)?)
//        }
//        _ => {
//            let text = res.text().await?;
//            match serde_json::from_str::<DxErrorResponse>(&text) {
//                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
//                _ => bail!("{text}"),
//            }
//        }
//    }
//}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_container(
    dx_env: &DxEnvironment,
    container_id: &str,
    options: &ContainerDescribeOptions,
) -> Result<ContainerDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, container_id
    );

    //describe(&url, &dx_env.auth_token, &options)

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_database(
    dx_env: &DxEnvironment,
    database_id: &str,
    options: &DatabaseDescribeOptions,
) -> Result<DatabaseDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, database_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_file(
    dx_env: &DxEnvironment,
    file_id: &str,
    options: &FileDescribeOptions,
) -> Result<FileDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, file_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_job(
    dx_env: &DxEnvironment,
    job_id: &str,
    options: &JobDescribeOptions,
) -> Result<JobDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, job_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_project(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: &ProjectDescribeOptions,
) -> Result<ProjectDescribeResult> {
    // https://documentation.dnanexus.com/developer/api/data-containers/
    // projects#api-method-project-xxxx-describe
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        //StatusCode::OK => Ok(res.json::<ProjectDescribeResult>().await?),
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn describe_record(
    dx_env: &DxEnvironment,
    record_id: &str,
    options: &RecordDescribeOptions,
) -> Result<RecordDescribeResult> {
    let url = format!(
        "{}://{}/{}/describe",
        API_SERVER_PROTOCOL, API_SERVER, record_id
    );

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn download(
    dx_env: &DxEnvironment,
    file_id: &str,
    options: &DownloadOptions,
) -> Result<DownloadResponse> {
    let url =
        format!("{API_SERVER_PROTOCOL}://{API_SERVER}/{file_id}/download");

    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn download_file(
    options: &DownloadResponse,
    mut file: impl Write,
    filename: &str,
    quiet: bool,
) -> Result<()> {
    let client = Client::new();
    let mut headers = HeaderMap::new();
    for (key, val) in &options.headers {
        headers.insert(
            HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_str(val)?,
        );
    }

    let res = client
        .get(options.url.clone())
        .headers(headers)
        .send()
        .await?;

    let total_size = res.content_length().ok_or(anyhow!(
        "Failed to get content length from '{}'",
        &options.url
    ))?;

    let progress = if quiet {
        None
    } else {
        let pb = ProgressBar::new(total_size);
        let template = "{msg}\n{spinner:.green} [{elapsed_precise}] \
            [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} \
            ({bytes_per_sec}, {eta})";

        pb.set_style(
            ProgressStyle::default_bar()
                .template(template)?
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Downloading {filename}"));
        Some(pb)
    };

    match res.status() {
        StatusCode::OK => {
            let mut downloaded: u64 = 0;
            let mut stream = res.bytes_stream();

            while let Some(item) = stream.next().await {
                let chunk =
                    item.or(Err(anyhow!("Error while downloading file")))?;

                file.write_all(&chunk)
                    .or(Err(anyhow!("Error while writing to file")))?;

                let new = std::cmp::min(
                    downloaded + (chunk.len() as u64),
                    total_size,
                );
                downloaded = new;
                if let Some(pb) = progress.as_ref() {
                    pb.set_position(new)
                }
            }

            if let Some(pb) = progress {
                pb.finish_with_message("Finished")
            }
            Ok(())
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn find_apps(
    dx_env: &DxEnvironment,
    options: &mut FindAppsOptions,
) -> Result<Vec<FindAppsResult>> {
    // https://documentation.dnanexus.com/developer/api/search#
    // api-method-system-findapps

    let url =
        format!("{}://{}/system/findApps", API_SERVER_PROTOCOL, API_SERVER);
    let client = Client::new();
    let mut apps: Vec<FindAppsResult> = vec![];

    loop {
        let req = client
            .post(&url)
            .bearer_auth(&dx_env.auth_token)
            .json(&options);
        let res = req.send().await?;

        match res.status() {
            StatusCode::OK => {
                let text = &res.text().await?;
                debug!("{}", &text);
                let response: FindAppsResponse = serde_json::from_str(text)?;

                let mut data: Vec<FindAppsResult> =
                    response.results.into_iter().collect();

                if !data.is_empty() {
                    apps.append(&mut data);
                }

                if response.next.is_some() {
                    options.starting = response.next.clone()
                } else {
                    break;
                }
            }
            _ => {
                let text = res.text().await?;
                match serde_json::from_str::<DxErrorResponse>(&text) {
                    Ok(e) => {
                        bail!("{}: {}", e.error.error_type, e.error.message)
                    }
                    _ => {
                        bail!("{text}")
                    }
                }
            }
        }
    }

    Ok(apps)
}

// --------------------------------------------------
#[tokio::main]
pub async fn find_data(
    dx_env: &DxEnvironment,
    options: &mut FindDataOptions,
) -> Result<Vec<FindDataResult>> {
    // https://documentation.dnanexus.com/developer/api/search#
    // api-method-system-finddataobjects

    let url = format!(
        "{}://{}/system/findDataObjects",
        API_SERVER_PROTOCOL, API_SERVER
    );
    let client = Client::new();
    let mut apps: Vec<FindDataResult> = vec![];

    loop {
        let req = client
            .post(&url)
            .bearer_auth(&dx_env.auth_token)
            .json(&options);
        let res = req.send().await?;

        match res.status() {
            StatusCode::OK => {
                let text = &res.text().await?;
                debug!("{}", &text);
                let response: FindDataResponse = serde_json::from_str(text)?;

                let mut data: Vec<FindDataResult> =
                    response.results.into_iter().collect();

                if !data.is_empty() {
                    apps.append(&mut data);
                }

                if response.next.is_some() {
                    options.starting = response.next.clone()
                } else {
                    break;
                }
            }
            _ => {
                let text = res.text().await?;
                match serde_json::from_str::<DxErrorResponse>(&text) {
                    Ok(e) => {
                        bail!("{}: {}", e.error.error_type, e.error.message)
                    }
                    _ => {
                        bail!("{text}")
                    }
                }
            }
        }
    }

    Ok(apps)
}

// --------------------------------------------------
#[tokio::main]
pub async fn find_projects(
    dx_env: &DxEnvironment,
    mut options: FindProjectsOptions,
) -> Result<Vec<FindProjectsResult>> {
    // https://documentation.dnanexus.com/developer/api/search#
    // api-method-system-findprojects

    let url = format!(
        "{}://{}/system/findProjects",
        API_SERVER_PROTOCOL, API_SERVER
    );
    let client = Client::new();
    let mut projects: Vec<FindProjectsResult> = vec![];

    loop {
        let req = client
            .post(&url)
            .bearer_auth(&dx_env.auth_token)
            .json(&options);
        let res = req.send().await?;

        match res.status() {
            StatusCode::OK => {
                let response = res.json::<FindProjectsResponse>().await?;

                let mut data: Vec<FindProjectsResult> =
                    response.results.into_iter().collect();

                if !data.is_empty() {
                    projects.append(&mut data);
                }

                if response.next.is_some() {
                    options.starting = response.next.clone()
                } else {
                    break;
                }
            }
            _ => {
                let text = res.text().await?;
                match serde_json::from_str::<DxErrorResponse>(&text) {
                    Ok(e) => {
                        bail!("{}: {}", e.error.error_type, e.error.message)
                    }
                    _ => {
                        bail!("{text}")
                    }
                }
            }
        }
    }

    Ok(projects)
}

// --------------------------------------------------
#[tokio::main]
pub async fn ls(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: ListFolderOptions,
) -> Result<ListFolderResult> {
    // https://documentation.dnanexus.com/developer/api/data-containers/
    // folders-and-deletion#api-method-class-xxxx-listfolder
    //println!("{}", serde_json::to_string(&options)?);
    let url = format!(
        "{}://{}/{}/listFolder",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );
    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn logout(dx_env: &DxEnvironment) -> Result<()> {
    let url = format!("{AUTH_SERVER}/system/destroyAuthToken");
    let client = Client::new();
    let payload = LogoutPayload {
        token_signature: digest(&dx_env.auth_token),
    };
    let res = client
        .post(url)
        .bearer_auth(&dx_env.auth_token)
        .json(&payload)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn login(
    username: &str,
    password: &str,
    _token: Option<String>,
) -> Result<AuthToken> {
    let url = format!("{AUTH_SERVER}/system/newAuthToken");
    let client = Client::new();
    let cred = Credentials {
        username: username.to_string(),
        password: password.to_string(),
    };
    let res = client.post(url).json(&cred).send().await?;
    let token = res.json::<AuthToken>().await?;
    Ok(token)
}

// --------------------------------------------------
#[tokio::main]
pub async fn mkdir(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: MakeFolderOptions,
) -> Result<MakeFolderResult> {
    let url = format!(
        "{}://{}/{}/newFolder",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );
    debug!("{}", &url);

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn new_project(
    dx_env: &DxEnvironment,
    options: NewProjectOptions,
) -> Result<NewProjectResult> {
    let url = format!("{}://{}/project/new", API_SERVER_PROTOCOL, API_SERVER);
    debug!("{}", &url);

    let client = Client::new();
    let req = client
        .post(&url)
        .bearer_auth(&dx_env.auth_token)
        .json(&options);
    let res = req.send().await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn watch(
    _dx_env: &DxEnvironment,
    _job_id: &str,
    _options: &WatchOptions,
) -> Result<()> {
    //) -> Result<WatchResult> {
    //let url = format!("wss://{API_SERVER}:443/{job_id}/getLog/websocket");

    //let listener = TcpListener::bind("127.0.0.1:3000").await?;

    //tokio::spawn(async move {
    //    while let Ok((stream, _)) = listener.accept().await {
    //        let mut ws_stream = ServerBuilder::new().accept(stream).await?;

    //        tokio::spawn(async move {
    //            // Just an echo server, really
    //            while let Some(Ok(msg)) = ws_stream.next().await {
    //                if msg.is_text() || msg.is_binary() {
    //                    ws_stream.send(msg).await?;
    //                }
    //            }

    //            Ok::<_, Error>(())
    //        });
    //    }

    //    Ok::<_, Error>(())
    //});

    //let uri = Uri::from_static("ws://127.0.0.1:3000");
    //let (mut client, _) = ClientBuilder::from_uri(uri).connect().await?;

    //client.send(Message::text("Hello world!")).await?;

    //while let Some(Ok(msg)) = client.next().await {
    //    if let Some(text) = msg.as_text() {
    //        assert_eq!(text, "Hello world!");
    //        // We got one message, just stop now
    //        client.close().await?;
    //    }
    //}

    //let client = Client::new();
    //let res = client
    //    .post(url)
    //    .json(&options)
    //    .bearer_auth(&dx_env.auth_token)
    //    .send()
    //    .await?;

    //dbg!(&res);
    //match res.status() {
    //    StatusCode::OK => {
    //        let t = &res.text().await?;
    //        debug!("{}", &t);
    //        Ok(serde_json::from_str(t)?)
    //    }
    //    _ => {
    //        let text = res.text().await?;
    //        dbg!(&text);
    //        match serde_json::from_str::<DxErrorResponse>(&text) {
    //            Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
    //            _ => bail!("Error: {text}"),
    //        }
    //    }
    //}
    //
    Ok(())
}

// --------------------------------------------------
#[tokio::main]
pub async fn whoami(
    dx_env: &DxEnvironment,
    options: &WhoAmIOptions,
) -> Result<WhoAmIResult> {
    let url =
        format!("{}://{}/system/whoami", API_SERVER_PROTOCOL, API_SERVER);
    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn file_new(
    dx_env: &DxEnvironment,
    options: &FileNewOptions,
) -> Result<FileNewResponse> {
    let url = format!("{}://{}/file/new", API_SERVER_PROTOCOL, API_SERVER);
    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn file_upload(
    dx_env: &DxEnvironment,
    file_id: &str,
    options: &FileUploadOptions,
) -> Result<FileUploadResponse> {
    let url = format!(
        "{}://{}/{}/upload",
        API_SERVER_PROTOCOL, API_SERVER, file_id
    );
    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn file_upload_part(
    options: FileUploadResponse,
    data: Vec<u8>,
) -> Result<()> {
    let client = Client::new();
    let mut headers = HeaderMap::new();
    for (key, val) in &options.headers {
        headers.insert(
            HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_str(val)?,
        );
    }

    let res = client
        .put(options.url.clone())
        .headers(headers)
        .body(data)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => Ok(()),
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn file_close(
    dx_env: &DxEnvironment,
    file_id: &str,
    options: &FileCloseOptions,
) -> Result<FileCloseResponse> {
    let url =
        format!("{}://{}/{}/close", API_SERVER_PROTOCOL, API_SERVER, file_id);
    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn rm(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: &RmOptions,
) -> Result<RmResult> {
    let url = format!(
        "{}://{}/{}/removeObjects",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );

    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn rmdir(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: &RmdirOptions,
) -> Result<RmdirResult> {
    let url = format!(
        "{}://{}/{}/removeFolder",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );

    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
#[tokio::main]
pub async fn rm_project(
    dx_env: &DxEnvironment,
    project_id: &str,
    options: &RmProjectOptions,
) -> Result<RmProjectResult> {
    let url = format!(
        "{}://{}/{}/destroy",
        API_SERVER_PROTOCOL, API_SERVER, project_id
    );

    let client = Client::new();
    let res = client
        .post(url)
        .json(&options)
        .bearer_auth(&dx_env.auth_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let t = &res.text().await?;
            debug!("{}", &t);
            Ok(serde_json::from_str(t)?)
        }
        _ => {
            let text = res.text().await?;
            match serde_json::from_str::<DxErrorResponse>(&text) {
                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
                _ => bail!("{text}"),
            }
        }
    }
}

// --------------------------------------------------
//#[tokio::main]
//pub async fn rm_file(
//    dx_env: &DxEnvironment,
//    file_id: &str,
//    options: &FileCloseOptions,
//) -> Result<FileCloseResponse> {
//    let url =
//        format!("{}://{}/{}/close", API_SERVER_PROTOCOL, API_SERVER, file_id);
//    let client = Client::new();
//    let res = client
//        .post(url)
//        .json(&options)
//        .bearer_auth(&dx_env.auth_token)
//        .send()
//        .await?;

//    match res.status() {
//        StatusCode::OK => {
//            let t = &res.text().await?;
//            debug!("{}", &t);
//            Ok(serde_json::from_str(t)?)
//        }
//        _ => {
//            let text = res.text().await?;
//            dbg!(&text);
//            match serde_json::from_str::<DxErrorResponse>(&text) {
//                Ok(e) => bail!("{}: {}", e.error.error_type, e.error.message),
//                _ => bail!("{text}"),
//            }
//        }
//    }
//}
