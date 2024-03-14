use anyhow::{bail, Result};
use clap::Parser;
use dxrs::{Cli, Command};

// --------------------------------------------------
fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

// --------------------------------------------------
fn run(args: Cli) -> Result<()> {
    env_logger::Builder::new()
        .filter_level(if args.debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Off
        })
        .init();

    match &args.command {
        Some(Command::Build(args)) => {
            dxrs::build(args.clone())?;
            Ok(())
        }
        Some(Command::Cd(args)) => {
            dxrs::cd(args.clone())?;
            Ok(())
        }
        Some(Command::Describe(args)) => {
            dxrs::describe(args.clone())?;
            Ok(())
        }
        Some(Command::Download(args)) => {
            dxrs::download(args.clone())?;
            Ok(())
        }
        Some(Command::Env(args)) => {
            dxrs::print_env(args.clone())?;
            Ok(())
        }
        Some(Command::FindApps(args)) => {
            dxrs::find_apps(args.clone())?;
            Ok(())
        }
        Some(Command::FindData(args)) => {
            dxrs::find_data(args.clone())?;
            Ok(())
        }
        Some(Command::Format(args)) => {
            dxrs::format(args.clone())?;
            Ok(())
        }
        Some(Command::Lint(args)) => {
            dxrs::lint(args.clone())?;
            Ok(())
        }
        Some(Command::Login(args)) => {
            dxrs::login(args.clone())?;
            println!("Login successful");
            Ok(())
        }
        Some(Command::Logout {}) => {
            dxrs::logout()?;
            println!("Logout successful");
            Ok(())
        }
        Some(Command::Ls(args)) => {
            dxrs::ls(args.clone())?;
            Ok(())
        }
        Some(Command::Mkdir(args)) => {
            dxrs::mkdir(args.clone())?;
            Ok(())
        }
        Some(Command::NewProject(args)) => {
            dxrs::new_project(args.clone())?;
            Ok(())
        }
        Some(Command::Pwd {}) => {
            dxrs::pwd()?;
            Ok(())
        }
        Some(Command::RmProject(args)) => {
            dxrs::rm_project(args.clone())?;
            Ok(())
        }
        Some(Command::Rm(args)) => {
            dxrs::rm(args.clone())?;
            Ok(())
        }
        Some(Command::Rmdir(args)) => {
            dxrs::rmdir(args.clone())?;
            Ok(())
        }
        Some(Command::Select(args)) => {
            dxrs::select_project(args.clone())?;
            Ok(())
        }
        Some(Command::Tree(args)) => {
            dxrs::tree(args.clone())?;
            Ok(())
        }
        Some(Command::Upload(args)) => {
            dxrs::upload(args.clone())?;
            Ok(())
        }
        Some(Command::Watch(args)) => {
            dxrs::watch(args.clone())?;
            Ok(())
        }
        Some(Command::Whoami(args)) => {
            dxrs::whoami(args.clone())?;
            Ok(())
        }
        Some(Command::Wizard(args)) => {
            dxrs::wizard(args.clone())?;
            Ok(())
        }
        None => {
            bail!("Run with -h|--help for usage")
        }
    }
}
