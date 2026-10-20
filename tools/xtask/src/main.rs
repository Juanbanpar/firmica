//! Workspace build tasks. Application builds continue to use Dioxus's asset and bundling pipeline.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{env, path::PathBuf, process::Command};

mod desktop;
mod install_dx;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Build the desktop application with its companion worker.
    Build(desktop::Options),
    /// Package the desktop application with its companion worker.
    Bundle(desktop::Options),
    /// Install the checksum-pinned Dioxus CLI used by CI.
    InstallDx,
}

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    match Cli::parse().task {
        Task::Build(options) => desktop::run(&root, false, options),
        Task::Bundle(options) => desktop::run(&root, true, options),
        Task::InstallDx => install_dx::run(),
    }
}

fn run(command: &mut Command) -> Result<()> {
    eprintln!("+ {command:?}");
    let status = command
        .status()
        .with_context(|| format!("could not start {command:?}"))?;
    if !status.success() {
        bail!("{command:?} exited with {status}");
    }
    Ok(())
}
