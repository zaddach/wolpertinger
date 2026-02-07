#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::Result;
use clap::Parser;
use env_logger::Env;
use log::info;

use wolpertinger::cli::Cli;
use wolpertinger::{EmuConfig, EmuCore};

fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(Env::default().default_filter_or(&cli.log_level)).init();

    info!("Starting wolpertinger with {}", cli.binary.display());

    let config = EmuConfig::from_cli(&cli)?;
    let mut core = EmuCore::new(config)?;
    core.run()?;

    Ok(())
}
