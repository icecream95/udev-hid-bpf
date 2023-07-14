// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, Subcommand};
use libbpf_rs;
use log;

pub mod bpf;
pub mod hidudev;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Folder to look at for bpf objects
    #[arg(short, long)]
    bpf: Option<std::path::PathBuf>,
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
    device: std::path::PathBuf,
}

fn print_to_log(level: libbpf_rs::PrintLevel, msg: String) {
    match level {
        libbpf_rs::PrintLevel::Debug => log::debug!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Info => log::info!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Warn => log::warn!(target: "libbpf", "{}", msg.trim()),
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// A new device is created
    Add {
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpf: Option<std::path::PathBuf>,
    },
    /// A device is removed from the sysfs
    Remove,
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    libbpf_rs::set_print(Some((
        if cli.debug {
            libbpf_rs::PrintLevel::Debug
        } else {
            libbpf_rs::PrintLevel::Info
        },
        print_to_log,
    )));

    stderrlog::new()
        .modules(vec![module_path!(), "libbpf"])
        .verbosity(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init()
        .unwrap();

    match hidudev::HidUdev::from_syspath(cli.device) {
        Err(e) => Err(e),
        Ok(dev) => match cli.command {
            Commands::Add { bpf } => {
                let target_bpf_dir = match bpf {
                    Some(bpf_dir) => bpf_dir,
                    None => {
                        let bpf_dir = std::path::PathBuf::from("target/bpf");
                        if bpf_dir.exists() {
                            bpf_dir
                        } else {
                            std::path::PathBuf::from("/lib/firmware/hid/bpf")
                        }
                    }
                };

                dev.add_directory(target_bpf_dir)
            }
            Commands::Remove => dev.remove(),
        },
    }
}
