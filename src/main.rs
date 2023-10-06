// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, Subcommand};
use libbpf_rs;
use log;
use regex::Regex;

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
    /// sysfs path to a device, e.g. /sys/class/hidraw/hidraw0/device
    devpath: std::path::PathBuf,
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

fn cmd_add(syspath: &std::path::PathBuf, bpf: Option<std::path::PathBuf>) -> std::io::Result<()> {
    let dev = hidudev::HidUdev::from_syspath(syspath)?;
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

    dev.load_bpf_from_directory(target_bpf_dir)
}

fn sysname_from_syspath(syspath: &std::path::PathBuf) -> std::io::Result<String> {
    let re = Regex::new(r"[A-Z0-9]{4}:[A-Z0-9]{4}:[A-Z0-9]{4}\.[A-Z0-9]{4}").unwrap();
    let abspath = std::fs::read_link(syspath).unwrap_or(syspath.clone());
    abspath
        .file_name()
        .map(|s| s.to_str())
        .flatten()
        .filter(|d| re.captures(d).is_some())
        .map(|d| String::from(d))
        .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn cmd_remove(syspath: &std::path::PathBuf) -> std::io::Result<()> {
    let sysname = match hidudev::HidUdev::from_syspath(syspath) {
        Ok(dev) => dev.sysname(),
        Err(e) => match e.raw_os_error() {
            Some(libc::ENODEV) => sysname_from_syspath(syspath)?,
            _ => return Err(e),
        },
    };
    bpf::remove_bpf_objects(&sysname)
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

    match cli.command {
        Commands::Add { bpf } => cmd_add(&cli.devpath, bpf),
        Commands::Remove => cmd_remove(&cli.devpath),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysname_resolution() {
        let syspath = "/sys/blah/1234";
        let sysname = sysname_from_syspath(&std::path::PathBuf::from(syspath));
        assert!(sysname.is_err());

        let syspath = "/sys/blah/0003:04F3:2D4A.0001";
        let sysname = sysname_from_syspath(&std::path::PathBuf::from(syspath));
        assert!(sysname.unwrap() == "0003:04F3:2D4A.0001");

        let syspath = "/sys/blah/0003:04F3:2D4A-0001";
        let sysname = sysname_from_syspath(&std::path::PathBuf::from(syspath));
        assert!(sysname.is_err());

        // Only run this test if there's a local hidraw0 device
        let syspath = "/sys/class/hidraw/hidraw0/device";
        if std::path::Path::new(syspath).exists() {
            let sysname = sysname_from_syspath(&std::path::PathBuf::from(syspath));
            assert!(sysname.is_ok());
        }
    }
}
