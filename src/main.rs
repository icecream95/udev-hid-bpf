// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, Subcommand};
use libbpf_rs;
use log;
use regex::Regex;

pub mod bpf;
pub mod hidudev;
pub mod modalias;

static DEFAULT_BPF_DIR: &str = "/lib/firmware/hid/bpf";

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
        /// sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        devpath: std::path::PathBuf,
        /// The BPF program to load
        prog: Option<String>,
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpfdir: Option<std::path::PathBuf>,
    },
    /// A device is removed from the sysfs
    Remove {
        /// sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        devpath: std::path::PathBuf,
    },
    /// List currently installed BPF programs
    ListBpfPrograms {
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpfdir: Option<std::path::PathBuf>,
    },
}

fn default_bpf_dir() -> std::path::PathBuf {
    let bpf_dir = std::path::PathBuf::from("target/bpf");
    if bpf_dir.exists() {
        bpf_dir
    } else {
        std::path::PathBuf::from(DEFAULT_BPF_DIR)
    }
}

fn cmd_add(
    syspath: &std::path::PathBuf,
    prog: Option<String>,
    bpfdir: Option<std::path::PathBuf>,
) -> std::io::Result<()> {
    let dev = hidudev::HidUdev::from_syspath(syspath)?;
    let target_bpf_dir = match bpfdir {
        Some(bpf_dir) => bpf_dir,
        None => default_bpf_dir(),
    };

    dev.load_bpf_from_directory(target_bpf_dir, prog)
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

fn cmd_list_bpf_programs(bpfdir: Option<std::path::PathBuf>) -> std::io::Result<()> {
    let dir = bpfdir.or(Some(default_bpf_dir())).unwrap();
    println!(
        "Showing available BPF files in {}:",
        dir.as_path().to_str().unwrap()
    );
    for entry in std::fs::read_dir(dir)? {
        if let Ok(entry) = entry {
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            if name.ends_with(".bpf.o") {
                println!(" {name}");
            }
        }
    }

    Ok(())
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
        Commands::Add {
            devpath,
            prog,
            bpfdir,
        } => cmd_add(&devpath, prog, bpfdir),
        Commands::Remove { devpath } => cmd_remove(&devpath),
        Commands::ListBpfPrograms { bpfdir } => cmd_list_bpf_programs(bpfdir),
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
