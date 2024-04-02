// SPDX-License-Identifier: GPL-2.0-only

use clap::{Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use std::process::ExitCode;

pub mod bpf;
pub mod hidudev;
pub mod modalias;

// FIXME: how can we make this configurable?
static DEFAULT_BPF_DIRS: &[&str] = &["/usr/local/lib/firmware/hid/bpf", "/lib/firmware/hid/bpf"];

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
    /// List available devices
    ListDevices {},
    /// Inspect a bpf.o file
    Inspect {
        /// One or more paths to a bpf.o file
        paths: Vec<std::path::PathBuf>,
    },
}

fn default_bpf_dirs() -> Vec<std::path::PathBuf> {
    let bpf_dir = std::path::PathBuf::from("target/bpf");
    if bpf_dir.exists() {
        vec![bpf_dir]
    } else {
        DEFAULT_BPF_DIRS
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    }
}

fn cmd_add(
    syspath: &std::path::PathBuf,
    prog: Option<String>,
    bpfdir: Option<std::path::PathBuf>,
) -> std::io::Result<()> {
    let dev = hidudev::HidUdev::from_syspath(syspath)?;
    let target_bpf_dirs = match bpfdir {
        Some(bpf_dir) => vec![bpf_dir],
        None => default_bpf_dirs(),
    };

    dev.load_bpf_from_directories(&target_bpf_dirs, prog)
}

fn sysname_from_syspath(syspath: &std::path::PathBuf) -> std::io::Result<String> {
    let re = Regex::new(r"[A-Z0-9]{4}:[A-Z0-9]{4}:[A-Z0-9]{4}\.[A-Z0-9]{4}").unwrap();
    let abspath = std::fs::read_link(syspath).unwrap_or(syspath.clone());
    abspath
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|d| re.captures(d).is_some())
        .map(String::from)
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
    let dirs = match bpfdir {
        Some(bpf_dir) => vec![bpf_dir],
        None => default_bpf_dirs(),
    };
    for dir in dirs {
        println!(
            "Showing available BPF files in {}:",
            dir.as_path().to_str().unwrap()
        );
        for entry in std::fs::read_dir(dir)?
            .flatten()
            .filter(|f| f.metadata().unwrap().is_file())
            .map(|e| e.path())
            .filter(|p| p.to_str().unwrap().ends_with(".bpf.o"))
        {
            println!(" {}", entry.to_str().unwrap());
        }
    }

    println!("Use udev-hid-bpf inspect <file> to obtain more information about a BPF object file.");
    Ok(())
}

fn cmd_list_devices() -> std::io::Result<()> {
    let re = Regex::new(r"hid:b([A-Z0-9]{4})g([A-Z0-9]{4})v0000([A-Z0-9]{4})p0000([A-Z0-9]{4})")
        .unwrap();

    println!("devices:");
    // We use this path because it looks nicer than the true device path in /sys/devices/pci...
    for entry in std::fs::read_dir("/sys/bus/hid/devices")? {
        let syspath = entry.unwrap().path();
        let device = udev::Device::from_syspath(&syspath)?;
        let name = device.property_value("HID_NAME").unwrap().to_str().unwrap();
        if let Some(Some(matches)) = device
            .property_value("MODALIAS")
            .map(|modalias| re.captures(modalias.to_str().unwrap()))
        {
            let bus = matches.get(1).unwrap().as_str();
            let group = matches.get(2).unwrap().as_str();
            let vid = matches.get(3).unwrap().as_str();
            let pid = matches.get(4).unwrap().as_str();

            let bus = match bus {
                "0001" => "BUS_PCI",
                "0002" => "BUS_ISAPNP",
                "0003" => "BUS_USB",
                "0004" => "BUS_HIL",
                "0005" => "BUS_BLUETOOTH",
                "0006" => "BUS_VIRTUAL",
                "0010" => "BUS_ISA",
                "0011" => "BUS_I8042",
                "0012" => "BUS_XTKBD",
                "0013" => "BUS_RS232",
                "0014" => "BUS_GAMEPORT",
                "0015" => "BUS_PARPORT",
                "0016" => "BUS_AMIGA",
                "0017" => "BUS_ADB",
                "0018" => "BUS_I2C",
                "0019" => "BUS_HOST",
                "001A" => "BUS_GSC",
                "001B" => "BUS_ATARI",
                "001C" => "BUS_SPI",
                "001D" => "BUS_RMI",
                "001E" => "BUS_CEC",
                "001F" => "BUS_INTEL_ISHTP",
                "0020" => "BUS_AMD_SFH",
                _ => bus,
            };

            let group = match group {
                "0001" => "HID_GROUP_GENERIC",
                "0002" => "HID_GROUP_MULTITOUCH",
                "0003" => "HID_GROUP_SENSOR_HUB",
                "0004" => "HID_GROUP_MULTITOUCH_WIN_8",
                "0100" => "HID_GROUP_RMI",
                "0101" => "HID_GROUP_WACOM",
                "0102" => "HID_GROUP_LOGITECH_DJ_DEVICE",
                "0103" => "HID_GROUP_STEAM",
                "0104" => "HID_GROUP_LOGITECH_27MHZ_DEVICE",
                "0105" => "HID_GROUP_VIVALDI",
                _ => group,
            };

            println!("  -  syspath:      \"{}\"", syspath.to_str().unwrap());
            println!("     name:         \"{name}\"");
            println!("     device entry: \"HID_DEVICE({bus}, {group}, 0x{vid}, 0x{pid})\"");
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct InspectionDevice {
    bus: String,
    group: String,
    vid: String,
    pid: String,
}

#[derive(Serialize)]
struct InspectionProgram {
    name: String,
    section: String,
}

#[derive(Serialize)]
struct InspectionMap {
    name: String,
}

#[derive(Serialize)]
struct InspectionData {
    filename: String,
    devices: Vec<InspectionDevice>,
    programs: Vec<InspectionProgram>,
    maps: Vec<InspectionMap>,
}

fn cmd_inspect(paths: &Vec<std::path::PathBuf>) -> std::io::Result<()> {
    let mut objects = Vec::new();
    for path in paths {
        match libbpf_rs::btf::Btf::from_path(path) {
            Ok(btf) => {
                let mut data = InspectionData {
                    filename: String::from(path.file_name().unwrap().to_string_lossy()),
                    devices: Vec::new(),
                    programs: Vec::new(),
                    maps: Vec::new(),
                };
                if let Some(metadata) = modalias::Metadata::from_btf(&btf) {
                    for modalias in metadata.modaliases() {
                        data.devices.push(InspectionDevice {
                            bus: format!("0x{:04X}", modalias.bus),
                            group: format!("0x{:04X}", modalias.group),
                            vid: format!("0x{:04X}", modalias.vid),
                            pid: format!("0x{:04X}", modalias.pid),
                        });
                    }
                }

                let mut obj_builder = libbpf_rs::ObjectBuilder::default();
                let object = obj_builder.open_file(path.clone()).unwrap();

                for prog in object.progs_iter() {
                    data.programs.push(InspectionProgram {
                        name: prog.name().unwrap().to_string(),
                        section: prog.section().to_string(),
                    })
                }

                for map in object.maps_iter() {
                    data.maps.push(InspectionMap {
                        name: map.name().unwrap().to_string(),
                    })
                }

                objects.push(data);
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            }
        }
    }
    let json = serde_json::to_string_pretty(&objects)?;
    println!("{}", json);
    Ok(())
}

fn main() -> ExitCode {
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
        .modules(vec![module_path!(), "libbpf", "HID-BPF metadata"])
        .verbosity(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init()
        .unwrap();

    let rc = match cli.command {
        Commands::Add {
            devpath,
            prog,
            bpfdir,
        } => cmd_add(&devpath, prog, bpfdir),
        Commands::Remove { devpath } => cmd_remove(&devpath),
        Commands::ListBpfPrograms { bpfdir } => cmd_list_bpf_programs(bpfdir),
        Commands::ListDevices {} => cmd_list_devices(),
        Commands::Inspect { paths } => cmd_inspect(&paths),
    };

    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e.kind());
            ExitCode::FAILURE
        }
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
