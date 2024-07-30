// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

pub mod bpf;
pub mod hidudev;
pub mod modalias;

static DEFAULT_BPF_DIRS: &str = env!("BPF_LOOKUP_DIRS");
static BINDIR: &str = env!("MESON_BINDIR");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Folder to look at for bpf objects
    #[arg(short, long)]
    bpf: Option<PathBuf>,
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

fn print_to_log(lvl: libbpf_rs::PrintLevel, msg: String) {
    let level = if msg.contains("skipping unrecognized data section")
        && msg.contains(".hid_bpf_config")
        || msg.contains("skipping relo section")
    {
        libbpf_rs::PrintLevel::Debug
    } else {
        lvl
    };
    match level {
        libbpf_rs::PrintLevel::Debug => log::debug!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Info => log::info!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Warn => log::warn!(target: "libbpf", "{}", msg.trim()),
    }
}

impl TryFrom<&str> for hidudev::HidUdevProperty {
    type Error = clap::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        s.split_once('=')
            .map(|(name, value)| hidudev::HidUdevProperty {
                name: name.into(),
                value: value.into(),
            })
            .and_then(|prop| {
                if prop.name.contains(char::is_whitespace) {
                    None
                } else {
                    Some(prop)
                }
            })
            .ok_or(clap::Error::new(clap::error::ErrorKind::ValueValidation))
    }
}

// For some reason we can't use PropertyTyple::try_from directly in #[arg(value_parser])
fn tuple_parse(s: &str) -> std::result::Result<hidudev::HidUdevProperty, clap::error::Error> {
    hidudev::HidUdevProperty::try_from(s)
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// A new device is created
    Add {
        /// The sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        /// followed by an optional path to a BPF program.
        ///
        /// Multiple devices and/or BPF programs may be specified, use - to separate
        /// device paths from BPF programs.
        #[clap(num_args = 1..)]
        paths: Vec<String>,
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpfdir: Option<PathBuf>,
        /// Remove current BPF programs for the device first.
        /// This is equivalent to running udev-hid-bpf remove with the
        /// same device argument first.
        #[arg(long, default_value_t = false)]
        replace: bool,

        /// Provide an arbitrary NAME=VALUE pair to the BPF program.
        /// This NAME=VALUE pair is treated as if it was a
        /// udev property set on the device, taking precedence over
        /// any udev property of the same name.
        /// This option may be specified multiple times to
        /// supply multiple properties. Empty properties must be
        /// the empty string (NAME="")
        #[arg(short, long, value_parser=tuple_parse)]
        property: Vec<hidudev::HidUdevProperty>,
    },
    /// A device is removed from the sysfs
    Remove {
        /// sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        #[clap(num_args = 1..)]
        devpaths: Vec<PathBuf>,
    },
    /// List currently installed BPF programs
    ListBpfPrograms {
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpfdir: Option<PathBuf>,
    },
    /// List available devices
    ListDevices {},
    /// Inspect a bpf.o file
    Inspect {
        /// One or more paths to a bpf.o file
        paths: Vec<PathBuf>,
    },
    /// Install one bpf.o file.
    ///
    /// The file is installed into /etc/udev-hid-bpf/ with a corresponding udev rule
    /// in /etc/udev/rules.d/. This command should be used for testing a single bpf.o file
    /// and/or in the case where a proper install of udev-hid-bpf is not otherwise suitable.
    ///
    /// This command looks for an existing udev-hid-bpf executable in the configured prefix,
    /// that executable is referenced in the udev rule. Use the --install-exe argument
    /// to install the current executable in that prefix.
    Install {
        /// Path to a bpf.o file
        path: PathBuf,
        /// The prefix, converted to $prefix/bin. Defaults to the compiled-in prefix.
        #[arg(long)]
        prefix: Option<PathBuf>,
        /// Overwrite an existing file with the same name
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Install the udev-hid-bpf executable at the given prefix (if not already installed)
        #[arg(long, default_value_t = false)]
        install_exe: bool,
        /// Do everything except actually creating/installing target files and directories
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

fn default_bpf_dirs() -> Vec<PathBuf> {
    DEFAULT_BPF_DIRS.split(':').map(PathBuf::from).collect()
}

fn cmd_add(
    devices: &[PathBuf],
    objfiles: &[String],
    bpfdir: Option<PathBuf>,
    properties: &[hidudev::HidUdevProperty],
) -> Result<()> {
    let target_bpf_dirs: Vec<PathBuf> = bpfdir.into_iter().chain(default_bpf_dirs()).collect();
    for syspath in devices {
        ensure!(syspath.exists(), "Invalid syspath {syspath:?}");
    }

    for syspath in devices {
        let dev = hidudev::HidUdev::from_syspath(syspath)?;
        if objfiles.is_empty() {
            dev.load_bpf_from_directories(&target_bpf_dirs, None, properties)?;
        } else {
            for objfile in objfiles {
                dev.load_bpf_from_directories(&target_bpf_dirs, Some(objfile), properties)?;
            }
        }
    }

    Ok(())
}

fn sysname_from_syspath(syspath: &PathBuf) -> std::io::Result<String> {
    let re = Regex::new(r"[A-Z0-9]{4}:[A-Z0-9]{4}:[A-Z0-9]{4}\.[A-Z0-9]{4}").unwrap();
    let abspath = std::fs::read_link(syspath).unwrap_or(syspath.clone());
    abspath
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|d| re.captures(d).is_some())
        .map(String::from)
        .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn cmd_remove(syspaths: &Vec<PathBuf>) -> Result<()> {
    for syspath in syspaths {
        let sysname = match hidudev::HidUdev::from_syspath(syspath) {
            Ok(dev) => dev.sysname(),
            Err(e) => match e.raw_os_error() {
                Some(libc::ENODEV) => sysname_from_syspath(syspath)?,
                _ => return Err(e.into()),
            },
        };
        bpf::remove_bpf_objects(&sysname)?;
    }
    Ok(())
}

fn find_bpfs(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    ensure!(dir.exists(), "File or directory {dir:?} does not exist");

    let metadata = dir.metadata().unwrap();
    let result = if metadata.is_file() {
        if dir.to_str().unwrap().ends_with(".bpf.o") {
            return Ok(vec![dir.into()]);
        }
        bail!("Not a bpf.o file");
    } else {
        std::fs::read_dir(dir)?
            .flatten()
            .flat_map(|f| find_bpfs(&f.path()))
            .flatten()
            .collect()
    };

    Ok(result)
}

fn cmd_list_bpf_programs(bpfdir: Option<PathBuf>) -> Result<()> {
    let dirs: Vec<PathBuf> = bpfdir.into_iter().chain(default_bpf_dirs()).collect();
    let files = dirs
        .iter()
        .map(move |dir| (dir, find_bpfs(dir)))
        .filter(|t| matches!(t, (_, Ok(_))))
        .inspect(|t| {
            let (dir, files) = t;
            if !files.as_ref().unwrap().is_empty() {
                println!(
                    "Showing available BPF files in {}:",
                    dir.as_path().to_str().unwrap()
                );
                files
                    .iter()
                    .flatten()
                    .for_each(|f| println!(" {}", f.to_str().unwrap()));
            }
        })
        .flat_map(move |t| t.1.into_iter())
        .flatten()
        .collect::<Vec<PathBuf>>();

    ensure!(!files.is_empty(), "no BPF object file found in {dirs:?}");

    println!("Use udev-hid-bpf inspect <file> to obtain more information about a BPF object file.");
    Ok(())
}

fn cmd_list_devices() -> Result<()> {
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

fn inspect(path: &PathBuf) -> Result<InspectionData> {
    ensure!(path.exists(), "Invalid bpf.o path {path:?}");

    let btf = libbpf_rs::btf::Btf::from_path(path)
        .context(format!("Failed to read BPF from {:?}", path))?;
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

    Ok(data)
}

fn cmd_inspect(paths: &[PathBuf]) -> Result<()> {
    let mut objects: Vec<InspectionData> = Vec::new();
    for path in paths {
        let idata = inspect(path)?;
        objects.push(idata);
    }

    let json = serde_json::to_string_pretty(&objects).context("Failed to parse json")?;
    println!("{}", json);
    Ok(())
}

fn write_udev_rule(
    rulefile: &mut dyn Write,
    bindir: &std::path::Path,
    target: &std::path::Path,
    devices: &[InspectionDevice],
) -> Result<()> {
    let header = r#"# This udev rule was generated by udev-hid-bpf install
ACTION!="add|remove", GOTO="hid_bpf_end"
SUBSYSTEM!="hid", GOTO="hid_bpf_end"
"#;
    let footer = r#"LABEL="hid_bpf_end""#;
    let bindir = bindir.to_string_lossy();

    writeln!(rulefile, "{}", header)?;
    devices.iter().for_each(|dev| {
        let bus = u32::from_str_radix(&dev.bus[2..], 16).unwrap();
        let vid = u32::from_str_radix(&dev.vid[2..], 16).unwrap();
        let pid = u32::from_str_radix(&dev.pid[2..], 16).unwrap();
        let grp = u32::from_str_radix(&dev.group[2..], 16).unwrap();
        let vid = if vid == 0 { String::from("*") } else { format!("{vid:08X}") };
        let pid = if pid == 0 { String::from("*") } else { format!("{pid:08X}") };
        let bus = if bus == 0 { String::from("*") } else { format!("{bus:04X}") };
        let grp = if grp == 0 { String::from("*") } else { format!("{grp:04X}") };
        let kernel_match = format!(r#"ENV{{MODALIAS}}=="hid:b{bus}g{grp}v{vid}p{pid}""#);
        writeln!(
            rulefile,
            r###"# {} "###,
            target.file_name().unwrap().to_string_lossy()
        ).unwrap();
        for action in ["add", "remove"] {
            let bpf_o = match action {
                "add" => target.to_string_lossy().into_owned(),
                "remove" => String::from(""),
                &_ => panic!("Unexpected action") // can't happen
            };
            writeln!(
                rulefile,
                r#"ACTION=="{action}",{kernel_match}, RUN{{program}}+="{bindir}/udev-hid-bpf {action} $sys$devpath {bpf_o}""#
            )
            .unwrap();
        }
    });
    writeln!(rulefile).unwrap();
    writeln!(rulefile, "{}", footer).unwrap();

    Ok(())
}

fn cmd_install(
    path: &PathBuf,
    prefix: Option<PathBuf>,
    force: bool,
    install_exe: bool,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!("This is a dry run, nothing will be created or installed");
    }

    if !path.to_str().unwrap().ends_with(".bpf.o") {
        bail!("Expected a bpf.o file as argument, not {path:?}");
    }

    let idata = inspect(path)?;
    if idata.devices.is_empty() {
        bail!("{path:?} has no HID_DEVICE entries and must be manually attached");
    }

    // udevdir is hardcoded for now, very few use-cases for the rule to be elsewhere
    let udevdir = "/etc/udev/rules.d";
    // bindir is always $prefix/bin unless we use the fallback, then it's whatever meson said
    let bindir = prefix
        .as_ref()
        .map(|p| p.join("bin"))
        .unwrap_or(PathBuf::from(BINDIR));

    // We install ourselves if requested
    let exe = bindir.join("udev-hid-bpf");
    if !exe.exists() {
        if !install_exe {
            bail!("{exe:?} does not exist. Install this project first or use --install-exe");
        }

        println!("Installing myself as {exe:?}");
        if !dry_run {
            let myself = std::env::current_exe().unwrap();
            std::fs::create_dir_all(exe.parent().unwrap())
                .and_then(|_| std::fs::copy(myself, &exe))
                .context("Failed to install myself as {exe:?}: {e}")?;
        }
    }

    let fwdir = PathBuf::from("/etc/udev-hid-bpf/");

    // We know it's .bpf.o suffixed
    let filename: String = path.file_name().unwrap().to_string_lossy().to_string();
    let stem = &filename.strip_suffix(".bpf.o").unwrap();
    let target = fwdir.join(&filename);
    let udevtarget = PathBuf::from(format!("{udevdir}/99-hid-bpf-{stem}.rules"));

    if !force {
        for t in [&target, &udevtarget] {
            ensure!(
                !t.exists(),
                format!("File {t:?} exists, remove first or use --force to overwrite")
            );
        }
    }

    println!("Installing {filename} as {target:?}");
    if !dry_run {
        std::fs::create_dir_all(target.parent().unwrap())
            .and_then(|_| std::fs::copy(path, &target))
            .context(format!("Failed to copy to {:?}", target))?;
    }

    println!("Installing udev rule as {:?}", udevtarget);
    if !dry_run {
        std::fs::create_dir_all(udevdir)?;
        let mut rulefile = std::fs::File::create(&udevtarget)
            .context(format!("Failed to install udev rule {:?}", udevtarget))?;
        write_udev_rule(&mut rulefile, &bindir, &target, &idata.devices)?;
    } else {
        println!("Printing udev rule instead of installing it:");
        println!("---");
        write_udev_rule(&mut std::io::stdout(), &bindir, &target, &idata.devices)?;
        println!("--");
    }

    if !dry_run {
        if let Err(e) = std::process::Command::new("udevadm")
            .args(["control", "--reload"])
            .status()
        {
            eprintln!("WARNING: Failed to run `udevadm control --reload`: {e:#}");
        }
    }

    println!();
    println!("Installation successful. You can now plug in your device.");
    println!("To uninstall, run");
    println!(" $ rm {target:?}");
    println!(" $ rm {udevtarget:?}");
    println!(" $ sudo udevadm control --reload ");
    Ok(())
}

/// Split a list of paths at the occurance of the first '-'
/// element, i.e. [a, b, c, -, d, e] becomes [a, b, c] and [d, e].
fn split_paths(mut paths: Vec<String>) -> Result<(Vec<String>, Vec<String>)> {
    let divider = String::from("-");
    let (devices, objects) = match &mut paths[..] {
        [] => bail!("At least one device path is required"),
        [d] => (vec![d.clone()], vec![]),
        [d, o] => (vec![d.clone()], vec![o.clone()]),
        _ => {
            let split = paths.iter().position(|p| p == &divider);
            match split {
                Some(idx) => {
                    let mut objfiles = paths.split_off(idx);
                    objfiles.remove(0);
                    (paths, objfiles)
                }
                None => (paths, vec![]),
            }
        }
    };

    if devices.iter().any(|d| d.is_empty() || d == &divider)
        || objects.iter().any(|o| o.is_empty() || o == &divider)
    {
        bail!("Invalid device or object path");
    }
    if devices.is_empty() {
        bail!("Missing device path");
    }

    Ok((devices, objects))
}

fn udev_hid_bpf() -> Result<()> {
    let cli = Cli::parse();

    libbpf_rs::set_print(Some((
        if cli.debug {
            libbpf_rs::PrintLevel::Debug
        } else {
            libbpf_rs::PrintLevel::Info
        },
        print_to_log,
    )));

    let mut modules = vec![module_path!(), "HID-BPF metadata"];
    if cli.verbose {
        modules.push("libbpf");
    }

    stderrlog::new()
        .modules(modules)
        .verbosity(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Warn
        })
        .init()
        .unwrap();

    match cli.command {
        Commands::Add {
            paths,
            bpfdir,
            replace,
            property,
        } => {
            let (devices, objfiles) = split_paths(paths)?;
            let devices: Vec<PathBuf> = devices.iter().map(PathBuf::from).collect();
            if replace {
                cmd_remove(&devices)?;
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            cmd_add(&devices, &objfiles, bpfdir, &property)
        }
        Commands::Remove { devpaths } => cmd_remove(&devpaths),
        Commands::ListBpfPrograms { bpfdir } => cmd_list_bpf_programs(bpfdir),
        Commands::ListDevices {} => cmd_list_devices(),
        Commands::Inspect { paths } => cmd_inspect(&paths),
        Commands::Install {
            path,
            prefix,
            force,
            install_exe,
            dry_run,
        } => cmd_install(&path, prefix, force, install_exe, dry_run),
    }
}

fn main() -> ExitCode {
    let rc = udev_hid_bpf();
    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
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
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.is_err());

        let syspath = "/sys/blah/0003:04F3:2D4A.0001";
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.unwrap() == "0003:04F3:2D4A.0001");

        let syspath = "/sys/blah/0003:04F3:2D4A-0001";
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.is_err());

        // Only run this test if there's a local hidraw0 device
        let syspath = "/sys/class/hidraw/hidraw0/device";
        if std::path::Path::new(syspath).exists() {
            let sysname = sysname_from_syspath(&PathBuf::from(syspath));
            assert!(sysname.is_ok());
        }
    }

    macro_rules! vec_of_strings {
        ($($x:expr),*) => (vec![$($x.to_string()),*]);
    }

    #[test]
    fn test_split_paths() {
        let paths: Vec<String> = vec_of_strings!["a"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec!["b"]);

        let paths: Vec<String> = vec_of_strings!["a", "b", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b", "c"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b", "-", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b"]);
        assert_eq!(b, vec!["c"]);

        let paths: Vec<String> = vec_of_strings!["a", "-", "b", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec!["b", "c"] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b", "c", "-"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b", "c"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["-", "b", "c", "d"];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings!["a", "-"];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings!["-", "a"];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings!["-"];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings![""];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings!["a", "-", ""];
        assert!(split_paths(paths).is_err());
    }

    #[test]
    fn test_tuple_parse() {
        let p = tuple_parse("foo=bar").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "bar");

        let p = tuple_parse("foo=bar=baz").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "bar=baz");

        let p = tuple_parse("foo=").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "");

        assert!(tuple_parse("foo bar=baz").is_err());
        assert!(tuple_parse("foo\tbar=baz").is_err());
        assert!(tuple_parse("foobar =baz").is_err());
        assert!(tuple_parse("foobar").is_err());
    }
}
