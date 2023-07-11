use clap::Parser;
use libbpf_rs;
use log;
use std::io;

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
}

fn print_event(event: &udev::Event) {
    log::debug!(
        "{}: {} {} (subsystem={}, sysname={})",
        event.sequence_number(),
        event.event_type(),
        event.syspath().to_str().unwrap_or("---"),
        event
            .subsystem()
            .map_or("", |s| { s.to_str().unwrap_or("") }),
        event.sysname().to_str().unwrap_or(""),
    );
}

fn print_to_log(level: libbpf_rs::PrintLevel, msg: String) {
    match level {
        libbpf_rs::PrintLevel::Debug => log::debug!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Info => log::info!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Warn => log::warn!(target: "libbpf", "{}", msg.trim()),
    }
}

fn main() -> Result<(), io::Error> {
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

    let skel = bpf::HidBPF::open_and_load().expect("Could not load base eBPF program");

    let debug_bpf = std::path::PathBuf::from("target/bpf");
    let default_bpf = std::path::PathBuf::from("/lib/firmware/hid/bpf");

    let bpf_dir: std::path::PathBuf;

    match cli.bpf {
        None => {
            if debug_bpf.exists() {
                bpf_dir = debug_bpf;
            } else {
                bpf_dir = default_bpf;
            }
        }
        Some(dir) => bpf_dir = dir,
    }

    log::debug!("Using eBPF programs from {}", bpf_dir.display());

    hidudev::poll(skel, bpf_dir, |x| print_event(x))
}
