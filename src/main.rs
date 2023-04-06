use clap::Parser;
use std::io;

pub mod bpf;
pub mod hidudev;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Folder to look at for bpf objects
    #[arg(short, long)]
    bpf: Option<std::path::PathBuf>,
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn print_event(event: &udev::Event, debug: bool) {
    if debug {
        eprintln!(
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
}

fn main() -> Result<(), io::Error> {
    let cli = Cli::parse();
    let skel = bpf::HidBPF::open_and_load(false).expect("Could not load base eBPF program");

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

    hidudev::poll(skel, bpf_dir, cli.debug, |x| print_event(x, cli.debug) )
}
