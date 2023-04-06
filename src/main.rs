use std::io;

pub mod bpf;
pub mod hidudev;

fn print_event(event: &udev::Event) {
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

fn main() -> Result<(), io::Error> {
    let skel = bpf::HidBPF::open_and_load(false).expect("Could not load base eBPF program");

    hidudev::poll(skel, |x| print_event(x))
}
