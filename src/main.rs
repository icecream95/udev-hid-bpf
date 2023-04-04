use std::io;

pub mod bpf;
pub mod hidudev;

fn bump_memlock_rlimit() -> Result<(), io::Error> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        panic!("Failed to increase rlimit");
    }
    Ok(())
}

fn print_event(event: &udev::Event) {
    println!(
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
    bump_memlock_rlimit()?;

    let skel = bpf::HidBPF::open_and_load(false).expect("Could not load base eBPF program");

    hidudev::poll(skel, |x| print_event(x))
}
