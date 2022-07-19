extern crate mio;
extern crate udev;

use glob::glob_with;
use glob::MatchOptions;
use std::io;
use std::path::PathBuf;

mod attachbpf {
    include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));
}

mod poll {
    use std::io;

    use mio::{Events, Interest, Poll, Token};

    pub fn poll(mut socket: udev::MonitorSocket) -> io::Result<()> {
        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(1024);

        poll.registry().register(
            &mut socket,
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )?;

        loop {
            poll.poll(&mut events, None)?;

            for event in &events {
                if event.token() == Token(0) && event.is_writable() {
                    socket.clone().for_each(|x| super::print_event(x));
                }
            }
        }
    }
}

fn get_filename(device: &udev::Device) -> String {
    let modalias = device.property_value("MODALIAS");

    let modalias = match modalias {
        Some(data) => data,
        _ => std::ffi::OsStr::new("hid:empty"), //panic!("modalias is empty"),
    };

    let modalias = match modalias.to_str() {
        Some(data) => data,
        _ => panic!("modalias problem"),
    };

    /* strip out the first 4 chars ("hid:") from the modalias */
    String::from(&modalias[4..])
        .replace("v0000", "v")
        .replace("p0000", "p")
}

fn get_bpffs_path(device: &udev::Device) -> String {
    format!(
        "/sys/fs/bpf/{}",
        device
            .sysname()
            .to_str()
            .unwrap()
            .replace(":", "_")
            .replace(".", "_"),
    )
}

fn load_bpf(device: &udev::Device, path: PathBuf) -> Result<(), libbpf_rs::Error> {
    println!("found BPF object at {:?}", path.display());

    let mut obj_builder = libbpf_rs::ObjectBuilder::default();

    //obj_builder.debug(true);

    let mut object = obj_builder.open_file(path)?.load()?;

    for prog in object.progs_iter_mut() {
        println!("found prog {} of type {}", prog.name(), prog.prog_type(),);

        let path = format!("{}/{}", get_bpffs_path(device), prog.name(),);

        println!("pin prog at {}", path);

        prog.pin(path)?;
    }

    Ok(())
}

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

fn add_device(device: udev::Device) {
    let prefix = get_filename(&device);

    println!(
        "device added {}, filename: {}",
        device.sysname().to_str().unwrap_or(""),
        prefix,
    );

    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };

    let glob_path = format!("target/bpf/{}*.bpf.o", prefix);

    for entry in glob_with(&glob_path[..], options).unwrap() {
        if let Ok(path) = entry {
            load_bpf(&device, path).unwrap_or(());
        }
    }
}

fn remove_device(device: udev::Device) {
    println!("device removed");

    let path = get_bpffs_path(&device);

    std::fs::remove_dir_all(path).unwrap_or(())
}

fn handle_event(event_type: udev::EventType, device: udev::Device) {
    match event_type {
        udev::EventType::Add => add_device(device),
        udev::EventType::Remove => remove_device(device),
        _ => (),
    }
}

fn print_event(event: udev::Event) {
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

    handle_event(event.event_type(), event.device())
}

fn main() -> io::Result<()> {
    bump_memlock_rlimit()?;

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("hid")?
        .listen()?;

    let mut enumerator = udev::Enumerator::new().unwrap();

    enumerator.match_subsystem("hid").unwrap();

    for device in enumerator.scan_devices().unwrap() {
        handle_event(udev::EventType::Add, device);
    }

    poll::poll(socket)
}
