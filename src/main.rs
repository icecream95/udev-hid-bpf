extern crate libbpf_sys;
extern crate mio;
extern crate udev;

use glob::glob_with;
use glob::MatchOptions;
use std::io;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/attach_bindings.rs"));

mod attachbpf {
    include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));
}

use attachbpf::*;

mod poll {
    use std::io;

    use crate::attachbpf::*;
    use mio::{Events, Interest, Poll, Token};

    pub fn poll(mut socket: udev::MonitorSocket, skel: &AttachSkel) -> io::Result<()> {
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
                    socket.clone().for_each(|x| super::print_event(x, skel));
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

fn attach_bpf(
    device: &udev::Device,
    skel: &AttachSkel,
    prog: &libbpf_rs::Program,
) -> Result<(), libbpf_rs::Error> {
    let fd = skel.progs().attach_prog().fd();
    let hid_sys = device.sysname().to_str().unwrap();
    let hid_id = u32::from_str_radix(&hid_sys[15..], 16).unwrap();

    let attach_args = attach_prog_args {
        prog_fd: prog.fd(),
        hid: hid_id,
        retval: -1,
    };
    let attach_args_ptr: *const libc::c_void = &attach_args as *const _ as *const libc::c_void;
    let mut run_opts = libbpf_sys::bpf_test_run_opts::default();

    run_opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as u64;
    run_opts.ctx_in = attach_args_ptr;
    run_opts.ctx_size_in = std::mem::size_of::<attach_prog_args>() as u32;

    let run_opts_ptr: *mut libbpf_sys::bpf_test_run_opts = &mut run_opts;

    let err = unsafe { libbpf_sys::bpf_prog_test_run_opts(fd, run_opts_ptr) };

    println!(
        "attached {} to device id {} through fd {} err: {}",
        prog.name(),
        hid_id,
        fd,
        err,
    );
    Ok(())
}

fn load_bpf(
    device: &udev::Device,
    path: PathBuf,
    skel: &AttachSkel,
) -> Result<(), libbpf_rs::Error> {
    println!("found BPF object at {:?}", path.display());

    let mut obj_builder = libbpf_rs::ObjectBuilder::default();

    //obj_builder.debug(true);

    let mut object = obj_builder.open_file(path)?.load()?;

    for prog in object.progs_iter_mut() {
        println!("found prog {} of type {}", prog.name(), prog.prog_type(),);

        match prog.prog_type() {
            libbpf_rs::ProgramType::Tracing => attach_bpf(device, skel, prog)?,
            _ => (),
        }

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

fn add_device(device: udev::Device, skel: &AttachSkel) {
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
            load_bpf(&device, path, skel).unwrap_or(());
        }
    }
}

fn remove_device(device: udev::Device) {
    println!("device removed");

    let path = get_bpffs_path(&device);

    std::fs::remove_dir_all(path).unwrap_or(())
}

fn handle_event(event_type: udev::EventType, device: udev::Device, skel: &AttachSkel) {
    match event_type {
        udev::EventType::Add => add_device(device, skel),
        udev::EventType::Remove => remove_device(device),
        _ => (),
    }
}

fn print_event(event: udev::Event, skel: &AttachSkel) {
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

    handle_event(event.event_type(), event.device(), skel)
}

fn main() -> Result<(), io::Error> {
    let skel_builder = AttachSkelBuilder::default();

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open().unwrap();

    let skel = open_skel.load().unwrap();

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("hid")?
        .listen()?;

    let mut enumerator = udev::Enumerator::new().unwrap();

    enumerator.match_subsystem("hid").unwrap();

    for device in enumerator.scan_devices().unwrap() {
        handle_event(udev::EventType::Add, device, &skel);
    }

    poll::poll(socket, &skel)
}
