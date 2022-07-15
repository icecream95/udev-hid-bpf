extern crate mio;
extern crate udev;

use glob::glob_with;
use glob::MatchOptions;
use std::io;

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
            println!("found BPF object at {:?}", path.display())
        }
    }
}

fn remove_device(device: udev::Device) {
    println!("device removed");

    println!("  properties:");
    for property in device.properties() {
        println!("    {:?} = {:?}", property.name(), property.value());
    }
    println!("  attributes:");
    for attribute in device.attributes() {
        println!("    {:?} = {:?}", attribute.name(), attribute.value());
    }

    println!("  filename: {}", get_filename(&device))
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
    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("hid")?
        .listen()?;

    let mut enumerator = udev::Enumerator::new().unwrap();

    enumerator.match_subsystem("hid").unwrap();

    for device in enumerator.scan_devices().unwrap() {
        println!("found device: {:?}", device.syspath());
        println!("  properties:");
        for property in device.properties() {
            println!("    {:?} = {:?}", property.name(), property.value());
        }
        println!("  attributes:");
        for attribute in device.attributes() {
            println!("    {:?} = {:?}", attribute.name(), attribute.value());
        }

        handle_event(udev::EventType::Add, device);
    }

    poll::poll(socket)
}
