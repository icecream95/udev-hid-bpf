use crate::bpf;
use globset::GlobBuilder;
use std::io;

pub struct HidUdev {
    inner: udev::Device,
}

impl HidUdev {
    pub fn new(device: udev::Device) -> Self {
        HidUdev { inner: device }
    }

    pub fn modalias(&self) -> String {
        let modalias = self.inner.property_value("MODALIAS");

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

    pub fn sysname(&self) -> String {
        String::from(self.inner.sysname().to_str().unwrap())
    }

    pub fn syspath(&self) -> String {
        String::from(self.inner.syspath().to_str().unwrap())
    }

    pub fn id(&self) -> u32 {
        let hid_sys = self.sysname();
        u32::from_str_radix(&hid_sys[15..], 16).unwrap()
    }

    pub fn add(&self, skel: &bpf::HidBPF, bpf_dir: &std::path::PathBuf) {
        if !bpf_dir.exists() {
            return;
        }

        let prefix = self.modalias();

        if prefix.len() != 20 {
            eprintln!("invalid modalias {} for device {}", prefix, self.sysname(),);
            return;
        }

        let glob_path = bpf_dir.join(format!(
            "b{{{},\\*}}g{{{},\\*}}v{{{},\\*}}p{{{},\\*}}*.bpf.o",
            &prefix[1..5],
            &prefix[6..10],
            &prefix[11..15],
            &prefix[16..20],
        ));

        eprintln!(
            "device added {}, filename: {}",
            self.sysname(),
            glob_path.as_path().display()
        );

        let globset = GlobBuilder::new(glob_path.as_path().to_str().unwrap())
            .literal_separator(true)
            .case_insensitive(true)
            .build()
            .unwrap()
            .compile_matcher();

        for elem in bpf_dir.read_dir().unwrap() {
            if let Ok(dir_entry) = elem {
                let path = dir_entry.path();
                if globset.is_match(&path.to_str().unwrap()) && path.is_file() {
                    skel.load_programs(path, self).unwrap();
                }
            }
        }
    }

    pub fn remove(&self) {
        eprintln!("device removed");

        let path = bpf::get_bpffs_path(self);

        std::fs::remove_dir_all(path).unwrap_or(())
    }
}

pub fn handle_event(event: udev::Event, skel: &bpf::HidBPF, bpf_dir: &std::path::PathBuf) {
    let device = HidUdev::new(event.device());

    match event.event_type() {
        udev::EventType::Add => device.add(skel, bpf_dir),
        udev::EventType::Remove => device.remove(),
        _ => (),
    }
}

fn add_udev_device(device: udev::Device, skel: &bpf::HidBPF, bpf_dir: &std::path::PathBuf) {
    HidUdev::new(device).add(skel, bpf_dir);
}

mod poll {
    use std::io;

    use mio::{Events, Interest, Poll, Token};

    pub fn poll<F>(mut socket: udev::MonitorSocket, mut f: F) -> io::Result<()>
    where
        F: FnMut(udev::Event),
    {
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
                    socket.clone().for_each(&mut f);
                }
            }
        }
    }
}

pub fn poll<F>(skel: bpf::HidBPF, bpf_dir: std::path::PathBuf, mut pre_fn: F) -> io::Result<()>
where
    F: FnMut(&udev::Event),
{
    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("hid")?
        .listen()?;

    let mut enumerator = udev::Enumerator::new().unwrap();

    enumerator.match_subsystem("hid").unwrap();

    for device in enumerator.scan_devices().unwrap() {
        add_udev_device(device, &skel, &bpf_dir);
    }

    poll::poll(socket, |x| {
        pre_fn(&x);
        handle_event(x, &skel, &bpf_dir)
    })
}
