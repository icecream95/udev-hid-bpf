use std::io;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/hid_bpf_bindings.rs"));
    include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));

    use crate::hidudev;
    use std::path::PathBuf;
    use std::fs;
    use std::convert::TryInto;

    pub struct HidBPF<'a> {
        inner: AttachSkel<'a>,
        debug: bool,
    }

    pub fn get_bpffs_path(device: &hidudev::HidUdev) -> String {
        format!(
            "/sys/fs/bpf/{}",
            device.sysname().replace(":", "_").replace(".", "_"),
        )
    }

    fn run_syscall_prog<T>(prog: &libbpf_rs::Program, data: T) -> Result<T, libbpf_rs::Error> {
        let fd = prog.fd();
        let data_ptr: *const libc::c_void = &data as *const _ as *const libc::c_void;
        let mut run_opts = libbpf_sys::bpf_test_run_opts::default();

        run_opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as u64;
        run_opts.ctx_in = data_ptr;
        run_opts.ctx_size_in = std::mem::size_of::<T>() as u32;

        let run_opts_ptr: *mut libbpf_sys::bpf_test_run_opts = &mut run_opts;

        match unsafe { libbpf_sys::bpf_prog_test_run_opts(fd, run_opts_ptr) } {
            0 => Ok(data),
            e => Err(libbpf_rs::Error::System(e)),
        }
    }

    impl probe_args {
        fn from(device: &hidudev::HidUdev) -> Self {
            let syspath = device.syspath();
            let rdesc = syspath + "/report_descriptor";

            let mut buffer = fs::read(&rdesc).unwrap();
            let length = buffer.len();

            buffer.resize(4096, 0);

            probe_args {
                hid: device.id(),
                rdesc_size: length as u32,
                rdesc: buffer.try_into().unwrap(),
                retval: -1,
            }
        }
    }

    impl<'a> HidBPF<'a> {
        pub fn open_and_load(debug: bool) -> Result<HidBPF<'a>, libbpf_rs::Error> {
            let mut skel_builder = AttachSkelBuilder::default();

            skel_builder.obj_builder.debug(debug);

            let open_skel = skel_builder.open()?;

            Ok(HidBPF {
                inner: open_skel.load()?,
                debug: debug,
            })
        }

        pub fn load_programs(
            &self,
            path: PathBuf,
            device: &hidudev::HidUdev,
        ) -> Result<(), libbpf_rs::Error> {
            if self.debug {
                println!("loading BPF object at {:?}", path.display());
            }

            let mut obj_builder = libbpf_rs::ObjectBuilder::default();

            obj_builder.debug(self.debug);

            let mut object = obj_builder.open_file(path)?.load()?;

            let hid_id = device.id();

            /*
             * if there is a "probe" syscall, execute it and
             * check for the return value: if not 0, then ignore
             * this bpf.o file
             */
            match object.prog("probe") {
                Some(probe) => {
                    let args = probe_args::from(device);

                    let args = run_syscall_prog(probe, args)?;

                    if args.retval != 0 {
                        return Ok(());
                    }
                }
                _ => (),
            };

            for prog in object.progs_iter_mut() {
                let tracing_prog = match prog.prog_type() {
                    libbpf_rs::ProgramType::Tracing => prog,
                    _ => continue,
                };

                let attach_args = attach_prog_args {
                    prog_fd: tracing_prog.fd(),
                    hid: hid_id,
                    retval: -1,
                };

                match run_syscall_prog(self.inner.progs().attach_prog(), attach_args) {
                    Ok(_) => println!(
                        "successfully attached {} to device id {}",
                        &tracing_prog.name(),
                        hid_id,
                    ),
                    Err(e) => {
                        println!(
                            "could not attach {} to device id {}, error {}",
                            &tracing_prog.name(),
                            hid_id,
                            e.to_string(),
                        );
                        continue;
                    }
                }

                let path = format!("{}/{}", get_bpffs_path(device), tracing_prog.name(),);

                println!("pin prog at {}", path);

                match tracing_prog.pin(path) {
                    Ok(()) => (),
                    Err(error) => println!("error while pinning: {}", error.to_string()),
                }
            }

            Ok(())
        }
    }
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

mod hidudev {
    use crate::bpf;
    use crate::poll;
    use glob::glob;
    use globset::GlobBuilder;
    use std::io;

    const BPF_O: &str = "target/bpf/*.bpf.o";

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

        pub fn add(&self, skel: &bpf::HidBPF) {
            let prefix = self.modalias();

            if prefix.len() != 20 {
                println!("invalid modalias {} for device {}", prefix, self.sysname(),);
                return;
            }

            let name = format!(
                "b{{{},\\*}}g{{{},\\*}}v{{{},\\*}}p{{{},\\*}}*",
                &prefix[1..5],
                &prefix[6..10],
                &prefix[11..15],
                &prefix[16..20],
            );
            let gpath = BPF_O.replace("*", &name[..]);

            println!("device added {}, filename: {}", self.sysname(), gpath);

            let globset = GlobBuilder::new(&gpath)
                .literal_separator(true)
                .case_insensitive(true)
                .build()
                .unwrap()
                .compile_matcher();

            for entry in glob(BPF_O).expect("can not find bpf objects") {
                if let Ok(path) = entry {
                    if globset.is_match(&path) {
                        skel.load_programs(path, self).unwrap();
                    }
                }
            }
        }

        pub fn remove(&self) {
            println!("device removed");

            let path = bpf::get_bpffs_path(self);

            std::fs::remove_dir_all(path).unwrap_or(())
        }
    }

    pub fn handle_event(event: udev::Event, skel: &bpf::HidBPF) {
        let device = HidUdev::new(event.device());

        match event.event_type() {
            udev::EventType::Add => device.add(skel),
            udev::EventType::Remove => device.remove(),
            _ => (),
        }
    }

    fn add_udev_device(device: udev::Device, skel: &bpf::HidBPF) {
        HidUdev::new(device).add(skel);
    }

    pub fn poll<F>(skel: bpf::HidBPF, mut pre_fn: F) -> io::Result<()>
    where
        F: FnMut(&udev::Event),
    {
        let socket = udev::MonitorBuilder::new()?
            .match_subsystem("hid")?
            .listen()?;

        let mut enumerator = udev::Enumerator::new().unwrap();

        enumerator.match_subsystem("hid").unwrap();

        for device in enumerator.scan_devices().unwrap() {
            add_udev_device(device, &skel);
        }

        poll::poll(socket, |x| {
            pre_fn(&x);
            handle_event(x, &skel)
        })
    }
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
