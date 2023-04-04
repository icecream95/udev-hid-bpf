include!(concat!(env!("OUT_DIR"), "/hid_bpf_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));

use crate::hidudev;
use std::convert::TryInto;
use std::fs;
use std::path::PathBuf;

pub struct HidBPF<'a> {
    inner: Option<AttachSkel<'a>>,
}

pub fn get_bpffs_path(device: &hidudev::HidUdev) -> String {
    format!(
        "/sys/fs/bpf/hid/{}",
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

fn pin_hid_bpf_prog(link: i32, path: String) -> Result<(), libbpf_rs::Error> {
    unsafe {
        let c_str = std::ffi::CString::new(path).unwrap();

        match libbpf_sys::bpf_obj_pin(link, c_str.as_ptr() as *const i8) {
            0 => Ok(()),
            e => Err(libbpf_rs::Error::System(e)),
        }
    }
}

impl hid_bpf_probe_args {
    fn from(device: &hidudev::HidUdev) -> Self {
        let syspath = device.syspath();
        let rdesc = syspath + "/report_descriptor";

        let mut buffer = fs::read(&rdesc).unwrap();
        let length = buffer.len();

        buffer.resize(4096, 0);

        hid_bpf_probe_args {
            hid: device.id(),
            rdesc_size: length as u32,
            rdesc: buffer.try_into().unwrap(),
            retval: -1,
        }
    }
}

impl<'a> HidBPF<'a> {
    pub fn new() -> Self {
        Self { inner: None }
    }

    pub fn open_and_load(&mut self) -> Result<(), libbpf_rs::Error> {
        if self.inner.is_none() {
            let skel_builder = AttachSkelBuilder::default();
            let open_skel = skel_builder.open()?;
            self.inner = Some(open_skel.load()?);
        }
        Ok(())
    }

    pub fn load_programs(
        &self,
        path: PathBuf,
        device: &hidudev::HidUdev,
    ) -> Result<bool, libbpf_rs::Error> {
        log::debug!(target: "libbpf", "loading BPF object at {:?}", path.display());

        let mut obj_builder = libbpf_rs::ObjectBuilder::default();
        let mut object = obj_builder.open_file(path)?.load()?;

        let hid_id = device.id();

        /*
         * if there is a "probe" syscall, execute it and
         * check for the return value: if not 0, then ignore
         * this bpf.o file
         */
        match object.prog("probe") {
            Some(probe) => {
                let args = hid_bpf_probe_args::from(device);

                let args = run_syscall_prog(probe, args)?;

                if args.retval != 0 {
                    return Ok(false);
                }
            }
            _ => (),
        };

        let inner = self.inner.as_ref().expect("open_and_load() never called!");
        let mut attached = false;

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

            let ret_syscall = run_syscall_prog(inner.progs().attach_prog(), attach_args);

            if let Err(e) = ret_syscall {
                eprintln!(
                    "could not call attach {} to device id {}, error {}",
                    &tracing_prog.name(),
                    hid_id,
                    e.to_string(),
                );
                continue;
            }

            let args = ret_syscall.unwrap();

            if args.retval <= 0 {
                eprintln!(
                    "could not attach {} to device id {}, error {}",
                    &tracing_prog.name(),
                    hid_id,
                    libbpf_rs::Error::System(args.retval).to_string(),
                );
                continue;
            }

            let link = args.retval;

            log::debug!(
                target: "libbpf",
                "successfully attached {} to device id {}",
                &tracing_prog.name(),
                hid_id,
            );

            let path = format!("{}/{}", get_bpffs_path(device), tracing_prog.name(),);

            fs::create_dir_all(get_bpffs_path(device)).unwrap_or_else(|why| {
                eprintln!("! {:?}", why.kind());
            });

            match pin_hid_bpf_prog(link, path.clone()) {
                Err(e) => eprintln!(
                    "could not pin {} to device id {}, error {}",
                    &tracing_prog.name(),
                    hid_id,
                    e.to_string(),
                ),
                Ok(_) => {
                    attached = true;
                    log::debug!(target: "libbpf", "Successfully pinned prog at {}", path);
                }
            }
        }

        Ok(attached)
    }
}
