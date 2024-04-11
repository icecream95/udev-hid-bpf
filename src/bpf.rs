// SPDX-License-Identifier: GPL-2.0-only

include!(concat!(env!("OUT_DIR"), "/hid_bpf_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));

use crate::hidudev;
use anyhow::{bail, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use std::convert::TryInto;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

pub struct HidBPF<'a> {
    inner: Option<AttachSkel<'a>>,
}

pub fn get_bpffs_path(sysname: &str, object: &str) -> String {
    format!(
        "/sys/fs/bpf/hid/{}/{}",
        sysname.replace([':', '.'], "_"),
        object.replace([':', '.'], "_"),
    )
}

pub fn remove_bpf_objects(sysname: &str) -> std::io::Result<()> {
    let path = get_bpffs_path(sysname, "");

    std::fs::remove_dir_all(path).ok();

    Ok(())
}

fn run_syscall_prog<T>(prog: &libbpf_rs::Program, data: T) -> Result<T, libbpf_rs::Error> {
    let fd = prog.as_fd().as_raw_fd();
    let data_ptr: *const libc::c_void = &data as *const _ as *const libc::c_void;
    let mut run_opts = libbpf_sys::bpf_test_run_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as u64,
        ctx_in: data_ptr,
        ctx_size_in: std::mem::size_of::<T>() as u32,
        ..Default::default()
    };

    let run_opts_ptr: *mut libbpf_sys::bpf_test_run_opts = &mut run_opts;

    match unsafe { libbpf_sys::bpf_prog_test_run_opts(fd, run_opts_ptr) } {
        0 => Ok(data),
        e => Err(libbpf_rs::Error::from_raw_os_error(-e)),
    }
}

/*
* We have to rewrite our own `pin()` because we must be pinning the link
* provided by HID-BPF, not the Program object nor a normal libbpf_rs::Link
*/
fn pin_hid_bpf_prog(link: i32, path: String) -> Result<(), libbpf_rs::Error> {
    unsafe {
        let c_str = std::ffi::CString::new(path).unwrap();

        match libbpf_sys::bpf_obj_pin(link, c_str.as_ptr()) {
            0 => Ok(()),
            e => Err(libbpf_rs::Error::from_raw_os_error(-e)),
        }
    }
}

impl hid_bpf_probe_args {
    fn from(device: &hidudev::HidUdev) -> Self {
        let syspath = device.syspath();
        let rdesc = syspath + "/report_descriptor";

        let mut buffer = fs::read(rdesc).unwrap();
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
    pub fn new() -> Result<Self, libbpf_rs::Error> {
        let skel_builder = AttachSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let inner = Some(open_skel.load()?);
        Ok(Self { inner })
    }

    pub fn load_programs(&self, path: &Path, device: &hidudev::HidUdev) -> Result<()> {
        log::debug!(target: "libbpf", "loading BPF object at {:?}", path.display());

        let mut obj_builder = libbpf_rs::ObjectBuilder::default();
        let mut object = obj_builder.open_file(path)?.load()?;
        let object_name = path.file_stem().unwrap().to_str().unwrap();

        let hid_id = device.id();

        /*
         * if there is a "probe" syscall, execute it and
         * check for the return value: if not 0, then ignore
         * this bpf.o file
         */
        if let Some(probe) = object.prog("probe") {
            let args = hid_bpf_probe_args::from(device);

            let args = run_syscall_prog(probe, args)?;

            if args.retval != 0 {
                bail!("probe() returned {:?}", args.retval);
            }
        };

        let bpffs_path = get_bpffs_path(&device.sysname(), object_name);
        let inner = self.inner.as_ref().expect("open_and_load() never called!");
        let mut attached = false;

        for tracing_prog in object
            .progs_iter()
            .filter(|p| matches!(p.prog_type(), libbpf_rs::ProgramType::Tracing))
        {
            let attach_args = AttachProgArgs {
                prog_fd: tracing_prog.as_fd().as_raw_fd(),
                hid: hid_id,
                retval: -1,
            };

            let ret_syscall = run_syscall_prog(inner.progs().attach_prog(), attach_args);

            if let Err(e) = ret_syscall {
                log::warn!(
                    "could not call attach {} to device id {}, error {}",
                    &tracing_prog.name(),
                    hid_id,
                    e.to_string(),
                );
                continue;
            }

            let args = ret_syscall.unwrap();

            if args.retval <= 0 {
                log::warn!(
                    "could not attach {} to device id {}, error {}",
                    &tracing_prog.name(),
                    hid_id,
                    libbpf_rs::Error::from_raw_os_error(-args.retval).to_string(),
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

            let path = format!("{}/{}", &bpffs_path, tracing_prog.name(),);

            fs::create_dir_all(&bpffs_path).unwrap_or_else(|why| {
                log::warn!("! {:?}", why.kind());
            });

            match pin_hid_bpf_prog(link, path.clone()) {
                Err(e) => {
                    log::warn!(
                        "could not pin {} to device id {}, error {}",
                        &tracing_prog.name(),
                        hid_id,
                        e.to_string(),
                    );
                }
                Ok(_) => {
                    attached = true;
                    log::debug!(target: "libbpf", "Successfully pinned prog at {}", path);
                }
            }
        }

        if attached {
            /* compiler internal maps contain the name of the object and a dot */
            for map in object
                .maps_iter_mut()
                .filter(|map| !map.name().contains('.'))
            {
                let path = format!("{}/{}", bpffs_path, map.name(),);

                if map.pin(&path).is_ok() {
                    log::debug!(target: "libbpf", "Successfully pinned map at {}", path);
                }
                // FIXME: if attaching the map fails we need to remove the object
            }
        }

        if !attached {
            bail!("Failed to attach prog");
        } else {
            Ok(())
        }
    }
}
