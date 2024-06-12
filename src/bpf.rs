// SPDX-License-Identifier: GPL-2.0-only

include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));

use crate::hidudev;
use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Object, Program};
use std::convert::TryInto;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct hid_bpf_probe_args {
    pub hid: ::std::os::raw::c_uint,
    pub rdesc_size: ::std::os::raw::c_uint,
    pub rdesc: [::std::os::raw::c_uchar; 4096usize],
    pub retval: ::std::os::raw::c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AttachProgArgs {
    pub prog_fd: ::std::os::raw::c_int,
    pub hid: ::std::os::raw::c_uint,
    pub retval: ::std::os::raw::c_int,
}

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

fn run_syscall_prog_generic<T>(prog: &libbpf_rs::Program, data: T) -> Result<T, libbpf_rs::Error> {
    let fd = prog.as_fd().as_raw_fd();
    let data_ptr: *const libc::c_void = &data as *const _ as *const libc::c_void;
    let mut run_opts = libbpf_sys::bpf_test_run_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_test_run_opts>()
            .try_into()
            .unwrap(),
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

fn run_syscall_prog_attach(
    prog: &libbpf_rs::Program,
    attach_args: AttachProgArgs,
) -> Result<i32, libbpf_rs::Error> {
    let args = run_syscall_prog_generic(prog, attach_args)?;
    if args.retval < 0 {
        Err(libbpf_rs::Error::from_raw_os_error(-args.retval))
    } else {
        Ok(args.retval)
    }
}

fn run_syscall_prog_probe(
    prog: &libbpf_rs::Program,
    probe_args: hid_bpf_probe_args,
) -> Result<i32, libbpf_rs::Error> {
    let args = run_syscall_prog_generic(prog, probe_args)?;
    if args.retval != 0 {
        Err(libbpf_rs::Error::from_raw_os_error(-args.retval))
    } else {
        Ok(args.retval)
    }
}

/*
* We have to rewrite our own `pin()` because we must be pinning the link
* provided by HID-BPF, not the Program object nor a normal libbpf_rs::Link
*/
fn pin_hid_bpf_prog(link: i32, path: &str) -> Result<(), libbpf_rs::Error> {
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

    fn load_prog(&self, prog: &Program, hid_id: u32, bpffs_path: &str) -> Result<String> {
        let inner = self.inner.as_ref().expect("open_and_load() never called!");
        let attach_args = AttachProgArgs {
            prog_fd: prog.as_fd().as_raw_fd(),
            hid: hid_id,
            retval: -1,
        };

        let link = run_syscall_prog_attach(inner.progs().attach_prog(), attach_args)
            .context(format!("failed the syscall for {}", prog.name()))?;

        log::debug!(
            target: "libbpf",
            "successfully attached {} to device id {}",
            &prog.name(),
            hid_id,
        );

        let path = format!("{}/{}", bpffs_path, prog.name(),);

        fs::create_dir_all(bpffs_path).unwrap_or_else(|why| {
            log::warn!("! {:?}", why.kind());
        });

        pin_hid_bpf_prog(link, &path).context(format!(
            "could not pin {} to device id {}",
            &prog.name(),
            hid_id
        ))?;

        log::debug!(target: "libbpf", "Successfully pinned prog at {}", path);

        Ok(path)
    }

    fn load_progs(
        &self,
        object: &Object,
        object_name: &str,
        hid_id: u32,
        bpffs_path: &str,
    ) -> Result<Vec<String>> {
        let attached: Vec<String> = object
            .progs_iter()
            .filter(|p| matches!(p.prog_type(), libbpf_rs::ProgramType::Tracing))
            .map(|p| self.load_prog(p, hid_id, bpffs_path))
            .inspect(|r| {
                if let Err(e) = r {
                    log::warn!("failed to attach to device id {}: {:#}", hid_id, e,);
                }
            })
            .flatten()
            .collect();

        if attached.is_empty() {
            bail!("Failed to attach object {object_name}");
        }
        Ok(attached)
    }

    fn pin_maps(&self, object: &mut Object, bpffs_path: &String) -> Result<()> {
        // compiler internal maps contain the name of the object and a dot
        for map in object
            .maps_iter_mut()
            .filter(|map| !map.name().contains('.'))
        {
            let path = format!("{}/{}", bpffs_path, map.name(),);

            map.pin(&path)
                .context(format!("Failed to pin map at {}", path))?;
            log::debug!(target: "libbpf", "Successfully pinned map at {}", path);
        }

        Ok(())
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
            run_syscall_prog_probe(probe, args).context("probe() failed")?;
        };

        let bpffs_path = get_bpffs_path(&device.sysname(), object_name);
        self.load_progs(&object, object_name, hid_id, &bpffs_path)?;
        if let Err(e) = self.pin_maps(&mut object, &bpffs_path) {
            let _ = std::fs::remove_dir_all(bpffs_path);
            bail!(e);
        };

        Ok(())
    }
}
