// SPDX-License-Identifier: GPL-2.0-only

extern crate bindgen;

use libbpf_cargo::SkeletonBuilder;
use regex::Regex;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const DIR: &str = "./src/bpf/";
const ATTACH_PROG: &str = "attach.bpf.c";
const WRAPPER: &str = "./src/hid_bpf_wrapper.h";
const TARGET_DIR: &str = "./target/bpf";

fn build_bpf_file(
    bpf_source: &std::path::Path,
    target_dir: &std::path::Path,
) -> std::io::Result<String> {
    let re = Regex::new(r"b(?<bus>[0-9A-Z\*]{1,4})g(?<group>[0-9A-Z\*]{1,4})v(?<vid>[0-9A-Z\*]{1,8})p(?<pid>[0-9A-Z\*]{1,8})-.*.bpf.c").unwrap();
    let re_match = re.captures(bpf_source.file_name().unwrap().to_str().unwrap());

    let error = Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "Invalid filename '{}', must be bBBBBgGGGGv0000VVVVp0000PPPP-any-value.bpf.c",
            bpf_source.file_name().unwrap().to_str().unwrap()
        ),
    ));

    if re_match.is_none() {
        return error;
    }

    let caps = re_match.unwrap();
    let (bus, group, vid, pid) = (&caps["bus"], &caps["group"], &caps["vid"], &caps["pid"]);
    if !bus.contains("*") && bus.len() != 4 {
        return error;
    }
    if !group.contains("*") && group.len() != 4 {
        return error;
    }
    if !vid.contains("*") && (vid.len() != 8 || !vid.starts_with("0000")) {
        return error;
    }
    if !pid.contains("*") && (pid.len() != 8 || !pid.starts_with("0000")) {
        return error;
    }

    let mut target_object = target_dir.clone().join(bpf_source.file_name().unwrap());

    target_object.set_extension("o");

    SkeletonBuilder::new()
        .source(bpf_source)
        .obj(target_object)
        .build()
        .unwrap();

    Ok(format!("b{}g{}v{}p{}", bus, group, vid, pid))
}

fn write_hwdb_entry(modalias: String, mut hwdb_fd: &File) -> std::io::Result<()> {
    let hwdb_match = format!("hid-bpf:hid:{}\n", modalias);
    hwdb_fd.write_all(hwdb_match.as_bytes())?;
    hwdb_fd.write_all(b" HID_BPF=1\n\n")?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed={}", DIR);
    println!("cargo:rerun-if-changed={}", WRAPPER);

    let attach_prog = PathBuf::from(DIR).join(ATTACH_PROG);

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join(ATTACH_PROG.replace(".bpf.c", ".skel.rs"));

    SkeletonBuilder::new()
        .source(attach_prog)
        .build_and_generate(&out)
        .unwrap();

    let target_dir = PathBuf::from(TARGET_DIR);

    std::fs::create_dir_all(target_dir.as_path())
        .expect(format!("Can't create TARGET_DIR '{}'", TARGET_DIR).as_str());

    let hwdb_file = target_dir.clone().join("99-hid-bpf.hwdb");
    let hwdb_fd = File::create(hwdb_file)?;

    // Then compile all other .bpf.c in a .bpf.o file
    for elem in Path::new(DIR).read_dir().unwrap() {
        if let Ok(dir_entry) = elem {
            let path = dir_entry.path();
            if path.is_file()
                && path.to_str().unwrap().ends_with(".bpf.c")
                && path.file_name().unwrap() != ATTACH_PROG
            {
                let modalias = build_bpf_file(&path, &target_dir)?;
                write_hwdb_entry(modalias, &hwdb_fd)?;
            }
        }
    }

    // Create a wrapper around our bpf interface
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(WRAPPER)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("hid_bpf_bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
