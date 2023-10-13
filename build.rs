// SPDX-License-Identifier: GPL-2.0-only

extern crate bindgen;

#[allow(dead_code)]
/// modalias is not used completely here, so some functions are not used
#[path = "src/modalias.rs"]
mod modalias;

use crate::modalias::Modalias;
use libbpf_cargo::SkeletonBuilder;
use libbpf_rs;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const DIR: &str = "./src/bpf/";
const ATTACH_PROG: &str = "attach.bpf.c";
const WRAPPER: &str = "./src/hid_bpf_wrapper.h";
const TARGET_DIR: &str = "bpf"; // inside $CARGO_TARGET_DIR

fn build_bpf_file(
    bpf_source: &std::path::Path,
    target_dir: &std::path::Path,
    modaliases: &mut std::collections::HashMap<Modalias, Vec<String>>,
) -> Result<(), libbpf_rs::Error> {
    let mut target_object = target_dir.join(bpf_source.file_name().unwrap());

    target_object.set_extension("o");

    SkeletonBuilder::new()
        .source(bpf_source)
        .obj(target_object.clone())
        .build()
        .unwrap();

    let btf = libbpf_rs::btf::Btf::from_path(target_object.clone())?;

    if let Some(metadata) = modalias::Metadata::from_btf(&btf) {
        let fname = String::from(target_object.file_name().unwrap().to_str().unwrap());
        for modalias in metadata.modaliases() {
            modaliases
                .entry(modalias)
                .or_insert(Vec::new())
                .push(fname.clone());
        }
    }
    Ok(())
}

fn write_hwdb_entry(
    mut cur_idx: u32,
    modalias: Modalias,
    files: Vec<String>,
    mut hwdb_fd: &File,
) -> std::io::Result<u32> {
    let hwdb_match = format!("hid-bpf:hid:{}\n", String::from(modalias));
    hwdb_fd.write_all(hwdb_match.as_bytes())?;
    for f in files {
        hwdb_fd.write_all(format!(" HID_BPF_{:?}={}\n", cur_idx, f).as_bytes())?;
        cur_idx += 1;
    }
    hwdb_fd.write_all(b"\n")?;

    Ok(cur_idx)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", DIR);
    println!("cargo:rerun-if-changed={}", WRAPPER);

    let attach_prog = PathBuf::from(DIR).join(ATTACH_PROG);

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join(ATTACH_PROG.replace(".bpf.c", ".skel.rs"));

    SkeletonBuilder::new()
        .source(attach_prog)
        .build_and_generate(&out)
        .unwrap();

    let cargo_target_dir = env::var("CARGO_TARGET_DIR").unwrap_or(String::from("./target"));
    let mut target_dir = PathBuf::from(cargo_target_dir);
    target_dir.push(TARGET_DIR);

    std::fs::create_dir_all(target_dir.as_path())
        .expect(format!("Can't create TARGET_DIR '{}'", TARGET_DIR).as_str());

    let hwdb_file = target_dir.clone().join("99-hid-bpf.hwdb");
    let hwdb_fd = File::create(hwdb_file)?;

    let mut modaliases = std::collections::HashMap::new();

    // Then compile all other .bpf.c in a .bpf.o file
    for elem in Path::new(DIR).read_dir().unwrap() {
        if let Ok(dir_entry) = elem {
            let path = dir_entry.path();
            if path.is_file()
                && path.to_str().unwrap().ends_with(".bpf.c")
                && path.file_name().unwrap() != ATTACH_PROG
            {
                build_bpf_file(&path, &target_dir, &mut modaliases)?;
            }
        }
    }

    let mut idx = 0;
    for (modalias, files) in modaliases {
        idx = write_hwdb_entry(idx, modalias, files, &hwdb_fd)?;
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
