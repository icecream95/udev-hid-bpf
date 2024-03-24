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
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const BPF_SOURCE_DIR: &str = "./src/bpf/"; // relative to our git repo root
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

    let extra_include = PathBuf::from(env::var("EXTRA_INCLUDE").unwrap_or(String::from(".")));
    // Automatically add the bpf program's parent directory to the includes. This is needed for vmlinux.h
    // which is one level up. If we build with meson we can pass the directory in as EXTRA_INCLUDE
    // but with pure cargo we need to find it - so let's hack arounds this.
    let includedirs = [
        bpf_source.parent().unwrap().parent().unwrap(),
        &extra_include,
    ];
    let includeflags: Vec<String> = includedirs
        .iter()
        .map(|d| format!("-I{} ", d.display()))
        .collect();
    let includeflags: String = includeflags.join(" ");

    SkeletonBuilder::new()
        .source(bpf_source)
        .obj(target_object.clone())
        .clang_args(includeflags)
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
    modalias: Modalias,
    files: Vec<String>,
    mut hwdb_fd: &File,
) -> std::io::Result<()> {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let hwdb_match = format!("hid-bpf:hid:{}\n", String::from(modalias));
    hwdb_fd.write_all(hwdb_match.as_bytes())?;
    for f in files {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        hwdb_fd.write_all(format!(" HID_BPF_{:?}={}\n", count, f).as_bytes())?;
    }
    hwdb_fd.write_all(b"\n")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", WRAPPER);

    let source_root = env::var("BPF_SOURCE_ROOT").unwrap_or(String::from("."));
    let bpf_src_dir = PathBuf::from(source_root).join(BPF_SOURCE_DIR);
    println!("cargo:rerun-if-changed={}", bpf_src_dir.display());

    let attach_prog = PathBuf::from(&bpf_src_dir).join(ATTACH_PROG);
    if !attach_prog.as_path().is_file() {
        panic!("Unable to find {}", attach_prog.display())
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join(ATTACH_PROG.replace(".bpf.c", ".skel.rs"));
    let extra_include = env::var("EXTRA_INCLUDE").unwrap_or(String::from("."));
    SkeletonBuilder::new()
        .source(attach_prog)
        .clang_args(format!("-I{}", extra_include))
        .build_and_generate(&out)
        .unwrap();

    let cargo_target_dir = env::var("CARGO_TARGET_DIR").unwrap_or(String::from("./target"));
    let target_dir = PathBuf::from(cargo_target_dir).join(TARGET_DIR);

    std::fs::create_dir_all(target_dir.as_path())
        .expect(format!("Can't create TARGET_DIR '{}'", TARGET_DIR).as_str());

    let mut subdirs: Vec<&'static str> = Vec::new();
    if cfg!(feature = "testing") {
        subdirs.push("testing");
    }
    if cfg!(feature = "stable") {
        subdirs.push("stable");
    }
    if cfg!(feature = "userhacks") {
        subdirs.push("userhacks");
    }
    if subdirs.is_empty() {
        println!("cargo:warning=No features selected, no BPF programs will be built");
    }

    // Then compile all other .bpf.c in a .bpf.o file
    for subdir in subdirs {
        let hwdb_name = format!("99-hid-bpf-{}.hwdb", subdir);
        let hwdb_file = target_dir.clone().join(hwdb_name);
        let hwdb_fd = File::create(hwdb_file)?;

        let mut modaliases = std::collections::HashMap::new();

        let dir = PathBuf::from(&bpf_src_dir).join(subdir);
        if dir.exists() {
            for path in dir
                .read_dir()
                .unwrap()
                .flatten()
                .filter(|f| f.metadata().unwrap().is_file())
                .map(|e| e.path())
                .filter(|p| p.to_str().unwrap().ends_with(".bpf.c"))
            {
                build_bpf_file(&path, &target_dir, &mut modaliases)?;
            }
            for (modalias, files) in modaliases {
                write_hwdb_entry(modalias, files, &hwdb_fd)?;
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
