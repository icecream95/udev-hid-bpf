// SPDX-License-Identifier: GPL-2.0-only

extern crate bindgen;

#[allow(dead_code)]
/// modalias is not used completely here, so some functions are not used
#[path = "src/modalias.rs"]
mod modalias;

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::{Path, PathBuf};

const BPF_SOURCE_DIR: &str = "src/bpf/"; // relative to our git repo root
const ATTACH_PROG: &str = "attach.bpf.c";
const WRAPPER: &str = "./src/hid_bpf_wrapper.h";

fn build_bpf_file(
    bpf_source: &std::path::Path,
    target_dir: &std::path::Path,
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
        .obj(&target_object)
        .clang_args(includeflags)
        .build()
        .unwrap();

    Ok(())
}

fn build_bpf_files(src_dir: &Path, dst_dir: &Path) -> Result<(), libbpf_rs::Error> {
    // Compile all .bpf.c into a .bpf.o file
    for subdir in &["testing", "stable", "userhacks"] {
        let dst_subdir = dst_dir.join(subdir);
        std::fs::create_dir_all(dst_subdir.as_path())
            .unwrap_or_else(|_| panic!("Can't create directory '{}'", dst_subdir.display()));

        let dir = PathBuf::from(&src_dir).join(subdir);
        if dir.exists() {
            for path in dir
                .read_dir()
                .unwrap()
                .flatten()
                .filter(|f| f.metadata().unwrap().is_file())
                .map(|e| e.path())
                .filter(|p| p.to_str().unwrap().ends_with(".bpf.c"))
            {
                build_bpf_file(&path, &dst_subdir)?;
            }
        }
    }

    Ok(())
}

fn build_bpf_wrappers(src_dir: &Path, dst_dir: &Path) {
    let attach_prog = PathBuf::from(&src_dir).join(ATTACH_PROG);
    if !attach_prog.as_path().is_file() {
        panic!("Unable to find {}", attach_prog.display())
    }

    let skel_file = dst_dir.join(ATTACH_PROG.replace(".bpf.c", ".skel.rs"));
    let extra_include = env::var("EXTRA_INCLUDE").unwrap_or(String::from("."));
    SkeletonBuilder::new()
        .source(attach_prog)
        .clang_args(format!("-I{}", extra_include))
        .build_and_generate(&skel_file)
        .unwrap();

    // Create a wrapper around our bpf interface
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(WRAPPER)
        // make struct attach_prog_args more rust-friendly
        .raw_line("type AttachProgArgs = attach_prog_args;")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the hid_bpf_bindings.rs file.
    bindings
        .write_to_file(dst_dir.join("hid_bpf_bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", WRAPPER);
    if env::var("MESON_BUILD").is_err() {
        println!("cargo:warning=############################################################");
        println!("cargo:warning=      Use meson compile -C builddir instead of cargo        ");
        println!("cargo:warning=############################################################");
    }

    let source_root = env::var("BPF_SOURCE_ROOT").unwrap_or(String::from("."));
    let bpf_src_dir = PathBuf::from(source_root).join(BPF_SOURCE_DIR);
    println!("cargo:rerun-if-changed={}", bpf_src_dir.display());

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    let out_dir = PathBuf::from(out_dir);

    let cargo_target_dir = env::var("CARGO_TARGET_DIR").unwrap_or(String::from("./target"));
    let target_dir = PathBuf::from(cargo_target_dir).join(BPF_SOURCE_DIR);

    build_bpf_wrappers(&bpf_src_dir, &out_dir);
    build_bpf_files(&bpf_src_dir, &target_dir)?;

    Ok(())
}
