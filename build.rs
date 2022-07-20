extern crate bindgen;

use libbpf_cargo::SkeletonBuilder;
use std::fs;
use std::process::Command;
use std::{env, path::Path, path::PathBuf};

const DIR: &str = "./src/bpf/";
const SRC: &str = "./src/bpf/attach.bpf.c";
const WRAPPER: &str = "./src/hid_bpf_wrapper.h";
const TARGET_DIR: &str = "./target";

fn main() {
    println!("cargo:rerun-if-changed={}", DIR);
    println!("cargo:rerun-if-changed={}", WRAPPER);

    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("attach.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    // Then compile all other .bpf.c in a .bpf.o file
    Command::new("cargo")
        .args(&["libbpf", "build"])
        .status()
        .unwrap();

    // remove unused bpf object
    let dest_path = Path::new(TARGET_DIR).join("bpf").join("attach.bpf.o");

    fs::remove_file(dest_path).unwrap();

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
}
