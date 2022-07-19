use libbpf_cargo::SkeletonBuilder;
use std::fs;
use std::process::Command;
use std::{env, path::Path, path::PathBuf};

const DIR: &str = "./src/bpf/";
const SRC: &str = "./src/bpf/attach.bpf.c";
const TARGET_DIR: &str = "./target";

fn main() {
    println!("cargo:rerun-if-changed={}", DIR);

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
}
