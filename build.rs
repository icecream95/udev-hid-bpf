// SPDX-License-Identifier: GPL-2.0-only

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

fn build_bpf_wrappers(src_dir: &Path, dst_dir: &Path) {
    let attach_prog = PathBuf::from(&src_dir).join(ATTACH_PROG);
    if !attach_prog.as_path().is_file() {
        panic!("Unable to find {}", attach_prog.display())
    }
    println!("cargo:rerun-if-changed={}", attach_prog.display());

    let skel_file = dst_dir.join(ATTACH_PROG.replace(".bpf.c", ".skel.rs"));
    SkeletonBuilder::new()
        .source(attach_prog)
        .build_and_generate(&skel_file)
        .unwrap();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={}", WRAPPER);
    if env::var("MESON_BUILD").is_err() {
        println!("cargo:warning=############################################################");
        println!("cargo:warning=      Use meson compile -C builddir instead of cargo        ");
        println!("cargo:warning=############################################################");
    }

    // The fallbacks are only necessary for cargo build/cargo check, meson always sets them
    let fallback_bindir: Result<String, std::env::VarError> = Ok(String::from("/usr/local/bin"));
    let bindir = std::env::var("MESON_BINDIR").or(fallback_bindir).unwrap();
    println!("cargo:rustc-env=MESON_BINDIR={bindir}");

    let source_root = env::var("BPF_SOURCE_ROOT").unwrap_or(String::from("."));
    let bpf_src_dir = PathBuf::from(source_root).join(BPF_SOURCE_DIR);

    let bpf_lookup_dirs =
        env::var("BPF_LOOKUP_DIRS").unwrap_or(String::from("/usr/local/lib/firmware/hid/bpf"));
    println!("cargo:rustc-env=BPF_LOOKUP_DIRS={bpf_lookup_dirs}");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    let out_dir = PathBuf::from(out_dir);

    build_bpf_wrappers(&bpf_src_dir, &out_dir);

    Ok(())
}
