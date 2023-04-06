extern crate bindgen;

use libbpf_cargo::SkeletonBuilder;
use std::{env, path::Path, path::PathBuf};

const DIR: &str = "./src/bpf/";
const ATTACH_PROG: &str = "attach.bpf.c";
const WRAPPER: &str = "./src/hid_bpf_wrapper.h";
const TARGET_DIR: &str = "./target/bpf";

fn main() {
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

    // Then compile all other .bpf.c in a .bpf.o file
    for elem in Path::new(DIR).read_dir().unwrap() {
        if let Ok(dir_entry) = elem {
            let path = dir_entry.path();
            if path.is_file()
                && path.to_str().unwrap().ends_with(".bpf.c")
                && path.file_name().unwrap() != ATTACH_PROG
            {
                let mut target_object = target_dir.clone().join(path.file_name().unwrap());

                target_object.set_extension("o");

                SkeletonBuilder::new()
                    .source(path)
                    .obj(target_object)
                    .build()
                    .unwrap();
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
}
