use std::process::Command;
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const DIR: &str = "./src/bpf/";
const SRC: &str = "./src/bpf/attach.bpf.c";

fn main() {
    println!("cargo:rerun-if-changed={}", DIR);

    // First build our always loaded HID-BPF program
    //
    // It's unfortunate we cannot use `OUT_DIR` to store the generated skeleton.
    // Reasons are because the generated skeleton contains compiler attributes
    // that cannot be `include!()`ed via macro. And we cannot use the `#[path = "..."]`
    // trick either because you cannot yet `concat!(env!("OUT_DIR"), "/skel.rs")` inside
    // the path attribute either (see https://github.com/rust-lang/rust/pull/83366).
    //
    // However, there is hope! When the above feature stabilizes we can clean this
    // all up.
    let skel = Path::new("./src/bpf/mod.rs");
    SkeletonBuilder::new(SRC).generate(&skel).unwrap();

    // Then compile all other .bpf.c in a .bpf.o file
    Command::new("cargo").args(&["libbpf", "build"])
                       .status().unwrap();
}
