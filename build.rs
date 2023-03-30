//! build.rs
//
use std::process::Command;

use std::{fs, io};

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=builtin-actors/*");
    // use the local makefile
    Command::new("make")
        .arg("build-actors")
        .output()
        .expect("failed to execute process");
    //
    let out_dir = std::env::var("OUT_DIR").unwrap();

    fs::create_dir_all(&format!("{}/builtin-actors/output", out_dir))
        .expect("unable to create actors directory");

    let path = format!("builtin-actors/output/builtin-actors-mainnet.car");

    let out_path = format!("{}/{}", out_dir, path);

    let mut out_file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&out_path)
        .expect("unable to open/create data file");

    if let Ok(mut source_file) = fs::File::open(&path) {
        io::copy(&mut source_file, &mut out_file).expect("failed to copy data after opening");
    }
}
