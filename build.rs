// Example custom build script.
use copy_to_output::copy_to_output;
use std::{env, process::Command};

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=builtin-actors/*");
    // use the local makefile
    Command::new("make")
        .arg("build-actors")
        .output()
        .expect("failed to execute process");

    let build_type = format!("{}/deps", &env::var("PROFILE").unwrap());

    copy_to_output(
        "builtin-actors/output/builtin-actors-mainnet.car",
        &build_type,
    )
    .expect("Could not copy");
}
