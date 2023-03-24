// Example custom build script.
use std::process::Command;

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=builtin-actors/*");
    // use the local makefile
    Command::new("make")
        .arg("build-actors")
        .output()
        .expect("failed to execute process");
}
