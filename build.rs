use std::process::Command;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/packed-refs");

    let commit = command_stdout("git", &["rev-parse", "--short=12", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned());

    let build_time = build_time().unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=MOSS_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=MOSS_BUILD_TIME={build_time}");
}

fn command_stdout(command: &str, args: &[&str]) -> Option<String> {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn build_time() -> Option<String> {
    OffsetDateTime::now_utc().format(&Rfc3339).ok()
}
