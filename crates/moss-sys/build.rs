use std::{env, path};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_type("xinpgen")
        .allowlist_type("xinpcb64")
        .allowlist_type("xtcpcb64")
        .allowlist_type("xsocket64")
        .allowlist_type("xsockbuf")
        .allowlist_type("socket_fdinfo")
        .allowlist_type("proc_fdinfo")
        .allowlist_function("proc_.*")
        .allowlist_var("AF_INET")
        .allowlist_var("AF_INET6")
        .allowlist_var("AF_UNIX")
        .allowlist_var("IPPROTO_TCP")
        .allowlist_var("IPPROTO_UDP")
        .allowlist_var("SOCK_STREAM")
        .allowlist_var("SOCK_DGRAM")
        .allowlist_var("TCPCTL_PCBLIST")
        .allowlist_var("UDPCTL_PCBLIST")
        .allowlist_var("INP_IPV4")
        .allowlist_var("INP_IPV6")
        .allowlist_var("TCPS_.*")
        .allowlist_var("PROC_.*")
        .allowlist_var("PROX_FDTYPE_SOCKET")
        .layout_tests(false)
        .generate()
        .expect("failed to generate macOS socket bindings");

    let out_path = path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write macOS socket bindings");
}
