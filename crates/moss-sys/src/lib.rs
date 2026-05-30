//! Raw Darwin bindings used by `moss`.
//!
//! This crate is intentionally thin and exposes bindgen-generated FFI items.
//! Most callers should use the safe API from the `moss-core` crate.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
