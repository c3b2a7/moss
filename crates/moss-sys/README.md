# moss-sys

`moss-sys` provides the raw Darwin FFI bindings used by
[`moss-core`](https://docs.rs/moss-core) and
[`moss`](https://github.com/c3b2a7/moss).

## Platform support

`moss-sys` is macOS-only. It exposes bindgen-generated items for Darwin socket
and `libproc` APIs, and is intended for low-level integration work.

Most users should depend on `moss-core` instead of using this crate directly.
