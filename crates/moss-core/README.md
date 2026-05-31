# moss-core

`moss-core` is the reusable macOS socket inspection library that powers
[`moss`](https://github.com/c3b2a7/moss).

It provides:

- Darwin socket collection through XNU `sysctl` and `libproc`
- Socket, endpoint, process, and memory data models
- `ss`-style filter parsing and evaluation
- Host-name and service-name resolution helpers

## Platform support

`moss-core` is macOS-only. It depends on Darwin kernel socket data and the
`moss-sys` FFI bindings crate.

## Example

```rust
use moss_core::{SocketQuery, list_sockets};

let sockets = list_sockets(SocketQuery::default())?;
# Ok::<(), moss_core::Error>(())
```

For a complete CLI built on top of this crate, see
[`moss`](https://github.com/c3b2a7/moss).
