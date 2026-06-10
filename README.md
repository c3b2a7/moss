# moss

`moss` is a macOS-native socket statistics CLI inspired by Linux `ss`.
It reads socket data through XNU `sysctl` and process metadata through
`libproc`; it does not shell out to `lsof`, `netstat`, or similar tools.

## Features

- TCP, UDP, and Unix domain socket listing.
- IPv4 and IPv6 filtering with `-4` and `-6`.
- Linux `ss` style protocol and state filters such as `-t`, `-u`, `-x`, `-l`,
  and `-a`.
- Optional process details with process name, pid, and file descriptor.
- Optional extended socket metadata and socket memory counters.
- Service-name lookup by default, numeric ports with `-n`, and reverse hostname
  lookup with `-r`.
- Resolver caching for host lookups, with `--no-resolver-cache` to disable it.
- Summary output for sockets selected by the current protocol, family, state,
  and expression filters.
- `ss`-style filter expressions for state, ports, addresses, CIDR ranges, Unix
  paths, boolean logic, and grouping.
- Support JSON output with `-j`, pretty-printed with `--pretty`.

## Installation

### Recommended

Install with the script:

```sh
curl -fsSL https://get.lolico.me/moss | sh
```

The script installs to `$HOME/.local/bin` by default, choose another directory with `-b`:

```sh
curl -fsSL https://get.lolico.me/moss | sh -s -- -b /usr/local/bin
```

### Manual

You can download prebuilt binary from [GitHub Releases](https://github.com/c3b2a7/moss/releases).

## Usage

By default, `moss` lists TCP and UDP sockets:

```sh
moss
```

Common socket views:

```sh
moss -t # TCP sockets
moss -u # UDP sockets
moss -x # Unix domain sockets
moss -t -l # listening TCP sockets
moss -t -a # all TCP sockets
moss -4 # IPv4 sockets
moss -6 # IPv6 sockets
moss -s # socket summary for TCP, UDP, and Unix sockets
```

Show process, extended, or memory details:

```sh
moss -t -p # include process name, pid, and fd when available
moss -t -e # include uid, socket handle, and PCB handle
moss -t -m # include socket memory counters
moss -t -a -p -m # all TCP sockets with process and memory info
```

Control name resolution:

```sh
moss -n # numeric ports; do not resolve service names
moss -r # resolve host names
moss -r -n # resolve host names but keep numeric ports
```

Use filter expressions after the options:

```sh
moss -t 'state established'
moss -t 'sport = :443'
moss -t 'dport != :22'
moss -t 'sport >= :1024 and state listen'
moss -t 'not state time-wait'
moss -t '( state listen or state established ) and dport = :443'
moss -t 'src 192.168.0.0/16'
moss -u 'dport = :53'
moss -x 'path /tmp/.x11-unix/*.sock'
```

Supported predicates:

- `state <state>` matches TCP states such as `listen`, `established`, and
  `time-wait`.
- `sport <op> <port>`, `dport <op> <port>`, and `port <op> <port>` match local,
  peer, or either endpoint port.
- `src <addr>[/<prefix>]`, `dst <addr>[/<prefix>]`, and
  `addr <addr>[/<prefix>]` match local, peer, or either endpoint address.
- `path <substring>` matches Unix socket paths.

Supported operators are `=`, `!=`, `<`, `>`, `<=`, and `>=`, plus text aliases
`eq`, `ne`, `lt`, `gt`, `le`, and `ge`. Expressions can be combined with `and`,
`or`, `not`, `&&`, `||`, `!`, and parentheses.

## License

`moss` is distributed under the MIT License. See [LICENSE](LICENSE) for the full
license text.
