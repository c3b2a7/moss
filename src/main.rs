mod output;

use clap::Parser;
use moss_core::{
    AddressFamily, FilterExpression, Protocol, SocketFilter, SocketQuery, filter_sockets,
    list_sockets,
};
use output::{OutputOptions, print_sockets, print_summary};
use std::process::ExitCode;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("MOSS_BUILD_COMMIT"),
    ", built ",
    env!("MOSS_BUILD_TIME"),
    ")"
);

#[derive(Debug, Parser)]
#[command(
    name = "moss",
    version = VERSION,
    about = "A macOS-native socket statistics tool inspired by Linux ss",
    after_long_help = "\
EXAMPLES:
  moss                                Show TCP and UDP sockets
  moss -t -l                          Show listening TCP sockets
  moss -u                             Show UDP sockets
  moss -x                             Show Unix domain sockets
  moss -t -p                          Show TCP sockets with process info
  moss -t -a -p -m                    Show all TCP sockets with memory info
  moss -n                             Show numeric ports
  moss -r                             Resolve host names
  moss -t 'state established'         Show established TCP connections
  moss -t 'sport = :443'              Show TCP sockets on local port 443
  moss -u 'dport = :53'               Show UDP sockets to DNS
  moss -x 'path /tmp/*'               Show Unix sockets matching a path"
)]
struct Cli {
    /// Show TCP sockets.
    #[arg(short = 't', long)]
    tcp: bool,

    /// Show UDP sockets.
    #[arg(short = 'u', long)]
    udp: bool,

    /// Show Unix domain sockets.
    #[arg(short = 'x', long)]
    unix: bool,

    /// Show listening sockets.
    #[arg(short = 'l', long)]
    listening: bool,

    /// Show all sockets.
    #[arg(short = 'a', long)]
    all: bool,

    /// Show only IPv4 sockets.
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Show only IPv6 sockets.
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Show process name, pid, and fd when available.
    #[arg(short = 'p', long)]
    processes: bool,

    /// Do not resolve service names.
    #[arg(short = 'n', long)]
    numeric: bool,

    /// Resolve host names.
    #[arg(short = 'r', long)]
    resolve: bool,

    /// Disable resolver caching for host lookups.
    #[arg(long)]
    no_resolver_cache: bool,

    /// Show detailed socket information.
    #[arg(short = 'e', long)]
    extended: bool,

    /// Show socket memory usage.
    #[arg(short = 'm', long)]
    memory: bool,

    /// Show socket usage summary.
    #[arg(short = 's', long)]
    summary: bool,

    /// Filter sockets with an ss-style expression.
    #[arg(
        trailing_var_arg = true,
        long_help = "\
Filter sockets with an ss-style expression.

PREDICATES:
  state [=] <state>            Match TCP state
  exclude [=] <state>          Exclude a TCP state
  sport [op] <port>            Match local (source) port
  dport [op] <port>            Match peer (destination) port
  port [op] <port>             Match port on either endpoint
  src [=] <addr>[/<prefix>]    Match local (source) address
  dst [=] <addr>[/<prefix>]    Match peer (destination) address
  addr [=] <addr>[/<prefix>]   Match address on either endpoint
  path [=] <glob>              Match Unix socket path

OPERATORS:
  =  ==  !=  <  >  <=  >=
  eq ne neq lt gt le leq ge geq

VALUES:
  state                         listen, established, closed, time-wait, ...
                                sets: all, connected, synchronized, bucket, big
  port                          443, :443, http, :https
  address                       127.0.0.1, 192.168.0.0/16, 193.233.7/24,
                                localhost, host:443, host:https, [::1]:443,
                                inet:127.0.0.1, inet6:::1, unix:/tmp/*.sock
  path                          case-insensitive glob with * and ?

LOGIC:
  expr and expr   (expr && expr)   Both conditions must hold
  expr or expr    (expr || expr)   Either condition must hold
  not expr        (!expr)          Negate a condition
  ( expr )                         Group expressions with parentheses

EXAMPLES:
  'state listen'
  'state connected'
  'exclude time-wait'
  'dport = :443'
  'sport >= :1024 and state listen'
  '( state listen or state established ) and dport 443'
  'dst 203.0.113.10:https'
  'dst [2001:db8::1]:443'
  'src /var/folders/*.sock'"
    )]
    expression: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let expression = match FilterExpression::parse(&cli.expression) {
        Ok(expression) => expression,
        Err(err) => {
            eprintln!("moss: {err}");
            return ExitCode::FAILURE;
        }
    };

    let family = family(&cli);
    let filter = SocketFilter {
        protocols: protocols(&cli),
        family,
        listening: cli.listening,
        all: cli.all || !cli.listening,
        expression,
    };

    let query = SocketQuery {
        include_processes: cli.processes,
        include_tcp: query_includes_protocol(&cli, Protocol::Tcp),
        include_udp: query_includes_protocol(&cli, Protocol::Udp),
        include_unix: !matches!(family, Some(AddressFamily::Ipv4 | AddressFamily::Ipv6))
            && (cli.summary
                || query_includes_protocol(&cli, Protocol::UnixStream)
                || query_includes_protocol(&cli, Protocol::UnixDatagram)),
    };

    match list_sockets(query) {
        Ok(sockets) => {
            let sockets = filter_sockets(sockets, &filter);
            if cli.summary {
                print_summary(&sockets);
            } else {
                let options = OutputOptions::from(&cli);
                print_sockets(&sockets, &options);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("moss: {err}");
            ExitCode::FAILURE
        }
    }
}

fn protocols(cli: &Cli) -> Vec<Protocol> {
    let mut protocols = Vec::new();
    if cli.unix {
        protocols.extend([Protocol::UnixStream, Protocol::UnixDatagram]);
    }
    if cli.tcp {
        protocols.push(Protocol::Tcp)
    }
    if cli.udp {
        protocols.push(Protocol::Udp);
    }
    protocols
}

fn query_includes_protocol(cli: &Cli, protocol: Protocol) -> bool {
    let no_protocol_filter = !cli.tcp && !cli.udp && !cli.unix;
    if no_protocol_filter {
        return matches!(protocol, Protocol::Tcp | Protocol::Udp);
    }

    match protocol {
        Protocol::Tcp => cli.tcp,
        Protocol::Udp => cli.udp,
        Protocol::UnixStream | Protocol::UnixDatagram => cli.unix,
    }
}

fn family(cli: &Cli) -> Option<AddressFamily> {
    if cli.unix && !cli.tcp && !cli.udp {
        return Some(AddressFamily::Unix);
    }

    match (cli.ipv4, cli.ipv6) {
        (true, false) => Some(AddressFamily::Ipv4),
        (false, true) => Some(AddressFamily::Ipv6),
        _ => None,
    }
}

impl From<&Cli> for OutputOptions {
    fn from(cli: &Cli) -> Self {
        Self {
            show_processes: cli.processes,
            numeric: cli.numeric,
            resolve: cli.resolve,
            resolver_cache: !cli.no_resolver_cache,
            extended: cli.extended,
            memory: cli.memory,
        }
    }
}
