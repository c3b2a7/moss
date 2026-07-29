use moss_core::{
    Protocol, Resolver, ResolverConfig, SocketAddress, SocketInfo, SocketState, TcpState,
};
use owo_colors::OwoColorize;
use std::io::{self, Write};
use std::net::IpAddr;
use tabled::builder::Builder;
use tabled::settings::Style;

pub struct OutputOptions {
    pub show_processes: bool,
    pub numeric: bool,
    pub resolve: bool,
    pub resolver_cache: bool,
    pub extended: bool,
    pub memory: bool,
}

pub fn print_sockets(sockets: &[SocketInfo], options: &OutputOptions) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let mut formatter = AddressFormatter::new(options);

    let mut builder = Builder::new();
    builder.push_record(header_row(options));
    let mut row_heights = Vec::with_capacity(sockets.len());
    for socket in sockets {
        let row = data_row(socket, options, &mut formatter);
        row_heights.push(
            row.iter()
                .map(|cell| cell.lines().count())
                .max()
                .unwrap_or(1),
        );
        builder.push_record(row);
    }

    let table = builder.build().with(Style::blank()).to_string();
    if !options.extended && !options.memory {
        return writeln!(out, "{table}");
    }

    let mut rows = table.lines();
    if let Some(header) = rows.next() {
        writeln!(out, "{header}")?;
    }

    for (socket, row_height) in sockets.iter().zip(row_heights) {
        if let Some(row) = rows.next() {
            writeln!(out, "{row}")?;
        }
        for row in rows.by_ref().take(row_height - 1) {
            writeln!(out, "{row}")?;
        }
        if options.extended {
            writeln!(
                out,
                " uid:{} sk:{:#x} pcb:{:#x}",
                socket.uid, socket.socket_handle, socket.pcb_handle
            )?;
        }
        if options.memory {
            let mem = socket.memory;
            writeln!(
                out,
                " skmem:(r{},rb{},rm{},rmb{},t{},tb{},tm{},tmb{})",
                mem.recv_bytes,
                mem.recv_high_water,
                mem.recv_mbuf_bytes,
                mem.recv_mbuf_limit,
                mem.send_bytes,
                mem.send_high_water,
                mem.send_mbuf_bytes,
                mem.send_mbuf_limit
            )?;
        }
    }

    Ok(())
}

fn header_row(options: &OutputOptions) -> Vec<String> {
    let mut header = vec![
        "Netid".bold().to_string(),
        "State".bold().to_string(),
        "Recv-Q".bold().to_string(),
        "Send-Q".bold().to_string(),
        "LocalAddress:Port".bold().to_string(),
        "PeerAddress:Port".bold().to_string(),
    ];

    if options.show_processes {
        header.push("Process".bold().to_string());
    }

    header
}

fn data_row(
    socket: &SocketInfo,
    options: &OutputOptions,
    formatter: &mut AddressFormatter,
) -> Vec<String> {
    let mut row = vec![
        netid_text(socket).cyan().to_string(),
        color_state(socket.state),
        socket.recv_queue.to_string(),
        socket.send_queue.to_string(),
        formatter
            .format(socket, &socket.local, true)
            .yellow()
            .to_string(),
        formatter
            .format(socket, &socket.peer, false)
            .yellow()
            .to_string(),
    ];

    if options.show_processes {
        row.push(
            socket
                .process
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default(),
        );
    }

    row
}

pub fn print_summary(sockets: &[SocketInfo]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let summary = SocketSummary::from_sockets(sockets);

    writeln!(out, "Total: {}", sockets.len())?;
    writeln!(
        out,
        "TCP:   {} (established {}, listening {})",
        summary.tcp, summary.established, summary.listening
    )?;
    writeln!(out, "UDP:   {}", summary.udp)?;
    writeln!(out, "RAW:   {}", summary.raw)?;
    writeln!(out, "UNIX:  {}", summary.unix)?;

    Ok(())
}

pub fn print_json(sockets: &[SocketInfo], pretty: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let result = if pretty {
        serde_json::to_string_pretty(sockets)
    } else {
        serde_json::to_string(sockets)
    };

    let json = result.map_err(io::Error::other)?;
    writeln!(out, "{json}")
}

#[derive(Default)]
struct SocketSummary {
    tcp: usize,
    udp: usize,
    raw: usize,
    unix: usize,
    established: usize,
    listening: usize,
}

impl SocketSummary {
    fn from_sockets(sockets: &[SocketInfo]) -> Self {
        let mut summary = Self::default();

        for socket in sockets {
            match socket.protocol {
                Protocol::Tcp => {
                    summary.tcp += 1;
                    match socket.state {
                        SocketState::Tcp(TcpState::Established) => summary.established += 1,
                        state if state.is_listening() => summary.listening += 1,
                        _ => {}
                    }
                }
                Protocol::Udp => summary.udp += 1,
                Protocol::Raw => summary.raw += 1,
                Protocol::UnixStream | Protocol::UnixDatagram => summary.unix += 1,
            }
        }

        summary
    }
}

fn netid_text(socket: &SocketInfo) -> String {
    if socket.protocol.is_unix() {
        return socket.protocol.to_string();
    }
    let suffix = match socket.family {
        moss_core::AddressFamily::Ipv6 => "6",
        moss_core::AddressFamily::Ipv46 => "46",
        _ => "",
    };
    format!("{}{}", socket.protocol, suffix)
}

fn state_display(state: SocketState) -> &'static str {
    match state {
        SocketState::Listen => "LISTEN",
        SocketState::Tcp(TcpState::Listen) => "LISTEN",
        SocketState::Connected => "CONNECTED",
        SocketState::Tcp(TcpState::Established) => "ESTABLISHED",
        SocketState::Tcp(TcpState::SynSent) => "SYN-SENT",
        SocketState::Tcp(TcpState::SynReceived) => "SYN-RECV",
        SocketState::Tcp(TcpState::CloseWait) => "CLOSE-WAIT",
        SocketState::Tcp(TcpState::FinWait1) => "FIN-WAIT-1",
        SocketState::Tcp(TcpState::FinWait2) => "FIN-WAIT-2",
        SocketState::Tcp(TcpState::Closing) => "CLOSING",
        SocketState::Tcp(TcpState::LastAck) => "LAST-ACK",
        SocketState::Tcp(TcpState::TimeWait) => "TIME-WAIT",
        SocketState::Unconnected => "UNCONN",
        SocketState::Unknown | SocketState::Tcp(TcpState::Unknown(_)) => "UNKNOWN",
        SocketState::Tcp(TcpState::Closed) => "CLOSED",
    }
}

fn color_state(state: SocketState) -> String {
    match state_display(state) {
        "LISTEN" | "CONNECTED" => state.green().to_string(),
        "ESTABLISHED" | "SYN-SENT" | "SYN-RECV" => state.blue().to_string(),
        "UNCONN" => state.dimmed().to_string(),
        "CLOSE-WAIT" | "FIN-WAIT-1" | "FIN-WAIT-2" | "CLOSING" | "LAST-ACK" | "TIME-WAIT" => {
            state.red().to_string()
        }
        _ => state.to_string(),
    }
}

struct AddressFormatter<'a> {
    options: &'a OutputOptions,
    resolver: Resolver,
}

impl<'a> AddressFormatter<'a> {
    fn new(options: &'a OutputOptions) -> Self {
        Self {
            options,
            resolver: Resolver::new(ResolverConfig {
                cache_enabled: options.resolver_cache,
                ..Default::default()
            }),
        }
    }

    fn format(&mut self, socket: &SocketInfo, address: &SocketAddress, local: bool) -> String {
        match address {
            SocketAddress::Inet(endpoint) => {
                let host = if self.options.resolve {
                    self.host_name(endpoint.address)
                } else {
                    endpoint.address.to_string()
                };

                let port = if socket.protocol == Protocol::Raw {
                    self.raw_protocol_name(socket, local)
                } else if self.options.numeric {
                    endpoint.port.to_string()
                } else {
                    self.service_name(endpoint.port, socket.protocol)
                };

                match endpoint.address {
                    IpAddr::V4(_) => format!("{host}:{port}"),
                    IpAddr::V6(_) => format!("[{host}]:{port}"),
                }
            }
            SocketAddress::Unix { path } => path.clone(),
        }
    }

    fn host_name(&mut self, address: IpAddr) -> String {
        self.resolver
            .host_name(address)
            .unwrap_or_else(|| address.to_string())
    }

    fn service_name(&mut self, port: u16, protocol: Protocol) -> String {
        self.resolver
            .service_name(port, protocol)
            .unwrap_or_else(|| port.to_string())
    }

    fn raw_protocol_name(&mut self, socket: &SocketInfo, local: bool) -> String {
        let Some(protocol) = socket.ip_protocol else {
            return "*".to_string();
        };
        if !local {
            return "*".to_string();
        }
        if self.options.numeric {
            return protocol.to_string();
        }

        self.resolver
            .protocol_name(protocol)
            .unwrap_or_else(|| format!("ipproto-{protocol}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressFormatter, OutputOptions, netid_text};
    use moss_core::{
        AddressFamily, Endpoint, Protocol, SocketAddress, SocketInfo, SocketMemory, SocketState,
        TcpState,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn raw_socket_uses_raw_netid_and_protocol_name_port() {
        let mut socket = socket(Protocol::Raw, AddressFamily::Ipv4);
        socket.ip_protocol = Some(1);
        let options = options(false);
        let mut formatter = AddressFormatter::new(&options);

        assert_eq!(netid_text(&socket), "raw");
        assert_eq!(
            formatter.format(&socket, &socket.local, true),
            "127.0.0.1:icmp"
        );
        assert_eq!(
            formatter.format(&socket, &socket.peer, false),
            "127.0.0.1:*"
        );
    }

    #[test]
    fn raw_protocol_port_uses_numeric_or_ipproto_fallback() {
        let mut socket = socket(Protocol::Raw, AddressFamily::Ipv4);
        socket.ip_protocol = Some(143);
        let named_options = options(false);
        let mut formatter = AddressFormatter::new(&named_options);

        assert_eq!(
            formatter.format(&socket, &socket.local, true),
            "127.0.0.1:ipproto-143"
        );

        let numeric_options = options(true);
        let mut formatter = AddressFormatter::new(&numeric_options);
        assert_eq!(
            formatter.format(&socket, &socket.local, true),
            "127.0.0.1:143"
        );
    }

    #[test]
    fn netid_includes_ip_family_suffix() {
        assert_eq!(
            netid_text(&socket(Protocol::Tcp, AddressFamily::Ipv4)),
            "tcp"
        );
        assert_eq!(
            netid_text(&socket(Protocol::Tcp, AddressFamily::Ipv6)),
            "tcp6"
        );
        assert_eq!(
            netid_text(&socket(Protocol::Tcp, AddressFamily::Ipv46)),
            "tcp46"
        );
        assert_eq!(
            netid_text(&socket(Protocol::Udp, AddressFamily::Ipv46)),
            "udp46"
        );
        assert_eq!(
            netid_text(&socket(Protocol::Raw, AddressFamily::Ipv46)),
            "raw46"
        );
        assert_eq!(
            netid_text(&socket(Protocol::UnixStream, AddressFamily::Unix)),
            "u_str"
        );
    }

    #[test]
    fn summary_counts_raw_separately() {
        let summary = super::SocketSummary::from_sockets(&[
            socket(Protocol::Raw, AddressFamily::Ipv4),
            socket(Protocol::Raw, AddressFamily::Ipv6),
            socket(Protocol::Udp, AddressFamily::Ipv4),
        ]);

        assert_eq!(summary.raw, 2);
        assert_eq!(summary.udp, 1);
        assert_eq!(summary.tcp, 0);
    }

    fn socket(protocol: Protocol, family: AddressFamily) -> SocketInfo {
        let local = match family {
            AddressFamily::Ipv4 => SocketAddress::Inet(Endpoint {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            }),
            AddressFamily::Ipv6 | AddressFamily::Ipv46 => SocketAddress::Inet(Endpoint {
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 0,
            }),
            AddressFamily::Unix => SocketAddress::Unix {
                path: "*".to_string(),
            },
        };

        SocketInfo {
            protocol,
            ip_protocol: None,
            family,
            state: SocketState::Tcp(TcpState::Listen),
            recv_queue: 0,
            send_queue: 0,
            local: local.clone(),
            peer: local,
            uid: 0,
            socket_handle: 0,
            pcb_handle: 0,
            memory: SocketMemory {
                recv_bytes: 0,
                recv_high_water: 0,
                recv_mbuf_bytes: 0,
                recv_mbuf_limit: 0,
                send_bytes: 0,
                send_high_water: 0,
                send_mbuf_bytes: 0,
                send_mbuf_limit: 0,
            },
            process: None,
        }
    }

    fn options(numeric: bool) -> OutputOptions {
        OutputOptions {
            show_processes: false,
            numeric,
            resolve: false,
            resolver_cache: false,
            extended: false,
            memory: false,
        }
    }
}
