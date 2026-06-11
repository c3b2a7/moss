use moss_core::{Protocol, Resolver, ResolverConfig, SocketAddress, SocketInfo, TcpState};
use owo_colors::OwoColorize;
use std::io::{self, Write};
use std::net::IpAddr;

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
    let rows: Vec<SocketRow> = sockets
        .iter()
        .map(|socket| SocketRow {
            netid: netid_text(socket),
            state: state_text(socket),
            recv_queue: socket.recv_queue.to_string(),
            send_queue: socket.send_queue.to_string(),
            local: formatter.format(socket, &socket.local, true),
            peer: formatter.format(socket, &socket.peer, false),
            process: socket.process.as_ref().map(ToString::to_string),
        })
        .collect();

    let widths = SocketWidths::new(&rows);
    writeln!(out, "{}", widths.header(options.show_processes))?;

    for (socket, row) in sockets.iter().zip(rows.iter()) {
        writeln!(out, "{}", widths.row(row))?;

        if options.extended {
            writeln!(
                out,
                "       uid:{} sk:{:#x} pcb:{:#x}",
                socket.uid, socket.socket_handle, socket.pcb_handle
            )?;
        }
        if options.memory {
            let mem = socket.memory;
            writeln!(
                out,
                "       skmem:(r{},rb{},rm{},rmb{},t{},tb{},tm{},tmb{})",
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

struct SocketRow {
    netid: String,
    state: String,
    recv_queue: String,
    send_queue: String,
    local: String,
    peer: String,
    process: Option<String>,
}

struct SocketWidths {
    netid: usize,
    state: usize,
    recv_queue: usize,
    send_queue: usize,
    local: usize,
    peer: usize,
}

impl SocketWidths {
    fn new(rows: &[SocketRow]) -> Self {
        let mut widths = Self {
            netid: "Netid".len(),
            state: "State".len(),
            recv_queue: "Recv-Q".len(),
            send_queue: "Send-Q".len(),
            local: "Local Address:Port".len(),
            peer: "Peer Address:Port".len(),
        };

        for row in rows {
            widths.netid = widths.netid.max(row.netid.len());
            widths.state = widths.state.max(row.state.len());
            widths.recv_queue = widths.recv_queue.max(row.recv_queue.len());
            widths.send_queue = widths.send_queue.max(row.send_queue.len());
            widths.local = widths.local.max(row.local.len());
            widths.peer = widths.peer.max(row.peer.len());
        }

        widths
    }

    fn header(&self, show_processes: bool) -> String {
        let mut line = format!(
            "{} {} {} {} {} {}",
            format_args!("{:<width$}", "Netid", width = self.netid).bold(),
            format_args!("{:<width$}", "State", width = self.state).bold(),
            format_args!("{:>width$}", "Recv-Q", width = self.recv_queue).bold(),
            format_args!("{:>width$}", "Send-Q", width = self.send_queue).bold(),
            format_args!("{:<width$}", "Local Address:Port", width = self.local).bold(),
            format_args!("{:<width$}", "Peer Address:Port", width = self.peer).bold(),
        );
        if show_processes {
            line.push_str(&" Process".bold().to_string());
        }
        line
    }

    fn row(&self, row: &SocketRow) -> String {
        let mut line = format!(
            "{} {} {} {} {} {}",
            format_args!("{:<width$}", row.netid, width = self.netid).cyan(),
            color_state_padded(&row.state, self.state),
            format_args!("{:>width$}", row.recv_queue, width = self.recv_queue),
            format_args!("{:>width$}", row.send_queue, width = self.send_queue),
            format_args!("{:<width$}", row.local, width = self.local).yellow(),
            format_args!("{:<width$}", row.peer, width = self.peer).yellow(),
        );
        if let Some(process) = &row.process {
            line.push(' ');
            line.push_str(process);
        }
        line
    }
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
                        Some(TcpState::Established) => summary.established += 1,
                        Some(state) if state.is_listening() => summary.listening += 1,
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

fn state_text(socket: &SocketInfo) -> String {
    socket
        .state
        .map(|state| state.to_string())
        .unwrap_or_else(|| "UNCONN".to_string())
}

fn netid_text(socket: &SocketInfo) -> String {
    match (socket.protocol, socket.family) {
        (Protocol::Raw, moss_core::AddressFamily::Ipv6) => "raw6".to_string(),
        _ => socket.protocol.to_string(),
    }
}

fn color_state(state: &str) -> String {
    match state {
        "LISTEN" => state.green().to_string(),
        "ESTABLISHED" => state.blue().to_string(),
        "UNCONN" => state.dimmed().to_string(),
        _ => state.to_string(),
    }
}

fn color_state_padded(state: &str, width: usize) -> String {
    let mut text = color_state(state);
    text.push_str(&" ".repeat(width.saturating_sub(state.len())));
    text
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
        AddressFamily, Endpoint, Protocol, SocketAddress, SocketInfo, SocketMemory, TcpState,
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
    fn raw_ipv6_keeps_raw6_netid() {
        assert_eq!(
            netid_text(&socket(Protocol::Raw, AddressFamily::Ipv6)),
            "raw6"
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
            AddressFamily::Ipv6 => SocketAddress::Inet(Endpoint {
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
            state: Some(TcpState::Listen),
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
