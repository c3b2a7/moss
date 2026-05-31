use moss_core::{Protocol, Resolver, ResolverConfig, SocketAddress, SocketInfo, TcpState};
use owo_colors::OwoColorize;
use std::net::IpAddr;

pub struct OutputOptions {
    pub show_processes: bool,
    pub numeric: bool,
    pub resolve: bool,
    pub resolver_cache: bool,
    pub extended: bool,
    pub memory: bool,
}

pub fn print_sockets(sockets: &[SocketInfo], options: &OutputOptions) {
    let mut formatter = AddressFormatter::new(options);
    let rows: Vec<SocketRow> = sockets
        .iter()
        .map(|socket| SocketRow {
            netid: socket.protocol.to_string(),
            state: state_text(socket),
            recv_queue: socket.recv_queue.to_string(),
            send_queue: socket.send_queue.to_string(),
            local: formatter.format(&socket.local, socket.protocol),
            peer: formatter.format(&socket.peer, socket.protocol),
            process: socket.process.as_ref().map(ToString::to_string),
        })
        .collect();

    let widths = SocketWidths::new(&rows);
    println!("{}", widths.header(options.show_processes));

    for (socket, row) in sockets.iter().zip(rows.iter()) {
        println!("{}", widths.row(row));

        if options.extended {
            println!(
                "       uid:{} sk:{:#x} pcb:{:#x}",
                socket.uid, socket.socket_handle, socket.pcb_handle
            );
        }
        if options.memory {
            let mem = socket.memory;
            println!(
                "       skmem:(r{},rb{},rm{},rmb{},t{},tb{},tm{},tmb{})",
                mem.recv_bytes,
                mem.recv_high_water,
                mem.recv_mbuf_bytes,
                mem.recv_mbuf_limit,
                mem.send_bytes,
                mem.send_high_water,
                mem.send_mbuf_bytes,
                mem.send_mbuf_limit
            );
        }
    }
}

pub fn print_summary(sockets: &[SocketInfo]) {
    let summary = SocketSummary::from_sockets(sockets);

    println!("Total: {}", sockets.len());
    println!(
        "TCP:   {} (established {}, listening {})",
        summary.tcp, summary.established, summary.listening
    );
    println!("UDP:   {}", summary.udp);
    println!("UNIX:  {}", summary.unix);
}

pub fn print_json(sockets: &[SocketInfo], pretty: bool) {
    let result = if pretty {
        serde_json::to_string_pretty(sockets)
    } else {
        serde_json::to_string(sockets)
    };

    match result {
        Ok(json) => println!("{json}"),
        Err(err) => eprintln!("moss: {err}"),
    }
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

    fn format(&mut self, address: &SocketAddress, protocol: Protocol) -> String {
        match address {
            SocketAddress::Inet(endpoint) => {
                let host = if self.options.resolve {
                    self.host_name(endpoint.address)
                } else {
                    endpoint.address.to_string()
                };
                let port = if self.options.numeric {
                    endpoint.port.to_string()
                } else {
                    self.service_name(endpoint.port, protocol)
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
}
