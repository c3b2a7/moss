use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Socket transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP over IPv4 or IPv6.
    Tcp,
    /// UDP over IPv4 or IPv6.
    Udp,
    /// Unix-domain stream socket.
    UnixStream,
    /// Unix-domain datagram socket.
    UnixDatagram,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::UnixStream => f.write_str("u_str"),
            Self::UnixDatagram => f.write_str("u_dgr"),
        }
    }
}

impl Protocol {
    /// Returns true for Unix-domain socket protocols.
    pub fn is_unix(self) -> bool {
        matches!(self, Self::UnixStream | Self::UnixDatagram)
    }
}

/// Address family used by a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4 socket.
    Ipv4,
    /// IPv6 socket.
    Ipv6,
    /// Unix-domain socket.
    Unix,
}

/// IP endpoint with an address and port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    /// IP address bound to the endpoint.
    pub address: IpAddr,
    /// TCP or UDP port in host byte order.
    pub port: u16,
}

impl Endpoint {
    /// Returns true when the address is the wildcard/unspecified address.
    pub fn is_wildcard(&self) -> bool {
        self.address.is_unspecified()
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IpAddr::V4(addr) => write!(f, "{addr}:{}", self.port),
            IpAddr::V6(addr) => write!(f, "[{addr}]:{}", self.port),
        }
    }
}

/// Socket endpoint address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SocketAddress {
    /// IPv4 or IPv6 address with a port.
    Inet(Endpoint),
    /// Unix-domain socket path. `"*"` represents an unnamed or wildcard path.
    Unix { path: String },
}

impl SocketAddress {
    /// Returns true for wildcard IP endpoints or unnamed Unix paths.
    pub fn is_wildcard(&self) -> bool {
        match self {
            Self::Inet(endpoint) => endpoint.is_wildcard(),
            Self::Unix { path } => path.is_empty() || path == "*",
        }
    }

    /// Returns the port for IP sockets.
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Inet(endpoint) => Some(endpoint.port),
            Self::Unix { .. } => None,
        }
    }

    /// Returns the IP address for IP sockets.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Inet(endpoint) => Some(endpoint.address),
            Self::Unix { .. } => None,
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(endpoint) => endpoint.fmt(f),
            Self::Unix { path } if path.is_empty() => f.write_str("*"),
            Self::Unix { path } => f.write_str(path),
        }
    }
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpState {
    /// Socket is closed.
    Closed,
    /// Socket is listening for incoming connections.
    Listen,
    /// SYN has been sent.
    SynSent,
    /// SYN has been received.
    SynReceived,
    /// Connection is established.
    Established,
    /// Remote side has closed.
    CloseWait,
    /// First FIN wait state.
    FinWait1,
    /// Both sides are closing.
    Closing,
    /// Waiting for final ACK.
    LastAck,
    /// Second FIN wait state.
    FinWait2,
    /// Connection is in TIME-WAIT.
    TimeWait,
    /// A raw platform state value not known by this crate.
    Unknown(i32),
}

impl TcpState {
    /// Known TCP states, excluding [`TcpState::Unknown`].
    pub const KNOWN: &'static [Self] = &[
        Self::Closed,
        Self::Listen,
        Self::SynSent,
        Self::SynReceived,
        Self::Established,
        Self::CloseWait,
        Self::FinWait1,
        Self::Closing,
        Self::LastAck,
        Self::FinWait2,
        Self::TimeWait,
    ];

    /// Returns true for the listening state.
    pub fn is_listening(self) -> bool {
        matches!(self, Self::Listen)
    }

    /// Returns true for states representing an active or closing connection.
    pub fn is_connected(self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::SynSent
                | Self::SynReceived
                | Self::CloseWait
                | Self::FinWait1
                | Self::FinWait2
                | Self::Closing
                | Self::LastAck
                | Self::TimeWait
        )
    }

    /// Returns true for connected states except `SYN-SENT`.
    pub fn is_synchronized(self) -> bool {
        self.is_connected() && !matches!(self, Self::SynSent)
    }

    /// Returns true for the `ss` bucket state set.
    pub fn is_bucket(self) -> bool {
        matches!(self, Self::TimeWait | Self::SynReceived)
    }

    /// Returns true for the `ss` big state set.
    pub fn is_big(self) -> bool {
        !self.is_bucket()
    }
}

impl From<i32> for TcpState {
    fn from(raw: i32) -> Self {
        match raw {
            0 => Self::Closed,
            1 => Self::Listen,
            2 => Self::SynSent,
            3 => Self::SynReceived,
            4 => Self::Established,
            5 => Self::CloseWait,
            6 => Self::FinWait1,
            7 => Self::Closing,
            8 => Self::LastAck,
            9 => Self::FinWait2,
            10 => Self::TimeWait,
            other => Self::Unknown(other),
        }
    }
}

impl FromStr for TcpState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "closed" => Ok(Self::Closed),
            "listen" | "listening" => Ok(Self::Listen),
            "syn-sent" => Ok(Self::SynSent),
            "syn-recv" | "syn-received" => Ok(Self::SynReceived),
            "estab" | "established" => Ok(Self::Established),
            "close-wait" => Ok(Self::CloseWait),
            "fin-wait-1" => Ok(Self::FinWait1),
            "closing" => Ok(Self::Closing),
            "last-ack" => Ok(Self::LastAck),
            "fin-wait-2" => Ok(Self::FinWait2),
            "time-wait" => Ok(Self::TimeWait),
            _ => Err(format!("unknown state: {value}")),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("CLOSED"),
            Self::Listen => f.write_str("LISTEN"),
            Self::SynSent => f.write_str("SYN-SENT"),
            Self::SynReceived => f.write_str("SYN-RECV"),
            Self::Established => f.write_str("ESTABLISHED"),
            Self::CloseWait => f.write_str("CLOSE-WAIT"),
            Self::FinWait1 => f.write_str("FIN-WAIT-1"),
            Self::Closing => f.write_str("CLOSING"),
            Self::LastAck => f.write_str("LAST-ACK"),
            Self::FinWait2 => f.write_str("FIN-WAIT-2"),
            Self::TimeWait => f.write_str("TIME-WAIT"),
            Self::Unknown(raw) => write!(f, "UNKNOWN({raw})"),
        }
    }
}

/// Socket state across supported protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "tcp_state", rename_all = "kebab-case")]
pub enum SocketState {
    /// TCP socket state.
    Tcp(TcpState),
    /// Listening socket state for non-TCP protocols.
    Listening,
    /// Connected socket state for non-TCP protocols.
    Connected,
    /// Unconnected socket state for non-TCP protocols.
    Unconnected,
    /// State could not be derived.
    Unknown,
}

impl SocketState {
    /// Returns the underlying TCP state when available.
    pub fn tcp_state(self) -> Option<TcpState> {
        match self {
            Self::Tcp(state) => Some(state),
            Self::Listening | Self::Connected | Self::Unconnected | Self::Unknown => None,
        }
    }

    /// Returns true for listening sockets.
    pub fn is_listening(self) -> bool {
        matches!(self, Self::Tcp(state) if state.is_listening()) || matches!(self, Self::Listening)
    }
}

impl fmt::Display for SocketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(state) => state.fmt(f),
            Self::Listening => f.write_str("LISTEN"),
            Self::Connected => f.write_str("CONNECTED"),
            Self::Unconnected => f.write_str("UNCONN"),
            Self::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

/// Process metadata associated with a socket, when available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    /// Process identifier.
    pub pid: i32,
    /// File descriptor number inside the process.
    pub fd: i32,
    /// Process name reported by macOS.
    pub name: String,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(pid={},fd={})", self.name, self.pid, self.fd)
    }
}

/// Socket buffer memory counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SocketMemory {
    /// Receive queue bytes currently used.
    pub recv_bytes: u32,
    /// Receive buffer high-water mark.
    pub recv_high_water: u32,
    /// Receive mbuf bytes currently used.
    pub recv_mbuf_bytes: u32,
    /// Receive mbuf byte limit.
    pub recv_mbuf_limit: u32,
    /// Send queue bytes currently used.
    pub send_bytes: u32,
    /// Send buffer high-water mark.
    pub send_high_water: u32,
    /// Send mbuf bytes currently used.
    pub send_mbuf_bytes: u32,
    /// Send mbuf byte limit.
    pub send_mbuf_limit: u32,
}

/// A socket record returned by [`crate::list_sockets`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketInfo {
    /// Socket protocol.
    pub protocol: Protocol,
    /// Socket address family.
    pub family: AddressFamily,
    /// Protocol-specific socket state.
    pub state: SocketState,
    /// Receive queue byte count.
    pub recv_queue: u32,
    /// Send queue byte count.
    pub send_queue: u32,
    /// Local endpoint.
    pub local: SocketAddress,
    /// Peer endpoint.
    pub peer: SocketAddress,
    /// Socket owner user id when reported by the platform.
    pub uid: u32,
    /// Kernel socket pointer value, useful for correlation and debugging.
    pub socket_handle: u64,
    /// Kernel protocol control block pointer value, useful for correlation.
    pub pcb_handle: u64,
    /// Socket memory counters.
    pub memory: SocketMemory,
    /// Process metadata when requested and available.
    pub process: Option<ProcessInfo>,
}
