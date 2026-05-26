use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    UnixStream,
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
    pub fn is_unix(self) -> bool {
        matches!(self, Self::UnixStream | Self::UnixDatagram)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
    Unix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl Endpoint {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SocketAddress {
    Inet(Endpoint),
    Unix { path: String },
}

impl SocketAddress {
    pub fn is_wildcard(&self) -> bool {
        match self {
            Self::Inet(endpoint) => endpoint.is_wildcard(),
            Self::Unix { path } => path.is_empty() || path == "*",
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Inet(endpoint) => Some(endpoint.port),
            Self::Unix { .. } => None,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
    Unknown(i32),
}

impl TcpState {
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

    pub fn is_listening(self) -> bool {
        matches!(self, Self::Listen)
    }

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

    pub fn is_synchronized(self) -> bool {
        self.is_connected() && !matches!(self, Self::SynSent)
    }

    pub fn is_bucket(self) -> bool {
        matches!(self, Self::TimeWait | Self::SynReceived)
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub fd: i32,
    pub name: String,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(pid={},fd={})", self.name, self.pid, self.fd)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SocketMemory {
    pub recv_bytes: u32,
    pub recv_high_water: u32,
    pub recv_mbuf_bytes: u32,
    pub recv_mbuf_limit: u32,
    pub send_bytes: u32,
    pub send_high_water: u32,
    pub send_mbuf_bytes: u32,
    pub send_mbuf_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub family: AddressFamily,
    pub state: Option<TcpState>,
    pub recv_queue: u32,
    pub send_queue: u32,
    pub local: SocketAddress,
    pub peer: SocketAddress,
    pub uid: u32,
    pub socket_handle: u64,
    pub pcb_handle: u64,
    pub memory: SocketMemory,
    pub process: Option<ProcessInfo>,
}
