use crate::model::{AddressFamily, Protocol, SocketAddress, SocketInfo, TcpState};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

#[derive(Debug, Clone, Default)]
pub struct SocketFilter {
    pub protocols: Vec<Protocol>,
    pub family: Option<AddressFamily>,
    pub listening: bool,
    pub all: bool,
    pub expression: Option<FilterExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterExpression {
    Predicate(Predicate),
    And(Box<FilterExpression>, Box<FilterExpression>),
    Or(Box<FilterExpression>, Box<FilterExpression>),
    Not(Box<FilterExpression>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    State(Vec<TcpState>),
    Port {
        side: EndpointSide,
        op: CompareOp,
        port: u16,
    },
    Address {
        side: EndpointSide,
        matcher: AddressMatcher,
    },
    UnixPath(PathMatcher),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSide {
    Local,
    Peer,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressMatcher {
    Exact(IpAddr),
    Network(IpNetwork),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatcher {
    pattern: String,
}

impl SocketFilter {
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        if !self.protocols.is_empty() && !self.protocols.contains(&socket.protocol) {
            return false;
        }

        if let Some(family) = self.family
            && socket.family != family
        {
            return false;
        }

        if !self.all && self.listening && !self.matches_state(socket) {
            return false;
        }

        if let Some(expression) = &self.expression
            && !expression.matches(socket)
        {
            return false;
        }

        true
    }

    fn matches_state(&self, socket: &SocketInfo) -> bool {
        let listening = socket.state.is_some_and(|state| state.is_listening())
            || (socket.protocol == Protocol::Udp && socket.peer.is_wildcard());

        self.listening && listening
    }
}

impl FilterExpression {
    pub fn parse(tokens: &[String]) -> Result<Option<Self>, String> {
        if tokens.is_empty() {
            return Ok(None);
        }
        Parser::new(tokens)?.parse().map(Some)
    }

    fn matches(&self, socket: &SocketInfo) -> bool {
        match self {
            Self::Predicate(predicate) => predicate.matches(socket),
            Self::And(left, right) => left.matches(socket) && right.matches(socket),
            Self::Or(left, right) => left.matches(socket) || right.matches(socket),
            Self::Not(expression) => !expression.matches(socket),
        }
    }
}

impl Predicate {
    fn matches(&self, socket: &SocketInfo) -> bool {
        match self {
            Self::State(states) => socket.state.is_some_and(|state| states.contains(&state)),
            Self::Port { side, op, port } => port_matches(socket, *side, *op, *port),
            Self::Address { side, matcher } => address_matches(socket, *side, *matcher),
            Self::UnixPath(matcher) => {
                matcher.matches(&socket.local) || matcher.matches(&socket.peer)
            }
        }
    }
}

impl AddressMatcher {
    fn matches(self, address: IpAddr) -> bool {
        match self {
            Self::Exact(expected) => address == expected,
            Self::Network(network) => network.contains(address),
        }
    }
}

impl PathMatcher {
    fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    fn matches(&self, address: &SocketAddress) -> bool {
        let SocketAddress::Unix { path } = address else {
            return false;
        };
        glob_matches(
            &path.to_ascii_lowercase(),
            &self.pattern.to_ascii_lowercase(),
        )
    }
}

impl IpNetwork {
    fn new(address: IpAddr, prefix_len: u8) -> Result<Self, String> {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(format!("invalid CIDR prefix length: {prefix_len}"));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                prefix_matches(u32::from(network), u32::from(address), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                prefix_matches(u128::from(network), u128::from(address), self.prefix_len)
            }
            _ => false,
        }
    }
}

fn prefix_matches<T>(network: T, address: T, prefix_len: u8) -> bool
where
    T: Copy
        + From<u8>
        + PartialEq
        + std::ops::BitAnd<Output = T>
        + std::ops::Not<Output = T>
        + std::ops::Sub<Output = T>
        + std::ops::Shl<u8, Output = T>,
{
    if prefix_len == 0 {
        return true;
    }
    let bits = (size_of::<T>() * 8) as u8;
    let mask = !((T::from(1) << (bits - prefix_len)) - T::from(1));
    (network & mask) == (address & mask)
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Compare(CompareOp),
    Word(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CompareOp {
    fn compare(self, candidate: u16, port: u16) -> bool {
        match self {
            Self::Eq => candidate == port,
            Self::Ne => candidate != port,
            Self::Lt => candidate < port,
            Self::Le => candidate <= port,
            Self::Gt => candidate > port,
            Self::Ge => candidate >= port,
        }
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }

        match ch {
            '(' => tokens.push(Token::LParen),
            ')' => tokens.push(Token::RParen),
            '!' => {
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Compare(CompareOp::Ne));
                } else {
                    tokens.push(Token::Not);
                }
            }
            '=' => {
                if chars.peek() == Some(&'=') {
                    chars.next();
                }
                tokens.push(Token::Compare(CompareOp::Eq));
            }
            '<' | '>' => {
                let has_equals = chars.peek() == Some(&'=');
                if has_equals {
                    chars.next();
                }
                tokens.push(Token::Compare(match (ch, has_equals) {
                    ('<', false) => CompareOp::Lt,
                    ('<', true) => CompareOp::Le,
                    ('>', false) => CompareOp::Gt,
                    ('>', true) => CompareOp::Ge,
                    _ => unreachable!("only < and > are handled here"),
                }));
            }
            '&' | '|' => {
                if chars.peek() == Some(&ch) {
                    chars.next();
                }
                tokens.push(if ch == '&' { Token::And } else { Token::Or });
            }
            '\'' | '"' => {
                let mut token = String::new();
                for quoted in chars.by_ref() {
                    if quoted == ch {
                        break;
                    }
                    token.push(quoted);
                }
                if looks_like_quoted_expression(&token) {
                    tokens.extend(tokenize(&token)?);
                } else {
                    tokens.push(Token::Word(token));
                }
            }
            _ => {
                let mut token = ch.to_string();
                while let Some(next) = chars.peek() {
                    if next.is_whitespace()
                        || matches!(next, '(' | ')' | '!' | '=' | '<' | '>' | '&' | '|')
                    {
                        break;
                    }
                    token.push(chars.next().expect("peeked character must exist"));
                }
                tokens.push(classify_word(token));
            }
        }
    }

    Ok(tokens)
}

fn looks_like_quoted_expression(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('(') && value.ends_with(')')
}

fn classify_word(token: String) -> Token {
    match token.to_ascii_lowercase().as_str() {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "eq" => Token::Compare(CompareOp::Eq),
        "ne" | "neq" => Token::Compare(CompareOp::Ne),
        "lt" => Token::Compare(CompareOp::Lt),
        "le" | "leq" => Token::Compare(CompareOp::Le),
        "gt" => Token::Compare(CompareOp::Gt),
        "ge" | "geq" => Token::Compare(CompareOp::Ge),
        _ => Token::Word(token),
    }
}

// ---------------------------------------------------------------------------
// Recursive descent parser
//
// Grammar:
//   expr              → or_expr
//   or_expr           → and_expr ( "or" and_expr )*
//   and_expr          → primary ( "and" primary )*
//   primary           → "not" primary | "(" expr ")" | predicate
//   predicate         → state_predicate
//                     | port_predicate
//                     | address_predicate
//                     | path_predicate
//   state_predicate   → ("state" | "exclude") [op] state_set
//   port_predicate    → ("sport" | "dport" | "port") [op] port
//   address_predicate → ("src" | "dst" | "addr" | "address") ["=" | "=="] address
//   path_predicate    → "path" ["=" | "=="] path
//   op                → "=" | "==" | "!=" | "<" | ">" | "<=" | ">="
//                     | "eq" | "ne" | "neq" | "lt" | "gt" | "le" | "leq"
//                     | "ge" | "geq"
//
// Boolean aliases are also accepted: && for "and", || for "or", and ! for
// "not". Address values may be IPs, CIDR ranges, host[:port] values, :port
// wildcards, unix:path values, or Unix path globs.
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: &[String]) -> Result<Self, String> {
        let input = tokens.join(" ");
        Ok(Self {
            tokens: tokenize(&input)?,
            pos: 0,
        })
    }

    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.at_end() {
            None
        } else {
            let token = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(token)
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), String> {
        match self.advance() {
            Some(ref token) if token == expected => Ok(()),
            Some(tok) => Err(format!("expected {expected:?}, got {tok:?}")),
            None => Err(format!("expected {expected:?}, got end of expression")),
        }
    }

    fn expect_word(&mut self, message: &str) -> Result<String, String> {
        match self.advance() {
            Some(Token::Word(word)) => Ok(word),
            Some(token) => Err(format!("{message}: got {token:?}")),
            None => Err(message.to_string()),
        }
    }

    fn parse(mut self) -> Result<FilterExpression, String> {
        let expression = self.parse_or()?;
        if !self.at_end() {
            return Err(format!("unexpected token: {:?}", self.tokens[self.pos]));
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<FilterExpression, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = FilterExpression::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpression, String> {
        let mut left = self.parse_primary()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_primary()?;
            left = FilterExpression::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<FilterExpression, String> {
        match self.peek() {
            Some(Token::Not) => {
                self.advance();
                let expr = self.parse_primary()?;
                Ok(FilterExpression::Not(Box::new(expr)))
            }
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_or()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }
            Some(Token::Word(_)) => self.parse_predicate(),
            Some(tok) => Err(format!("unexpected token: {tok:?}")),
            None => Err("unexpected end of expression".to_string()),
        }
    }

    fn parse_predicate(&mut self) -> Result<FilterExpression, String> {
        let keyword = self.expect_word("expected filter predicate")?;
        match keyword.to_ascii_lowercase().as_str() {
            "state" => self.parse_state_predicate(false),
            "exclude" => self.parse_state_predicate(true),
            "sport" => self.parse_port_predicate(EndpointSide::Local),
            "dport" => self.parse_port_predicate(EndpointSide::Peer),
            "port" => self.parse_port_predicate(EndpointSide::Any),
            "src" => self.parse_address_predicate(EndpointSide::Local),
            "dst" => self.parse_address_predicate(EndpointSide::Peer),
            "addr" | "address" => self.parse_address_predicate(EndpointSide::Any),
            "path" => self.parse_unix_path_predicate(),
            "dev" | "fwmark" | "cgroup" | "autobound" => {
                Err(format!("unsupported predicate: {keyword}"))
            }
            _ => Err(format!("unsupported filter expression near: {keyword}")),
        }
    }

    fn parse_state_predicate(&mut self, exclude: bool) -> Result<FilterExpression, String> {
        self.consume_comparison_operator();
        let value = self.expect_word("expected state in filter expression")?;
        let expression = state_expression(parse_state_set(&value)?);
        if exclude {
            Ok(FilterExpression::Not(Box::new(expression)))
        } else {
            Ok(expression)
        }
    }

    fn parse_port_predicate(&mut self, side: EndpointSide) -> Result<FilterExpression, String> {
        let op = self.consume_comparison_operator().unwrap_or(CompareOp::Eq);
        let value = self.expect_word("expected port in filter expression")?;
        let port = parse_port(&value)?;
        Ok(port_expression(side, op, port))
    }

    fn parse_address_predicate(&mut self, side: EndpointSide) -> Result<FilterExpression, String> {
        if let Some(op) = self.consume_comparison_operator()
            && op != CompareOp::Eq
        {
            return Err("address filters only support equality comparisons".to_string());
        }
        let value = self.expect_word("expected address in filter expression")?;

        if looks_like_port(&value) {
            return Ok(port_expression(side, CompareOp::Eq, parse_port(&value)?));
        }

        let family = family_prefix(&value);
        let value = strip_family_prefix(&value);
        if matches!(family, Some("unix")) {
            return Ok(path_expression(value));
        }

        let (host, port) = split_host_port(value);
        let port = port.map(parse_port).transpose()?;
        if host == "*" {
            return port
                .map(|port| port_expression(side, CompareOp::Eq, port))
                .ok_or_else(|| "address wildcard requires a port".to_string());
        }

        let network = match parse_network(host) {
            Ok(network) => network,
            Err(_) if looks_like_unix_path(value) => {
                return Ok(path_expression(value));
            }
            Err(err) => return Err(err),
        };
        let address = address_expression(side, network);
        Ok(if let Some(port) = port {
            FilterExpression::And(
                Box::new(address),
                Box::new(port_expression(side, CompareOp::Eq, port)),
            )
        } else {
            address
        })
    }

    fn parse_unix_path_predicate(&mut self) -> Result<FilterExpression, String> {
        if let Some(op) = self.consume_comparison_operator()
            && op != CompareOp::Eq
        {
            return Err("path filters only support equality comparisons".to_string());
        }
        let value = self.expect_word("expected path in filter expression")?;
        Ok(path_expression(value))
    }

    fn consume_comparison_operator(&mut self) -> Option<CompareOp> {
        let Token::Compare(op) = self.peek()? else {
            return None;
        };
        let op = *op;
        self.pos += 1;
        Some(op)
    }
}

fn state_expression(states: Vec<TcpState>) -> FilterExpression {
    FilterExpression::Predicate(Predicate::State(states))
}

fn port_expression(side: EndpointSide, op: CompareOp, port: u16) -> FilterExpression {
    FilterExpression::Predicate(Predicate::Port { side, op, port })
}

fn path_expression(pattern: impl Into<String>) -> FilterExpression {
    FilterExpression::Predicate(Predicate::UnixPath(PathMatcher::new(pattern)))
}

fn address_expression(side: EndpointSide, network: IpNetwork) -> FilterExpression {
    let exact_prefix = match network.address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let matcher = if network.prefix_len == exact_prefix {
        AddressMatcher::Exact(network.address)
    } else {
        AddressMatcher::Network(network)
    };
    FilterExpression::Predicate(Predicate::Address { side, matcher })
}

fn port_matches(socket: &SocketInfo, side: EndpointSide, op: CompareOp, port: u16) -> bool {
    match side {
        EndpointSide::Local => socket
            .local
            .port()
            .is_some_and(|candidate| op.compare(candidate, port)),
        EndpointSide::Peer => socket
            .peer
            .port()
            .is_some_and(|candidate| op.compare(candidate, port)),
        EndpointSide::Any => {
            socket
                .local
                .port()
                .is_some_and(|candidate| op.compare(candidate, port))
                || socket
                    .peer
                    .port()
                    .is_some_and(|candidate| op.compare(candidate, port))
        }
    }
}

fn address_matches(socket: &SocketInfo, side: EndpointSide, matcher: AddressMatcher) -> bool {
    match side {
        EndpointSide::Local => socket.local.ip().is_some_and(|ip| matcher.matches(ip)),
        EndpointSide::Peer => socket.peer.ip().is_some_and(|ip| matcher.matches(ip)),
        EndpointSide::Any => {
            socket.local.ip().is_some_and(|ip| matcher.matches(ip))
                || socket.peer.ip().is_some_and(|ip| matcher.matches(ip))
        }
    }
}

fn glob_matches(value: &str, pattern: &str) -> bool {
    fn matches(value: &[u8], pattern: &[u8]) -> bool {
        match pattern {
            [] => value.is_empty(),
            [b'*', rest @ ..] => {
                matches(value, rest) || (!value.is_empty() && matches(&value[1..], pattern))
            }
            [b'?', rest @ ..] => !value.is_empty() && matches(&value[1..], rest),
            [ch, rest @ ..] => value.first() == Some(ch) && matches(&value[1..], rest),
        }
    }

    matches(value.as_bytes(), pattern.as_bytes())
}

fn looks_like_port(value: &str) -> bool {
    let value = value.trim_start_matches('=');
    value.starts_with(':') || value.chars().all(|ch| ch.is_ascii_digit())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let value = strip_family_prefix(value)
        .trim_start_matches('=')
        .trim_start_matches(':');
    value
        .parse()
        .or_else(|_| resolve_service_name(value))
        .map_err(|_| format!("invalid port in filter expression: {value}"))
}

fn resolve_service_name(value: &str) -> Result<u16, ()> {
    let name = CString::new(value).map_err(|_| ())?;
    for proto in [c"tcp", c"udp"] {
        let service = unsafe { libc::getservbyname(name.as_ptr(), proto.as_ptr()) };
        if !service.is_null() {
            return Ok(u16::from_be(unsafe { (*service).s_port as u16 }));
        }
    }
    Err(())
}

fn parse_network(value: &str) -> Result<IpNetwork, String> {
    let value = strip_family_prefix(value)
        .trim_start_matches('=')
        .trim_matches(|ch| ch == '[' || ch == ']');
    let (address, prefix_len) = match value.split_once('/') {
        Some((address, prefix_len)) => (address, Some(prefix_len)),
        None => (value, None),
    };
    let address = parse_ip(address)?;
    let prefix_len = match (address, prefix_len) {
        (IpAddr::V4(_), Some(prefix_len)) => prefix_len
            .parse()
            .map_err(|_| format!("invalid CIDR prefix length: {prefix_len}"))?,
        (IpAddr::V6(_), Some(prefix_len)) => prefix_len
            .parse()
            .map_err(|_| format!("invalid CIDR prefix length: {prefix_len}"))?,
        (IpAddr::V4(_), None) => 32,
        (IpAddr::V6(_), None) => 128,
    };
    IpNetwork::new(address, prefix_len)
}

fn split_host_port(value: &str) -> (&str, Option<&str>) {
    if let Some(rest) = value.strip_prefix('[')
        && let Some((address, port)) = rest.split_once("]:")
    {
        return (address, Some(port));
    }

    if let Some(port) = value.strip_prefix(':') {
        return ("*", Some(port));
    }

    if value.matches(':').count() == 1
        && let Some((host, port)) = value.rsplit_once(':')
        && !port.is_empty()
    {
        return (host, Some(port));
    }

    (value, None)
}

fn looks_like_unix_path(value: &str) -> bool {
    value.starts_with('/') || value.contains('*') || value.contains('?')
}

fn parse_ip(value: &str) -> Result<IpAddr, String> {
    if let Ok(address) = IpAddr::from_str(value) {
        return Ok(address);
    }
    if let Some(address) = parse_short_ipv4(value) {
        return Ok(IpAddr::V4(address));
    }
    resolve_host_name(value).ok_or_else(|| format!("invalid address in filter expression: {value}"))
}

fn resolve_host_name(value: &str) -> Option<IpAddr> {
    (value, 0)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|address| address.ip())
}

fn parse_short_ipv4(value: &str) -> Option<Ipv4Addr> {
    let octets: Vec<u8> = value
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }

    let mut address = [0; 4];
    address[..octets.len()].copy_from_slice(&octets);
    Some(Ipv4Addr::from(address))
}

fn parse_state_set(value: &str) -> Result<Vec<TcpState>, String> {
    let normalized = value.to_ascii_lowercase().replace('_', "-");
    let states = match normalized.as_str() {
        "all" => TcpState::KNOWN.to_vec(),
        "connected" => matching_states(TcpState::is_connected),
        "synchronized" => matching_states(TcpState::is_synchronized),
        "bucket" => matching_states(TcpState::is_bucket),
        "big" => matching_states(TcpState::is_big),
        _ => vec![value.parse()?],
    };
    Ok(states)
}

fn matching_states(predicate: impl Fn(TcpState) -> bool) -> Vec<TcpState> {
    TcpState::KNOWN
        .to_vec()
        .into_iter()
        .filter(|state| predicate(*state))
        .collect()
}

fn family_prefix(value: &str) -> Option<&str> {
    value
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .filter(|prefix| matches!(*prefix, "inet" | "inet6" | "unix"))
}

fn strip_family_prefix(value: &str) -> &str {
    value
        .split_once(':')
        .filter(|(prefix, _)| matches!(*prefix, "inet" | "inet6" | "unix"))
        .map_or(value, |(_, rest)| rest)
}

pub fn filter_sockets(sockets: Vec<SocketInfo>, filter: &SocketFilter) -> Vec<SocketInfo> {
    sockets
        .into_iter()
        .filter(|socket| filter.matches(socket))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Endpoint, ProcessInfo, SocketMemory, TcpState};

    fn socket(
        protocol: Protocol,
        state: Option<TcpState>,
        local_port: u16,
        peer_port: u16,
    ) -> SocketInfo {
        socket_with_addrs(
            protocol,
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer_port,
        )
    }

    fn socket_with_addrs(
        protocol: Protocol,
        state: Option<TcpState>,
        local_address: IpAddr,
        local_port: u16,
        peer_address: IpAddr,
        peer_port: u16,
    ) -> SocketInfo {
        SocketInfo {
            protocol,
            family: if local_address.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            },
            state,
            recv_queue: 0,
            send_queue: 0,
            local: SocketAddress::Inet(Endpoint {
                address: local_address,
                port: local_port,
            }),
            peer: SocketAddress::Inet(Endpoint {
                address: peer_address,
                port: peer_port,
            }),
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
            process: Some(ProcessInfo {
                pid: 1,
                fd: 2,
                name: "test".to_string(),
            }),
        }
    }

    fn unix_socket(local: &str, peer: &str) -> SocketInfo {
        SocketInfo {
            protocol: Protocol::UnixStream,
            family: AddressFamily::Unix,
            state: None,
            recv_queue: 0,
            send_queue: 0,
            local: SocketAddress::Unix {
                path: local.to_string(),
            },
            peer: SocketAddress::Unix {
                path: peer.to_string(),
            },
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

    fn parse(input: &str) -> FilterExpression {
        FilterExpression::parse(&[input.to_string()])
            .unwrap()
            .unwrap()
    }

    #[test]
    fn filters_by_port_on_either_endpoint() {
        let filter = SocketFilter {
            expression: Some(port_expression(EndpointSide::Any, CompareOp::Eq, 443)),
            ..SocketFilter::default()
        };

        assert!(filter.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
        assert!(filter.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 443, 0)));
        assert!(!filter.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 80, 0)));
    }

    #[test]
    fn listening_matches_tcp_listen_and_unconnected_udp() {
        let filter = SocketFilter {
            listening: true,
            ..SocketFilter::default()
        };

        assert!(filter.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 22, 0)));
        assert!(filter.matches(&socket(Protocol::Udp, None, 53, 0)));
        assert!(!filter.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
    }

    #[test]
    fn parses_ss_style_port_expression() {
        let expression = FilterExpression::parse(&["sport".to_string(), "=:443".to_string()])
            .unwrap()
            .unwrap();

        assert_eq!(
            expression,
            port_expression(EndpointSide::Local, CompareOp::Eq, 443)
        );
    }

    #[test]
    fn parses_boolean_expressions_with_grouping() {
        let expression = parse("state established and ( dport = :443 or sport = :443 )");

        assert!(expression.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
        assert!(expression.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            443,
            50_000
        )));
        assert!(!expression.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 443, 0)));
    }

    #[test]
    fn parses_boolean_expressions_with_complex_grouping() {
        let expression = parse(
            "state fin-wait-1 and '( sport = :http or sport = :https )' and dst 193.233.7/24",
        );

        assert!(expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::FinWait1),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::new(193, 233, 7, 10)),
            50_000,
        )));
        assert!(expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::FinWait1),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            443,
            IpAddr::V4(Ipv4Addr::new(193, 233, 7, 10)),
            50_000,
        )));
        assert!(!expression.matches(&socket(Protocol::Tcp, Some(TcpState::FinWait1), 80, 50_000,)));
        assert!(!expression.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 443, 0)));
    }
    #[test]
    fn parses_port_comparison_aliases() {
        let greater = parse("sport gt :1024");
        let not_equal = parse("dport ne :443");

        assert!(greater.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
        assert!(!greater.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 80, 0)));
        assert!(not_equal.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            80
        )));
        assert!(!not_equal.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
    }

    #[test]
    fn parses_state_sets_and_exclusions() {
        let connected = parse("state connected");
        let exclude_listen = parse("exclude listening");

        assert!(connected.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            443
        )));
        assert!(!connected.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 22, 0)));
        assert!(!exclude_listen.matches(&socket(Protocol::Tcp, Some(TcpState::Listen), 22, 0)));
    }

    #[test]
    fn parses_cidr_address_filters() {
        let expression = parse("dst 193.233.7/24");

        assert!(expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::Established),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::new(193, 233, 7, 10)),
            50_000,
        )));
        assert!(!expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::Established),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IpAddr::V4(Ipv4Addr::new(193, 233, 8, 10)),
            50_000,
        )));
    }

    #[test]
    fn parses_host_filters_with_ports() {
        let expression = parse("dst 203.0.113.10:https");

        assert!(expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::Established),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            50_000,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            443,
        )));
        assert!(!expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::Established),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            50_000,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            80,
        )));
    }

    #[test]
    fn parses_bracketed_ipv6_host_filters_with_ports() {
        let expression = parse("dst [2001:db8::1]:443");

        assert!(expression.matches(&socket_with_addrs(
            Protocol::Tcp,
            Some(TcpState::Established),
            IpAddr::V6("::1".parse().unwrap()),
            50_000,
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            443,
        )));
    }

    #[test]
    fn parses_unix_glob_paths_case_insensitively() {
        let expression = parse("src /tmp/.x11-unix/*");

        assert!(expression.matches(&unix_socket("/tmp/.X11-unix/X0", "*")));
        assert!(!expression.matches(&unix_socket("/tmp/other", "*")));
    }

    #[test]
    fn resolves_common_service_names_for_ports() {
        let expression = parse("dport = :ssh");

        assert!(expression.matches(&socket(
            Protocol::Tcp,
            Some(TcpState::Established),
            50_000,
            22
        )));
    }

    #[test]
    fn rejects_predicates_without_socket_model_support() {
        assert!(FilterExpression::parse(&["dev eth0".to_string()]).is_err());
        assert!(FilterExpression::parse(&["fwmark = 1".to_string()]).is_err());
        assert!(FilterExpression::parse(&["cgroup /user.slice".to_string()]).is_err());
        assert!(FilterExpression::parse(&["autobound".to_string()]).is_err());
        assert!(FilterExpression::parse(&["dst != 127.0.0.1".to_string()]).is_err());
    }
}
