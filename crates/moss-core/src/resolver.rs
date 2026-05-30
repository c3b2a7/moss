use crate::model::Protocol;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const SERVICES_PATH: &str = "/etc/services";

/// Name resolver configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverConfig {
    /// Enables the per-resolver host-name cache.
    pub cache_enabled: bool,
    /// Time-to-live for cached host-name lookup results.
    pub cache_ttl: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            cache_ttl: DEFAULT_CACHE_TTL,
        }
    }
}

/// Resolver for host names and service names.
///
/// Host-name lookups use `getnameinfo` and can be cached per resolver.
/// Service-name lookups read `/etc/services` into a process-wide table.
#[derive(Debug)]
pub struct Resolver {
    config: ResolverConfig,
    host_name_cache: HashMap<IpAddr, CacheEntry<Option<String>>>,
}

impl Resolver {
    /// Creates a resolver with the provided configuration.
    pub fn new(config: ResolverConfig) -> Self {
        Self {
            config,
            host_name_cache: HashMap::new(),
        }
    }

    /// Returns the active resolver configuration.
    pub fn config(&self) -> ResolverConfig {
        self.config
    }

    /// Looks up a host name for an IP address.
    ///
    /// Returns `None` when reverse lookup fails or the address has no name.
    pub fn host_name(&mut self, address: IpAddr) -> Option<String> {
        if !self.config.cache_enabled {
            return hostname_lookup(address);
        }

        cached_lookup(
            &mut self.host_name_cache,
            address,
            self.config.cache_ttl,
            || hostname_lookup(address),
        )
    }

    /// Looks up a service name for a port and protocol.
    pub fn service_name(&mut self, port: u16, protocol: Protocol) -> Option<String> {
        service_name_lookup(port, protocol)
    }

    /// Clears cached host-name lookup results.
    pub fn clear_cache(&mut self) {
        self.host_name_cache.clear();
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(ResolverConfig::default())
    }
}

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

fn cached_lookup<K, F>(
    cache: &mut HashMap<K, CacheEntry<Option<String>>>,
    key: K,
    ttl: Duration,
    lookup: F,
) -> Option<String>
where
    K: Copy + Eq + Hash,
    F: FnOnce() -> Option<String>,
{
    if let Some(entry) = cache.get(&key)
        && !entry.is_expired()
    {
        return entry.value.clone();
    }

    let value = lookup();
    cache.insert(
        key,
        CacheEntry {
            value: value.clone(),
            expires_at: Instant::now() + ttl,
        },
    );
    value
}

/// Looks up the canonical service name for a port and protocol.
pub fn service_name_lookup(port: u16, protocol: Protocol) -> Option<String> {
    services().by_port.get(&(port, protocol)).cloned()
}

/// Looks up a TCP or UDP service port by service name.
pub fn service_port_lookup(name: &str) -> Option<u16> {
    service_port_lookup_from(services(), name)
}

fn service_port_lookup_from(services: &ServiceTables, name: &str) -> Option<u16> {
    [Protocol::Tcp, Protocol::Udp]
        .into_iter()
        .find_map(|protocol| services.by_name.get(&(name.to_string(), protocol)).copied())
}

fn services() -> &'static ServiceTables {
    static SERVICES: OnceLock<ServiceTables> = OnceLock::new();

    SERVICES.get_or_init(|| parse_services(&fs::read_to_string(SERVICES_PATH).unwrap_or_default()))
}

#[derive(Debug, Default)]
struct ServiceTables {
    by_port: HashMap<(u16, Protocol), String>,
    by_name: HashMap<(String, Protocol), u16>,
}

fn parse_services(contents: &str) -> ServiceTables {
    let mut services = ServiceTables::default();

    for line in contents.lines() {
        let line = line.split_once('#').map_or(line, |(line, _)| line);
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(port_protocol) = fields.next() else {
            continue;
        };
        let Some((port, protocol)) = parse_port_protocol(port_protocol) else {
            continue;
        };

        services
            .by_port
            .entry((port, protocol))
            .or_insert_with(|| name.to_string());
        services
            .by_name
            .entry((name.to_string(), protocol))
            .or_insert(port);
        for alias in fields {
            services
                .by_name
                .entry((alias.to_string(), protocol))
                .or_insert(port);
        }
    }

    services
}

fn parse_port_protocol(value: &str) -> Option<(u16, Protocol)> {
    let (port, protocol) = value.split_once('/')?;
    let port = port.parse().ok()?;
    let protocol = match protocol {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };

    Some((port, protocol))
}

/// Performs an uncached reverse host-name lookup.
pub fn hostname_lookup(address: IpAddr) -> Option<String> {
    let mut host = [0i8; libc::NI_MAXHOST as usize];
    let rc = match address {
        IpAddr::V4(address) => {
            let sockaddr = libc::sockaddr_in {
                sin_len: size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as u8,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::getnameinfo(
                    (&sockaddr as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(address) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_len: size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: address.octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::getnameinfo(
                    (&sockaddr as *const libc::sockaddr_in6).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if rc == 0 {
        Some(
            unsafe { CStr::from_ptr(host.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_services_by_port_and_protocol() {
        let services = parse_services(
            r#"
http      80/tcp    www www-http # WorldWideWeb HTTP
domain    53/udp
domain    53/tcp
different 1234/udp
different 4321/tcp
ignored   9/sctp
override  80/tcp
"#,
        );

        assert_eq!(
            services.by_port.get(&(80, Protocol::Tcp)),
            Some(&"http".to_string())
        );
        assert_eq!(
            services.by_port.get(&(53, Protocol::Udp)),
            Some(&"domain".to_string())
        );
        assert_eq!(
            services.by_port.get(&(53, Protocol::Tcp)),
            Some(&"domain".to_string())
        );
        assert_eq!(
            services.by_name.get(&("www".to_string(), Protocol::Tcp)),
            Some(&80)
        );
        assert_eq!(
            services
                .by_name
                .get(&("www-http".to_string(), Protocol::Tcp)),
            Some(&80)
        );
        assert_eq!(
            services
                .by_name
                .get(&("override".to_string(), Protocol::Tcp)),
            Some(&80)
        );
        assert_eq!(
            services
                .by_name
                .get(&("different".to_string(), Protocol::Tcp)),
            Some(&4321)
        );
        assert_eq!(
            services
                .by_name
                .get(&("different".to_string(), Protocol::Udp)),
            Some(&1234)
        );
        assert!(!services.by_port.contains_key(&(9, Protocol::Tcp)));
    }

    #[test]
    fn resolves_service_ports_with_tcp_preferred() {
        let services = parse_services(
            r#"
different 1234/udp
different 4321/tcp
"#,
        );

        assert_eq!(service_port_lookup_from(&services, "different"), Some(4321));
    }

    #[test]
    fn exposes_resolver_configuration_and_cache_controls() {
        let config = ResolverConfig {
            cache_enabled: false,
            cache_ttl: Duration::from_secs(42),
        };
        let mut resolver = Resolver::new(config);

        assert_eq!(resolver.config(), config);
        resolver.clear_cache();
        assert_eq!(resolver.config(), config);
    }
}
