use crate::model::Protocol;
use std::collections::HashMap;
use std::ffi::CStr;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverConfig {
    pub cache_enabled: bool,
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

#[derive(Debug)]
pub struct Resolver {
    config: ResolverConfig,
    host_name_cache: HashMap<IpAddr, CacheEntry<Option<String>>>,
    service_name_cache: HashMap<(u16, Protocol), CacheEntry<Option<String>>>,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Self {
        Self {
            config,
            host_name_cache: HashMap::new(),
            service_name_cache: HashMap::new(),
        }
    }

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

    pub fn service_name(&mut self, port: u16, protocol: Protocol) -> Option<String> {
        if !self.config.cache_enabled {
            return service_name_lookup(port, protocol);
        }

        cached_lookup(
            &mut self.service_name_cache,
            (port, protocol),
            self.config.cache_ttl,
            || service_name_lookup(port, protocol),
        )
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

pub fn service_name_lookup(port: u16, protocol: Protocol) -> Option<String> {
    let proto = match protocol {
        Protocol::Tcp => c"tcp",
        Protocol::Udp => c"udp",
        Protocol::UnixStream | Protocol::UnixDatagram => return None,
    };

    if port == 0 {
        return None;
    }

    let service = unsafe { libc::getservbyport(port.to_be() as i32, proto.as_ptr()) };
    if service.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr((*service).s_name) };
    Some(name.to_string_lossy().into_owned())
}

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
