use crate::model::{
    AddressFamily, Endpoint, ProcessInfo, Protocol, SocketAddress, SocketInfo, SocketMemory,
    TcpState,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use moss_sys as ffi;

/// Error returned while collecting socket data from macOS.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `sysctlbyname` socket query failed.
    #[error("sysctl {name} failed: {source}")]
    Sysctl {
        /// Name of the sysctl that failed.
        name: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
}

type ProcessIndex = HashMap<(u64, u64), ProcessInfo>;

/// Controls which socket data [`list_sockets`] should collect.
#[derive(Debug, Clone, Copy)]
pub struct SocketQuery {
    /// Include process name, pid, and file descriptor metadata when available.
    pub include_processes: bool,
    /// Include TCP sockets.
    pub include_tcp: bool,
    /// Include UDP sockets.
    pub include_udp: bool,
    /// Include raw sockets.
    pub include_raw: bool,
    /// Include Unix-domain sockets.
    pub include_unix: bool,
}

impl Default for SocketQuery {
    fn default() -> Self {
        Self {
            include_processes: false,
            include_tcp: true,
            include_udp: true,
            include_raw: false,
            include_unix: false,
        }
    }
}

/// Lists macOS sockets matching the requested protocol groups.
///
/// By default, [`SocketQuery`] collects TCP and UDP sockets without process
/// metadata. Unix-domain sockets and process metadata require walking process
/// file descriptors through `libproc`, so those options can be slower and may
/// omit data hidden by macOS permissions.
pub fn list_sockets(query: SocketQuery) -> Result<Vec<SocketInfo>, Error> {
    let processes = if query.include_processes {
        process_index()
    } else {
        HashMap::new()
    };

    let mut sockets = Vec::new();
    if query.include_tcp {
        sockets.extend(list_tcp(&processes)?);
    }
    if query.include_udp {
        sockets.extend(list_udp(&processes)?);
    }
    if query.include_raw {
        sockets.extend(list_raw(&processes)?);
    }
    if query.include_unix {
        sockets.extend(list_unix(query.include_processes));
    }
    sockets.sort_by_key(|socket| {
        (
            socket.protocol as u8,
            socket.family as u8,
            socket.local.to_string(),
            socket.peer.to_string(),
        )
    });
    Ok(sockets)
}

fn list_tcp(processes: &ProcessIndex) -> Result<Vec<SocketInfo>, Error> {
    let buf = sysctl_bytes("net.inet.tcp.pcblist64")?;
    let mut sockets = Vec::new();
    let mut offset = size_of::<ffi::xinpgen>();

    while offset + size_of::<u32>() <= buf.len() {
        let len = read_unaligned::<u32>(&buf[offset..]) as usize;
        if len == 0 || offset + len > buf.len() || len == size_of::<ffi::xinpgen>() {
            break;
        }
        if len >= size_of::<ffi::xtcpcb64>() {
            let raw = read_unaligned::<ffi::xtcpcb64>(&buf[offset..]);
            if let Some(socket) = tcp_socket(raw, processes) {
                sockets.push(socket);
            }
        }
        offset += len;
    }

    Ok(sockets)
}

fn list_udp(processes: &ProcessIndex) -> Result<Vec<SocketInfo>, Error> {
    let buf = sysctl_bytes("net.inet.udp.pcblist64")?;
    let mut sockets = Vec::new();
    let mut offset = size_of::<ffi::xinpgen>();

    while offset + size_of::<u32>() <= buf.len() {
        let small_len = read_unaligned::<u32>(&buf[offset..]) as usize;
        if small_len == 0 || small_len == size_of::<ffi::xinpgen>() {
            break;
        }
        let len = read_unaligned::<u64>(&buf[offset..]) as usize;
        if len == 0 || offset + len > buf.len() {
            break;
        }
        if len >= size_of::<ffi::xinpcb64>() {
            let raw = read_unaligned::<ffi::xinpcb64>(&buf[offset..]);
            if let Some(socket) = udp_socket(raw, processes) {
                sockets.push(socket);
            }
        }
        offset += len;
    }

    Ok(sockets)
}

fn list_raw(processes: &ProcessIndex) -> Result<Vec<SocketInfo>, Error> {
    let buf = sysctl_bytes("net.inet.raw.pcblist64")?;
    let mut sockets = Vec::new();
    let mut offset = size_of::<ffi::xinpgen>();

    while offset + size_of::<u32>() <= buf.len() {
        let small_len = read_unaligned::<u32>(&buf[offset..]) as usize;
        if small_len == 0 || small_len == size_of::<ffi::xinpgen>() {
            break;
        }
        let len = read_unaligned::<u64>(&buf[offset..]) as usize;
        if len == 0 || offset + len > buf.len() {
            break;
        }
        if len >= size_of::<ffi::xinpcb64>() {
            let raw = read_unaligned::<ffi::xinpcb64>(&buf[offset..]);
            if let Some(socket) = raw_socket(raw, processes) {
                sockets.push(socket);
            }
        }
        offset += len;
    }

    Ok(sockets)
}

fn tcp_socket(raw: ffi::xtcpcb64, processes: &ProcessIndex) -> Option<SocketInfo> {
    let pcb = raw.xt_inpcb;
    let family = family_from_flags(pcb.inp_vflag)?;
    let local = endpoint(&pcb, family, true);
    let peer = endpoint(&pcb, family, false);
    let socket = pcb.xi_socket;

    Some(SocketInfo {
        protocol: Protocol::Tcp,
        ip_protocol: None,
        family,
        state: Some(TcpState::from(raw.t_state)),
        recv_queue: socket.so_rcv.sb_cc,
        send_queue: socket.so_snd.sb_cc,
        local: SocketAddress::Inet(local),
        peer: SocketAddress::Inet(peer),
        uid: socket.so_uid,
        socket_handle: socket.xso_so,
        pcb_handle: socket.so_pcb,
        memory: memory_from_xsocket(socket),
        process: lookup_process(processes, socket.xso_so, socket.so_pcb),
    })
}

fn udp_socket(pcb: ffi::xinpcb64, processes: &ProcessIndex) -> Option<SocketInfo> {
    let family = family_from_flags(pcb.inp_vflag)?;
    let socket = pcb.xi_socket;

    Some(SocketInfo {
        protocol: Protocol::Udp,
        ip_protocol: None,
        family,
        state: None,
        recv_queue: socket.so_rcv.sb_cc,
        send_queue: socket.so_snd.sb_cc,
        local: SocketAddress::Inet(endpoint(&pcb, family, true)),
        peer: SocketAddress::Inet(endpoint(&pcb, family, false)),
        uid: socket.so_uid,
        socket_handle: socket.xso_so,
        pcb_handle: socket.so_pcb,
        memory: memory_from_xsocket(socket),
        process: lookup_process(processes, socket.xso_so, socket.so_pcb),
    })
}

fn raw_socket(pcb: ffi::xinpcb64, processes: &ProcessIndex) -> Option<SocketInfo> {
    let family = family_from_flags(pcb.inp_vflag)?;
    let socket = pcb.xi_socket;
    let local = endpoint(&pcb, family, true);
    let peer = endpoint(&pcb, family, false);

    Some(SocketInfo {
        protocol: Protocol::Raw,
        ip_protocol: Some(pcb.inp_ip_p),
        family,
        state: None,
        recv_queue: socket.so_rcv.sb_cc,
        send_queue: socket.so_snd.sb_cc,
        local: SocketAddress::Inet(local),
        peer: SocketAddress::Inet(peer),
        uid: socket.so_uid,
        socket_handle: socket.xso_so,
        pcb_handle: socket.so_pcb,
        memory: memory_from_xsocket(socket),
        process: lookup_process(processes, socket.xso_so, socket.so_pcb),
    })
}

fn list_unix(include_processes: bool) -> Vec<SocketInfo> {
    let mut sockets = Vec::new();
    for pid in list_pids() {
        let name = include_processes.then(|| process_name(pid));
        for fd in list_fds(pid) {
            if fd.proc_fdtype != ffi::PROX_FDTYPE_SOCKET {
                continue;
            }
            if let Some(info) = socket_fdinfo(pid, fd.proc_fd)
                && info.psi.soi_family == ffi::AF_UNIX as i32
                && let Some(socket) = unix_socket(info, pid, fd.proc_fd, name.as_deref())
            {
                sockets.push(socket);
            }
        }
    }
    sockets
}

fn unix_socket(
    info: ffi::socket_fdinfo,
    pid: i32,
    fd: i32,
    process_name: Option<&str>,
) -> Option<SocketInfo> {
    let protocol = match info.psi.soi_type as u32 {
        ffi::SOCK_STREAM => Protocol::UnixStream,
        ffi::SOCK_DGRAM => Protocol::UnixDatagram,
        _ => return None,
    };
    let unix = unsafe { info.psi.soi_proto.pri_un };
    let local = unix_path(unsafe { unix.unsi_addr.ua_sun });
    let peer = unix_path(unsafe { unix.unsi_caddr.ua_sun });

    Some(SocketInfo {
        protocol,
        ip_protocol: None,
        family: AddressFamily::Unix,
        state: None,
        recv_queue: info.psi.soi_rcv.sbi_cc,
        send_queue: info.psi.soi_snd.sbi_cc,
        local: SocketAddress::Unix { path: local },
        peer: SocketAddress::Unix { path: peer },
        uid: 0,
        socket_handle: info.psi.soi_so,
        pcb_handle: info.psi.soi_pcb,
        memory: memory_from_socket_info(info),
        process: process_name.map(|name| ProcessInfo {
            pid,
            fd,
            name: name.to_string(),
        }),
    })
}

fn unix_path(addr: ffi::sockaddr_un) -> String {
    let len = addr
        .sun_path
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(addr.sun_path.len());
    if len == 0 {
        return "*".to_string();
    }
    let bytes: Vec<u8> = addr.sun_path[..len].iter().map(|ch| *ch as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn memory_from_xsocket(socket: ffi::xsocket64) -> SocketMemory {
    SocketMemory {
        recv_bytes: socket.so_rcv.sb_cc,
        recv_high_water: socket.so_rcv.sb_hiwat,
        recv_mbuf_bytes: socket.so_rcv.sb_mbcnt,
        recv_mbuf_limit: socket.so_rcv.sb_mbmax,
        send_bytes: socket.so_snd.sb_cc,
        send_high_water: socket.so_snd.sb_hiwat,
        send_mbuf_bytes: socket.so_snd.sb_mbcnt,
        send_mbuf_limit: socket.so_snd.sb_mbmax,
    }
}

fn memory_from_socket_info(info: ffi::socket_fdinfo) -> SocketMemory {
    SocketMemory {
        recv_bytes: info.psi.soi_rcv.sbi_cc,
        recv_high_water: info.psi.soi_rcv.sbi_hiwat,
        recv_mbuf_bytes: info.psi.soi_rcv.sbi_mbcnt,
        recv_mbuf_limit: info.psi.soi_rcv.sbi_mbmax,
        send_bytes: info.psi.soi_snd.sbi_cc,
        send_high_water: info.psi.soi_snd.sbi_hiwat,
        send_mbuf_bytes: info.psi.soi_snd.sbi_mbcnt,
        send_mbuf_limit: info.psi.soi_snd.sbi_mbmax,
    }
}

fn endpoint(pcb: &ffi::xinpcb64, family: AddressFamily, local: bool) -> Endpoint {
    let port = u16::from_be(if local { pcb.inp_lport } else { pcb.inp_fport });

    let address = match (family, local) {
        (AddressFamily::Ipv4, true) => {
            let raw = unsafe { pcb.inp_dependladdr.inp46_local.ia46_addr4.s_addr };
            IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
        }
        (AddressFamily::Ipv4, false) => {
            let raw = unsafe { pcb.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr };
            IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
        }
        (AddressFamily::Ipv6, true) => {
            let raw = unsafe { pcb.inp_dependladdr.inp6_local.__u6_addr.__u6_addr8 };
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        (AddressFamily::Ipv6, false) => {
            let raw = unsafe { pcb.inp_dependfaddr.inp6_foreign.__u6_addr.__u6_addr8 };
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        (AddressFamily::Unix, _) => unreachable!("Unix sockets do not use inet endpoints"),
    };

    Endpoint { address, port }
}

fn family_from_flags(flags: u8) -> Option<AddressFamily> {
    if flags & ffi::INP_IPV4 as u8 != 0 {
        Some(AddressFamily::Ipv4)
    } else if flags & ffi::INP_IPV6 as u8 != 0 {
        Some(AddressFamily::Ipv6)
    } else {
        None
    }
}

fn lookup_process(processes: &ProcessIndex, socket: u64, pcb: u64) -> Option<ProcessInfo> {
    processes
        .get(&(socket, pcb))
        .or_else(|| processes.get(&(socket, 0)))
        .or_else(|| processes.get(&(0, pcb)))
        .cloned()
}

fn sysctl_bytes(name: &'static str) -> Result<Vec<u8>, Error> {
    let c_name = CString::new(name).expect("static sysctl name has no NUL");
    let mut len = 0usize;

    let first = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            ptr::null_mut(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if first != 0 {
        return Err(Error::Sysctl {
            name,
            source: io::Error::last_os_error(),
        });
    }

    let mut buf = vec![0u8; len];
    let second = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if second != 0 {
        return Err(Error::Sysctl {
            name,
            source: io::Error::last_os_error(),
        });
    }
    buf.truncate(len);
    Ok(buf)
}

fn process_index() -> ProcessIndex {
    let mut index = HashMap::new();
    for pid in list_pids() {
        let name = process_name(pid);
        for fd in list_fds(pid) {
            if fd.proc_fdtype != ffi::PROX_FDTYPE_SOCKET {
                continue;
            }
            if let Some(info) = socket_fdinfo(pid, fd.proc_fd) {
                let socket = info.psi.soi_so;
                let pcb = info.psi.soi_pcb;
                let process = ProcessInfo {
                    pid,
                    fd: fd.proc_fd,
                    name: name.clone(),
                };
                index
                    .entry((socket, pcb))
                    .or_insert_with(|| process.clone());
                index.entry((socket, 0)).or_insert_with(|| process.clone());
                index.entry((0, pcb)).or_insert(process);
            }
        }
    }
    index
}

fn list_pids() -> Vec<i32> {
    let bytes = unsafe { ffi::proc_listpids(ffi::PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Vec::new();
    }

    let mut pids = vec![0i32; bytes as usize / size_of::<i32>() + 128];
    let bytes = unsafe {
        ffi::proc_listpids(
            ffi::PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()) as i32,
        )
    };
    if bytes <= 0 {
        return Vec::new();
    }
    pids.truncate(bytes as usize / size_of::<i32>());
    pids.into_iter().filter(|pid| *pid > 0).collect()
}

fn list_fds(pid: i32) -> Vec<ffi::proc_fdinfo> {
    let bytes =
        unsafe { ffi::proc_pidinfo(pid, ffi::PROC_PIDLISTFDS as i32, 0, ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Vec::new();
    }

    let mut fds =
        vec![zeroed::<ffi::proc_fdinfo>(); bytes as usize / size_of::<ffi::proc_fdinfo>()];
    let bytes = unsafe {
        ffi::proc_pidinfo(
            pid,
            ffi::PROC_PIDLISTFDS as i32,
            0,
            fds.as_mut_ptr().cast(),
            (fds.len() * size_of::<ffi::proc_fdinfo>()) as i32,
        )
    };
    if bytes <= 0 {
        return Vec::new();
    }
    fds.truncate(bytes as usize / size_of::<ffi::proc_fdinfo>());
    fds
}

fn socket_fdinfo(pid: i32, fd: i32) -> Option<ffi::socket_fdinfo> {
    let mut info = zeroed::<ffi::socket_fdinfo>();
    let bytes = unsafe {
        ffi::proc_pidfdinfo(
            pid,
            fd,
            ffi::PROC_PIDFDSOCKETINFO as i32,
            (&mut info as *mut ffi::socket_fdinfo).cast(),
            size_of::<ffi::socket_fdinfo>() as i32,
        )
    };
    (bytes as usize == size_of::<ffi::socket_fdinfo>()).then_some(info)
}

fn process_name(pid: i32) -> String {
    let mut buf = [0u8; 256];
    let len = unsafe { ffi::proc_name(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return pid.to_string();
    }

    let len = buf
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(len as usize);
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

fn read_unaligned<T: Copy>(buf: &[u8]) -> T {
    assert!(buf.len() >= size_of::<T>());
    unsafe { ptr::read_unaligned(buf.as_ptr().cast()) }
}

fn zeroed<T>() -> T {
    unsafe { MaybeUninit::<T>::zeroed().assume_init() }
}
