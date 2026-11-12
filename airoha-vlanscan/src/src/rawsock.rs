// SPDX-License-Identifier: GPL-2.0-only

//! Raw AF_PACKET socket wrapper. Read-mostly: the passive scan only ever
//! receives; the probe mode additionally sends a fixed set of discovery
//! frames (ARP request, PPPoE PADI, DHCP DISCOVER) on a temporary VLAN
//! subinterface. Nothing else is ever transmitted.

use std::io;
use std::mem::size_of;
use std::os::raw::{c_int, c_void};

pub const AF_PACKET: c_int = 17;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_CLOEXEC: c_int = 0o2000000;
pub const SOL_SOCKET: c_int = 1;
pub const SO_RCVTIMEO: c_int = 20;
pub const ETH_P_ALL: u16 = 0x0003;

/// packet_type as reported in sockaddr_ll of received frames.
pub const PACKET_OUTGOING: u8 = 4;

const RECV_TIMEOUT_MS: i64 = 250;

#[repr(C)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrLink {
    pub family: u16,
    pub protocol: u16,
    pub ifindex: i32,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
}

impl SockAddrLink {
    fn zeroed() -> Self {
        Self {
            family: 0,
            protocol: 0,
            ifindex: 0,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        }
    }

    fn for_bind(ifindex: i32) -> Self {
        Self {
            family: AF_PACKET as u16,
            protocol: ETH_P_ALL.to_be(),
            ifindex,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        }
    }

    fn for_send(ifindex: i32, ethertype: u16, destination: &[u8; 6]) -> Self {
        let mut addr = [0u8; 8];
        addr[..6].copy_from_slice(destination);
        Self {
            family: AF_PACKET as u16,
            protocol: ethertype.to_be(),
            ifindex,
            hatype: 1,
            pkttype: 0,
            halen: 6,
            addr,
        }
    }
}

#[repr(C)]
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    seconds: i64,
    microseconds: i64,
}

extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
    fn sendto(
        fd: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_length: u32,
    ) -> isize;
    fn recvfrom(
        fd: c_int,
        buffer: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut c_void,
        address_length: *mut u32,
    ) -> isize;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, length: u32)
        -> c_int;
    fn close(fd: c_int) -> c_int;
}

/// A bound raw packet socket. Closed on drop.
pub struct RawPacketSocket(c_int);

impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

pub struct Received<'a> {
    /// sockaddr_ll pkttype of the received frame (PACKET_OUTGOING for our
    /// own transmissions echoed back on the same interface).
    pub pkttype: u8,
    pub data: &'a [u8],
}

impl RawPacketSocket {
    /// Bind a raw socket to one interface. Promiscuous mode is deliberately
    /// NOT enabled: every reply the scanner cares about (broadcast DHCP
    /// offers, unicast replies addressed to our own MAC) is delivered
    /// without it, and not touching interface flags keeps the scan
    /// side-effect free.
    pub fn bind_interface(ifindex: i32) -> io::Result<Self> {
        let fd = unsafe {
            socket(
                AF_PACKET,
                SOCK_RAW | SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = Self(fd);

        // Short receive timeout so loops can observe the stop flag.
        let timeout = Timeval {
            seconds: 0,
            microseconds: RECV_TIMEOUT_MS * 1000,
        };
        let ret = unsafe {
            setsockopt(
                socket.0,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout as *const _ as *const c_void,
                size_of::<Timeval>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let local = SockAddrLink::for_bind(ifindex);
        let ret = unsafe {
            bind(
                socket.0,
                &local as *const _ as *const c_void,
                size_of::<SockAddrLink>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    /// Receive one frame. Returns Ok(None) on receive timeout (caller should
    /// re-check its stop conditions), Err on real socket errors.
    pub fn receive<'a>(&self, buffer: &'a mut [u8]) -> io::Result<Option<Received<'a>>> {
        let mut address = SockAddrLink::zeroed();
        let mut address_length = size_of::<SockAddrLink>() as u32;
        loop {
            let received = unsafe {
                recvfrom(
                    self.0,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                    &mut address as *mut _ as *mut c_void,
                    &mut address_length,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => return Err(error),
                }
            }
            let received = received as usize;
            return Ok(Some(Received {
                pkttype: address.pkttype,
                data: &buffer[..received],
            }));
        }
    }

    /// Transmit one already-built frame out of `ifindex`. Used only by the
    /// probe mode on a temporary VLAN subinterface, so the kernel performs
    /// the VLAN tagging exactly like a real service would.
    pub fn send(
        &self,
        ifindex: i32,
        ethertype: u16,
        destination: &[u8; 6],
        frame: &[u8],
    ) -> io::Result<()> {
        let address = SockAddrLink::for_send(ifindex, ethertype, destination);
        loop {
            let sent = unsafe {
                sendto(
                    self.0,
                    frame.as_ptr() as *const c_void,
                    frame.len(),
                    0,
                    &address as *const _ as *const c_void,
                    size_of::<SockAddrLink>() as u32,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(());
        }
    }
}
