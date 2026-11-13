// SPDX-License-Identifier: GPL-2.0-only

//! Raw AF_PACKET socket wrapper. The passive scan only ever receives; the
//! probe mode additionally transmits a fixed set of discovery frames as
//! 802.1Q-tagged ethernet frames on the parent interface.
//!
//! PACKET_AUXDATA is always enabled: when the PON NIC uses RX VLAN offload
//! it strips the 802.1Q header before userspace sees the frame, and the VID
//! is only available in an ancillary control message. Recovering it is what
//! lets both the passive scan and the probe matcher see the real VLAN id.
//! Probe mode additionally requests socket-scoped promiscuous reception so
//! unicast replies to a custom probe MAC are not filtered by the hardware.

use std::io;
use std::mem::size_of;
use std::os::raw::{c_int, c_void};

pub const AF_PACKET: c_int = 17;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_CLOEXEC: c_int = 0o2000000;
pub const SOL_SOCKET: c_int = 1;
pub const SO_RCVTIMEO: c_int = 20;
pub const ETH_P_ALL: u16 = 0x0003;

pub const SOL_PACKET: c_int = 263;
pub const PACKET_AUXDATA: c_int = 8;
pub const PACKET_ADD_MEMBERSHIP: c_int = 1;
pub const PACKET_MR_PROMISC: u16 = 1;
pub const TP_STATUS_VLAN_VALID: u32 = 1 << 4;

/// packet_type as reported in sockaddr_ll of received frames.
pub const PACKET_OUTGOING: u8 = 4;

const RECV_TIMEOUT_MS: i64 = 250;

// struct timeval uses `long` everywhere except 32-bit musl, which switched
// to a 64-bit time_t. OpenWrt/aarch64 is 64-bit, but keep the other targets
// correct too.
#[cfg(any(target_pointer_width = "64", all(target_pointer_width = "32", target_env = "musl")))]
type TimeField = i64;
#[cfg(all(target_pointer_width = "32", not(target_env = "musl")))]
type TimeField = i32;

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
struct Timeval {
    seconds: TimeField,
    microseconds: TimeField,
}

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

// 64-bit little-endian musl (OpenWrt/aarch64) declares msg_iovlen and
// msg_controllen as 32-bit ints with explicit padding, whereas glibc uses
// size_t. Getting this wrong makes recvmsg() look for the ancillary data in
// the wrong place and PACKET_AUXDATA silently disappears. big-endian musl
// places the pads differently; it is not a target of this package.
#[cfg(all(target_env = "musl", target_pointer_width = "64", target_endian = "little"))]
#[repr(C)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *mut IoVec,
    msg_iovlen: c_int,
    __pad1: c_int,
    msg_control: *mut c_void,
    msg_controllen: u32,
    __pad2: c_int,
    msg_flags: c_int,
}

// glibc, and 32-bit targets where int and size_t have the same width.
#[cfg(not(all(target_env = "musl", target_pointer_width = "64", target_endian = "little")))]
#[repr(C)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *mut IoVec,
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: usize,
    msg_flags: c_int,
}

impl MsgHdr {
    fn new(
        name: *mut c_void,
        namelen: u32,
        iov: *mut IoVec,
        control: *mut c_void,
        controllen: usize,
    ) -> Self {
        #[cfg(all(target_env = "musl", target_pointer_width = "64", target_endian = "little"))]
        {
            Self {
                msg_name: name,
                msg_namelen: namelen,
                msg_iov: iov,
                msg_iovlen: 1,
                __pad1: 0,
                msg_control: control,
                msg_controllen: controllen as u32,
                __pad2: 0,
                msg_flags: 0,
            }
        }
        #[cfg(not(all(target_env = "musl", target_pointer_width = "64", target_endian = "little")))]
        {
            Self {
                msg_name: name,
                msg_namelen: namelen,
                msg_iov: iov,
                msg_iovlen: 1,
                msg_control: control,
                msg_controllen: controllen,
                msg_flags: 0,
            }
        }
    }

    /// Actual ancillary-data length written back by the kernel.
    fn controllen(&self) -> usize {
        self.msg_controllen as usize
    }
}

#[cfg(all(target_env = "musl", target_pointer_width = "64", target_endian = "little"))]
#[repr(C)]
struct CmsgHdr {
    len: u32,
    __pad1: c_int,
    level: c_int,
    kind: c_int,
}

#[cfg(not(all(target_env = "musl", target_pointer_width = "64", target_endian = "little")))]
#[repr(C)]
struct CmsgHdr {
    len: usize,
    level: c_int,
    kind: c_int,
}

impl CmsgHdr {
    fn length(&self) -> usize {
        self.len as usize
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TPacketAuxdata {
    status: u32,
    len: u32,
    snaplen: u32,
    mac: u16,
    net: u16,
    vlan_tci: u16,
    vlan_tpid: u16,
}

#[repr(C)]
struct PacketMreq {
    mr_ifindex: c_int,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

/// Ancillary data buffer, aligned as required by struct cmsghdr.
#[repr(C, align(8))]
struct ControlBuffer([u8; 64]);

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
    fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, length: u32)
        -> c_int;
    fn close(fd: c_int) -> c_int;
}

pub struct Received<'a> {
    /// sockaddr_ll pkttype of the received frame (PACKET_OUTGOING for our
    /// own transmissions echoed back on the same interface).
    pub pkttype: u8,
    /// VID recovered from the 802.1Q header or PACKET_AUXDATA.
    pub vlan: Option<u16>,
    pub data: &'a [u8],
}

/// Walk the ancillary control messages and return a validated VLAN id.
fn aux_vlan(control: &[u8], controllen: usize) -> Option<u16> {
    let header_size = size_of::<CmsgHdr>();
    let value_size = size_of::<TPacketAuxdata>();
    let alignment = size_of::<usize>();
    let mut offset = 0usize;
    while offset + header_size <= controllen {
        let header = unsafe { &*(control.as_ptr().add(offset) as *const CmsgHdr) };
        let length = header.length();
        if length < header_size {
            break;
        }
        if header.level == SOL_PACKET
            && header.kind == PACKET_AUXDATA
            && length >= header_size + value_size
        {
            let value = unsafe {
                &*(control.as_ptr().add(offset + header_size) as *const TPacketAuxdata)
            };
            if value.status & TP_STATUS_VLAN_VALID != 0 {
                return Some(value.vlan_tci & 0x0fff);
            }
        }
        let step = (length + alignment - 1) & !(alignment - 1);
        if step == 0 {
            break;
        }
        offset += step;
    }
    None
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

impl RawPacketSocket {
    /// Bind a raw socket to one interface.
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
            microseconds: (RECV_TIMEOUT_MS * 1000) as TimeField,
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

        // Ask the kernel to hand us the VLAN id in an ancillary message for
        // frames whose 802.1Q header was stripped by hardware offload.
        // Failure here is non-fatal on old kernels; inline tags still work.
        let enable: c_int = 1;
        let _ = unsafe {
            setsockopt(
                socket.0,
                SOL_PACKET,
                PACKET_AUXDATA,
                &enable as *const _ as *const c_void,
                size_of::<c_int>() as u32,
            )
        };

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

    /// Receive all frames on this interface, including unicast replies
    /// addressed to a custom probe MAC. This is socket-scoped (the same
    /// mechanism tcpdump uses) and is undone automatically on close; the
    /// interface flags and UCI configuration are never modified.
    pub fn enable_promiscuous(&self, ifindex: i32) -> io::Result<()> {
        let request = PacketMreq {
            mr_ifindex: ifindex,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let ret = unsafe {
            setsockopt(
                self.0,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &request as *const _ as *const c_void,
                size_of::<PacketMreq>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive one frame. Returns Ok(None) on receive timeout (caller should
    /// re-check its stop conditions), Err on real socket errors.
    pub fn receive<'a>(&self, buffer: &'a mut [u8]) -> io::Result<Option<Received<'a>>> {
        loop {
            let mut address = SockAddrLink::zeroed();
            let mut control = ControlBuffer([0u8; 64]);
            let mut iov = IoVec {
                base: buffer.as_mut_ptr() as *mut c_void,
                len: buffer.len(),
            };
            let mut message = MsgHdr::new(
                &mut address as *mut _ as *mut c_void,
                size_of::<SockAddrLink>() as u32,
                &mut iov as *mut IoVec,
                control.0.as_mut_ptr() as *mut c_void,
                control.0.len(),
            );
            let received = unsafe { recvmsg(self.0, &mut message as *mut MsgHdr, 0) };
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
                vlan: aux_vlan(&control.0, message.controllen()),
                data: &buffer[..received],
            }));
        }
    }

    /// Transmit one already-built frame out of `ifindex`. Probe frames carry
    /// their own 802.1Q header, so no temporary VLAN subinterface is needed.
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
