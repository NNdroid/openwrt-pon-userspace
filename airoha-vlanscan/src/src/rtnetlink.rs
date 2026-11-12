// SPDX-License-Identifier: GPL-2.0-only

//! Minimal rtnetlink client used to create and delete temporary VLAN
//! subinterfaces during the probe phase. Only two operations exist:
//! RTM_NEWLINK (create vlan) and RTM_DELLINK. No other link state is ever
//! touched, and /etc/config/network (UCI) is never modified.

use std::io;
use std::mem::size_of;
use std::os::raw::{c_int, c_void};

const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const SOCK_CLOEXEC: c_int = 0o2000000;
const NETLINK_ROUTE: c_int = 0;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLMSG_ERROR: u16 = 0x02;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;

const IFLA_IFNAME: u16 = 3;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_ID: u16 = 1;

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

#[repr(C)]
struct IfInfoMessage {
    family: u8,
    pad: u8,
    link_type: u16,
    index: i32,
    flags: u32,
    change: u32,
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
    fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
}

struct RouteSocket(c_int);

impl Drop for RouteSocket {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

fn align4(length: usize) -> usize {
    (length + 3) & !3
}

fn append_attr(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    message.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}

fn append_nested(message: &mut Vec<u8>, kind: u16, nested: &[u8]) {
    append_attr(message, kind, nested);
}

impl RouteSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = Self(fd);
        let local = SockAddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        let ret = unsafe {
            bind(
                socket.0,
                &local as *const _ as *const c_void,
                size_of::<SockAddrNl>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    /// Send one rtnetlink request and wait for the matching ACK.
    fn exchange(&self, message: &mut Vec<u8>, sequence: u32) -> io::Result<()> {
        let message_length = message.len() as u32;
        message[..4].copy_from_slice(&message_length.to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());

        let kernel = SockAddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        let sent = unsafe {
            sendto(
                self.0,
                message.as_ptr() as *const c_void,
                message.len(),
                0,
                &kernel as *const _ as *const c_void,
                size_of::<SockAddrNl>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buffer = vec![0u8; 8192];
        loop {
            let received =
                unsafe { recv(self.0, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let received = received as usize;
            let mut offset = 0;
            while offset + 16 <= received {
                let length =
                    u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                let kind = u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().unwrap());
                let reply_sequence =
                    u32::from_ne_bytes(buffer[offset + 8..offset + 12].try_into().unwrap());
                if length < 16 || offset + length > received {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid netlink message length",
                    ));
                }
                if reply_sequence != sequence {
                    offset += align4(length);
                    continue;
                }
                if kind == NLMSG_ERROR {
                    if length < 20 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated netlink error",
                        ));
                    }
                    let error =
                        i32::from_ne_bytes(buffer[offset + 16..offset + 20].try_into().unwrap());
                    if error == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-error));
                }
                offset += align4(length);
            }
        }
    }
}

fn link_message(message_type: u16, flags: u16, index: i32) -> Vec<u8> {
    let mut message = vec![0u8; 16 + size_of::<IfInfoMessage>()];
    message[4..6].copy_from_slice(&message_type.to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    let header = IfInfoMessage {
        family: 0,
        pad: 0,
        link_type: 0,
        index,
        flags: 0,
        change: 0,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(&header as *const _ as *const u8, size_of::<IfInfoMessage>())
    };
    message[16..].copy_from_slice(bytes);
    message
}

/// Create a temporary 802.1Q subinterface `name` on top of the parent link.
/// Always created through the kernel's own vlan machinery so the probe path
/// matches what a real service would use.
pub fn create_vlan(parent_index: i32, name: &str, vlan_id: u16) -> io::Result<()> {
    let mut info = Vec::new();
    append_attr(&mut info, IFLA_INFO_KIND, b"vlan");
    let mut data = Vec::new();
    append_attr(&mut data, IFLA_VLAN_ID, &vlan_id.to_ne_bytes());
    append_nested(&mut info, IFLA_INFO_DATA, &data);

    let mut message = link_message(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        0,
    );
    append_attr(&mut message, IFLA_IFNAME, name.as_bytes());
    append_attr(&mut message, IFLA_LINK, &parent_index.to_ne_bytes());
    append_nested(&mut message, IFLA_LINKINFO, &info);

    let socket = RouteSocket::open()?;
    socket.exchange(&mut message, 1)
}

/// Delete a link by index. Used exclusively for the scanner's own temporary
/// subinterfaces.
pub fn delete_link(index: i32) -> io::Result<()> {
    let mut message = link_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, index);
    let socket = RouteSocket::open()?;
    socket.exchange(&mut message, 1)
}
