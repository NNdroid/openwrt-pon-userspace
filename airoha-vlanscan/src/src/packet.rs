// SPDX-License-Identifier: GPL-2.0-only

//! Frame analysis for the passive scan and fixed construction of the three
//! probe frames. All parsing is bounds-checked slice work; the only frames
//! ever built here are the standard discovery packets (ARP request, PPPoE
//! PADI, DHCP DISCOVER) with no caller-controlled payload.
//!
//! Frames may carry their 802.1Q tag either inline (normal AF_PACKET path)
//! or out-of-band in PACKET_AUXDATA when the NIC uses RX VLAN offload and
//! strips the header before userspace sees it. `aux_vlan` carries that
//! recovered VID; every entry point accepts it and prefers an inline tag.

/// Result of analysing one received frame.
pub struct FrameInfo {
    /// Outermost VLAN id, None for untagged frames.
    pub vlan: Option<u16>,
    /// Traffic class label, e.g. "dhcp-offer" or "arp-request"; carries a
    /// " (qinq)" suffix when a second inner tag was present.
    pub class: String,
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_PPPOE_DISCOVERY: u16 = 0x8863;
const ETHERTYPE_PPPOE_SESSION: u16 = 0x8864;
const ETHERTYPE_SVLAN: u16 = 0x88a8;

const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// Minimum 802.1Q ethernet frame length, excluding the FCS. Frames shorter
/// than this are runts and may be dropped by the NIC or the upstream switch.
const MIN_TAGGED_FRAME: usize = 64;

/// Resolve the outermost VLAN id from an inline tag plus an offloaded VID.
/// When RX VLAN offload stripped the *outer* tag, `aux` is that outer S-VID
/// and any inline tag still present is the inner C-VID of a QinQ frame, so
/// the offloaded VID must win. Returns (outer VID, has a second tag).
fn resolve_vlan(inline: Option<u16>, aux: Option<u16>) -> (Option<u16>, bool) {
    match (aux, inline) {
        (Some(outer), Some(_inner)) => (Some(outer), true),
        (Some(outer), None) => (Some(outer), false),
        (None, inner) => (inner, false),
    }
}

/// Read the Host-Uniq tag (0x0103) from a PPPoE discovery payload, if any.
fn pppoe_host_uniq(payload: &[u8]) -> Option<u32> {
    // PPPoE discovery header: ver/type(1) code(1) session(2) length(2).
    if payload.len() < 6 {
        return None;
    }
    let mut offset = 6;
    while offset + 4 <= payload.len() {
        let tag = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let length = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        if offset + 4 + length > payload.len() {
            break;
        }
        if tag == 0x0103 && length >= 4 {
            return Some(u32::from_be_bytes([
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            ]));
        }
        offset += 4 + length;
    }
    None
}

/// Analyse a received ethernet frame. Returns None for runts.
///
/// `aux_vlan` is the VID recovered from PACKET_AUXDATA, used when the NIC
/// stripped the 802.1Q header on receive (RX VLAN offload).
pub fn analyze(frame: &[u8], aux_vlan: Option<u16>) -> Option<FrameInfo> {
    if frame.len() < 14 {
        return None;
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    let mut vlan: Option<u16> = None;
    let mut double_tagged = false;

    // Unwrap at most two VLAN tags ( QinQ: outer S-VID + inner C-VID ).
    for _ in 0..2 {
        if ether_type != ETHERTYPE_VLAN && ether_type != ETHERTYPE_SVLAN {
            break;
        }
        if frame.len() < offset + 4 {
            break;
        }
        let vid = u16::from_be_bytes([frame[offset], frame[offset + 1]]) & 0x0fff;
        if vlan.is_none() {
            vlan = Some(vid);
        } else {
            double_tagged = true;
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    // Hardware-offloaded tags never appear inline; recover them here so the
    // passive scan reports real VLAN ids instead of lumping everything into
    // the "untagged" bucket. With QinQ the offloaded VID is the outer S-VID
    // and the inline tag still visible is the inner C-VID.
    let (vlan, offloaded_double) = resolve_vlan(vlan, aux_vlan);
    let double_tagged = double_tagged || offloaded_double;

    let mut class = classify(ether_type, &frame[offset..]);
    if double_tagged {
        class.push_str(" (qinq)");
    }
    Some(FrameInfo { vlan, class })
}

fn classify(ether_type: u16, payload: &[u8]) -> String {
    match ether_type {
        ETHERTYPE_ARP => classify_arp(payload),
        ETHERTYPE_PPPOE_DISCOVERY => classify_pppoe_discovery(payload),
        ETHERTYPE_PPPOE_SESSION => "pppoe-session".to_owned(),
        ETHERTYPE_IPV4 => classify_ipv4(payload),
        ETHERTYPE_IPV6 => classify_ipv6(payload),
        other => format!("0x{other:04x}"),
    }
}

fn classify_arp(payload: &[u8]) -> String {
    // htype(2) ptype(2) hlen plen op(2) ...
    if payload.len() >= 8 {
        let opcode = u16::from_be_bytes([payload[6], payload[7]]);
        return match opcode {
            1 => "arp-request".to_owned(),
            2 => "arp-reply".to_owned(),
            _ => "arp".to_owned(),
        };
    }
    "arp".to_owned()
}

fn classify_pppoe_discovery(payload: &[u8]) -> String {
    // ver/type(1) code(1) session(2) length(2)
    if payload.len() < 2 {
        return "pppoe".to_owned();
    }
    match payload[1] {
        0x09 => "pppoe-padi".to_owned(),
        0x07 => "pppoe-pado".to_owned(),
        0x19 => "pppoe-padr".to_owned(),
        0x65 => "pppoe-pads".to_owned(),
        0xa7 => "pppoe-padt".to_owned(),
        _ => "pppoe".to_owned(),
    }
}

fn classify_ipv4(payload: &[u8]) -> String {
    if payload.len() < 20 {
        return "ipv4".to_owned();
    }
    let ihl = ((payload[0] & 0x0f) as usize) * 4;
    if ihl < 20 || payload.len() < ihl {
        return "ipv4".to_owned();
    }
    let protocol = payload[9];
    let l4 = &payload[ihl..];
    if protocol == 2 {
        return "igmp".to_owned();
    }
    if protocol == 17 && l4.len() >= 8 {
        let source_port = u16::from_be_bytes([l4[0], l4[1]]);
        let destination_port = u16::from_be_bytes([l4[2], l4[3]]);
        if (source_port == 67 && destination_port == 68)
            || (source_port == 68 && destination_port == 67)
        {
            return classify_dhcp(&l4[8..]);
        }
    }
    "ipv4".to_owned()
}

fn classify_ipv6(payload: &[u8]) -> String {
    if payload.len() < 40 {
        return "ipv6".to_owned();
    }
    // Walk past common extension headers; otherwise DHCPv6 and ICMPv6
    // traffic behind a hop-by-hop/routing/dest-opt header is mislabelled
    // as plain "ipv6". Fragment (44) and AH (51) are left alone because
    // their payload is not parseable without reassembly.
    let mut next = payload[6];
    let mut offset = 40usize;
    for _ in 0..4 {
        match next {
            0 | 43 | 60 | 135 | 139 => {
                if offset + 2 > payload.len() {
                    return "ipv6".to_owned();
                }
                let following = payload[offset];
                let length = (payload[offset + 1] as usize + 1) * 8;
                offset += length;
                next = following;
            }
            _ => break,
        }
    }
    if offset > payload.len() {
        return "ipv6".to_owned();
    }
    match next {
        17 => {
            let l4 = &payload[offset..];
            if l4.len() >= 8 {
                let source_port = u16::from_be_bytes([l4[0], l4[1]]);
                let destination_port = u16::from_be_bytes([l4[2], l4[3]]);
                if (source_port == 546 && destination_port == 547)
                    || (source_port == 547 && destination_port == 546)
                {
                    return "dhcpv6".to_owned();
                }
            }
            "ipv6".to_owned()
        }
        58 if offset < payload.len() => match payload[offset] {
            133..=136 => "ndp".to_owned(),
            _ => "icmpv6".to_owned(),
        },
        _ => "ipv6".to_owned(),
    }
}

fn classify_dhcp(bootp: &[u8]) -> String {
    // op(1) htype hlen hops xid(4) ... cookie at 236..240
    if bootp.len() < 240 || bootp[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return "dhcp".to_owned();
    }
    let message_type = dhcp_options(bootp)
        .iter()
        .find(|(code, _)| *code == 53)
        .and_then(|(_, value)| value.first().copied());
    match (bootp[0], message_type) {
        (1, Some(1)) => "dhcp-discover".to_owned(),
        (1, Some(3)) => "dhcp-request".to_owned(),
        (1, _) => "dhcp-query".to_owned(),
        (2, Some(2)) => "dhcp-offer".to_owned(),
        (2, Some(5)) => "dhcp-ack".to_owned(),
        (2, Some(6)) => "dhcp-nak".to_owned(),
        (2, _) => "dhcp-reply".to_owned(),
        _ => "dhcp".to_owned(),
    }
}

/// Parse DHCP option TLVs (0 = pad, 255 = end). Bounds-checked throughout.
pub fn dhcp_options(bootp: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut options = Vec::new();
    let mut offset = 240;
    while offset < bootp.len() {
        let code = bootp[offset];
        if code == 0 {
            offset += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        if offset + 2 > bootp.len() {
            break;
        }
        let length = bootp[offset + 1] as usize;
        if offset + 2 + length > bootp.len() {
            break;
        }
        options.push((code, bootp[offset + 2..offset + 2 + length].to_vec()));
        offset += 2 + length;
    }
    options
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = data.chunks_exact(2).remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_address(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

fn format_ipv4(address: &[u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

/// Parse a colon-separated MAC address ("00:11:22:33:44:55").
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let bytes = text
        .split(':')
        .map(|part| {
            if part.len() != 2 {
                return None;
            }
            u8::from_str_radix(part, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    bytes.try_into().ok()
}

/// Insert an 802.1Q tag into an already-built ethernet frame.
///
/// Sending tagged frames directly on the parent avoids creating temporary
/// VLAN subinterfaces: no EEXIST clash with an already configured service
/// interface, no interface state to change, and no UCI/network side effects.
pub fn tag_frame(frame: &[u8], vlan: u16) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    let mut tagged = Vec::with_capacity(frame.len() + 4);
    tagged.extend_from_slice(&frame[..12]); // destination + source MAC
    tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
    tagged.extend_from_slice(&(vlan & 0x0fff).to_be_bytes());
    tagged.extend_from_slice(&frame[12..]); // original ethertype + payload
    // ARP requests (46 bytes tagged) and PADI (36 bytes tagged) are runts.
    // Some drivers pad short frames, others transmit them verbatim and the
    // peer drops them. Pad explicitly; the zero tail is ignored by ARP,
    // PPPoE and IPv4 (which has its own total_length field).
    while tagged.len() < MIN_TAGGED_FRAME {
        tagged.push(0);
    }
    Some(tagged)
}

/// Discovered services inside one probe reply frame.
#[derive(Default)]
pub struct ProbeReply {
    /// ARP reply sender protocol address (potential gateway).
    pub gateway: Option<String>,
    /// A PPPoE PADO was seen.
    pub pado: bool,
    /// DHCP offer details.
    pub offer: Option<DhcpOffer>,
}

pub struct DhcpOffer {
    pub address: String,
    pub server: Option<String>,
}

/// Look at one frame received on the parent interface during a probe window
/// and extract any probe-relevant reply.
///
/// `aux_vlan` is the VID from PACKET_AUXDATA (RX VLAN offload) and, when
/// present, is the *outermost* tag. Every protocol is tied back to our own
/// probe by an independent token, so a reply with no VLAN evidence at all
/// is still usable: DHCP by xid + chaddr, ARP by target MAC, and PPPoE by
/// the Host-Uniq token echoed from the PADI (plus a unicast destination).
pub fn inspect_probe_reply(
    frame: &[u8],
    aux_vlan: Option<u16>,
    probe_mac: &[u8; 6],
    vlan: u16,
    transaction_id: u32,
) -> Option<ProbeReply> {
    if frame.len() < 14 {
        return None;
    }
    // Only frames addressed to us (broadcast or our probe MAC) are relevant.
    let addressed_to_us = frame[0..6] == BROADCAST_MAC || frame[0..6] == *probe_mac;
    if !addressed_to_us {
        return None;
    }
    // Ignore our own transmissions echoed back by the kernel.
    if frame[6..12] == *probe_mac {
        return None;
    }

    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    let mut seen_vlan: Option<u16> = None;
    for _ in 0..2 {
        if ether_type != ETHERTYPE_VLAN && ether_type != ETHERTYPE_SVLAN {
            break;
        }
        if frame.len() < offset + 4 {
            return None;
        }
        if seen_vlan.is_none() {
            seen_vlan = Some(u16::from_be_bytes([frame[offset], frame[offset + 1]]) & 0x0fff);
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    let (frame_vlan, _) = resolve_vlan(seen_vlan, aux_vlan);
    if let Some(outer) = frame_vlan {
        if outer != vlan {
            return None;
        }
    }
    let payload = &frame[offset..];
    let unicast_to_us = frame[0..6] == *probe_mac;

    let mut reply = ProbeReply::default();
    match ether_type {
        ETHERTYPE_ARP => {
            if payload.len() >= 28 {
                let opcode = u16::from_be_bytes([payload[6], payload[7]]);
                // ARP reply: target hardware address (18..24) must be our
                // probe MAC, otherwise it is someone else's exchange.
                if opcode == 2 && payload[18..24] == *probe_mac {
                    let sender = [payload[14], payload[15], payload[16], payload[17]];
                    reply.gateway = Some(format_ipv4(&sender));
                }
            }
        }
        ETHERTYPE_PPPOE_DISCOVERY => {
            // PADO is normally unicast back to the PADI's source MAC. RFC
            // 2516 requires the AC to echo our Host-Uniq token, which embeds
            // the VLAN id and therefore also discriminates late replies from
            // other VLANs. Some BRAS omit the tag: accept those on the
            // strength of the unicast destination alone, but never accept a
            // broadcast PADO (it could belong to any other client).
            if unicast_to_us && payload.len() >= 2 && payload[1] == 0x07 {
                let token_ok = match pppoe_host_uniq(payload) {
                    Some(token) => token == (vlan as u32),
                    None => true,
                };
                if token_ok {
                    reply.pado = true;
                }
            }
        }
        ETHERTYPE_IPV4 => {
            if payload.len() >= 20 {
                let ihl = ((payload[0] & 0x0f) as usize) * 4;
                if ihl >= 20 && payload.len() >= ihl + 8 && payload[9] == 17 {
                    let l4 = &payload[ihl..];
                    let source_port = u16::from_be_bytes([l4[0], l4[1]]);
                    let destination_port = u16::from_be_bytes([l4[2], l4[3]]);
                    if source_port == 67 && destination_port == 68 && l4.len() >= 8 {
                        let bootp = &l4[8..];
                        if bootp.len() >= 240
                            && bootp[236..240] == [0x63, 0x82, 0x53, 0x63]
                            && bootp[0] == 2 // BOOTREPLY, not an echoed BOOTREQUEST
                        {
                            let xid = u32::from_be_bytes([
                                bootp[4], bootp[5], bootp[6], bootp[7],
                            ]);
                            // chaddr at 28..34; match both xid and client MAC
                            // so an unrelated offer cannot mark a VLAN alive.
                            if xid == transaction_id && bootp[28..34] == *probe_mac {
                                let address = [bootp[16], bootp[17], bootp[18], bootp[19]];
                                let server = dhcp_options(bootp)
                                    .into_iter()
                                    .find(|(code, _)| *code == 54)
                                    .and_then(|(_, value)| {
                                        <[u8; 4]>::try_from(value.as_slice())
                                            .ok()
                                            .map(|a| format_ipv4(&a))
                                    });
                                reply.offer = Some(DhcpOffer {
                                    address: format_ipv4(&address),
                                    server,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if reply.gateway.is_some() || reply.pado || reply.offer.is_some() {
        Some(reply)
    } else {
        None
    }
}

/// Build an ARP request probing for `target`. Sender address is 0.0.0.0
/// because the temporary interface has no IP yet; this is the standard
/// probe form and never alters any neighbour table remotely.
pub fn build_arp_request(source_mac: &[u8; 6], target: &str) -> Option<Vec<u8>> {
    let target_ip = ipv4_address(target)?;
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(source_mac);
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes()); // htype: ethernet
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype
    frame.push(6); // hlen
    frame.push(4); // plen
    frame.extend_from_slice(&1u16.to_be_bytes()); // op: request
    frame.extend_from_slice(source_mac);
    frame.extend_from_slice(&[0, 0, 0, 0]); // sender ip: unset
    frame.extend_from_slice(&[0; 6]); // target mac: unknown
    frame.extend_from_slice(&target_ip);
    debug_assert_eq!(frame.len(), 42);
    Some(frame)
}

/// Build a PPPoE PADI asking for any service. Contains only a zero-length
/// Service-Name tag plus a Host-Uniq echo token; never leads to a session
/// because a PADR is never sent.
pub fn build_pppoe_padi(source_mac: &[u8; 6], host_uniq: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(26);
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(source_mac);
    frame.extend_from_slice(&ETHERTYPE_PPPOE_DISCOVERY.to_be_bytes());
    frame.push(0x11); // version 1, type 1
    frame.push(0x09); // code: PADI
    frame.extend_from_slice(&0u16.to_be_bytes()); // session id
    frame.extend_from_slice(&12u16.to_be_bytes()); // payload length
    frame.extend_from_slice(&0x0101u16.to_be_bytes()); // tag: Service-Name
    frame.extend_from_slice(&0u16.to_be_bytes()); // tag length: any service
    frame.extend_from_slice(&0x0103u16.to_be_bytes()); // tag: Host-Uniq
    frame.extend_from_slice(&4u16.to_be_bytes());
    frame.extend_from_slice(&host_uniq.to_be_bytes());
    frame
}

/// Build a DHCP DISCOVER. Discovery only: no REQUEST is ever sent, so no
/// lease is bound and no pool address is consumed. The broadcast flag makes
/// the server answer on the wire so the probe window can see the offer.
pub fn build_dhcp_discover(
    source_mac: &[u8; 6],
    transaction_id: u32,
    vendor_class: Option<&str>,
) -> Vec<u8> {
    let mut bootp = Vec::with_capacity(300);
    bootp.push(1); // op: BOOTREQUEST
    bootp.push(1); // htype: ethernet
    bootp.push(6); // hlen
    bootp.push(0); // hops
    bootp.extend_from_slice(&transaction_id.to_be_bytes());
    bootp.extend_from_slice(&0u16.to_be_bytes()); // secs
    bootp.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
    bootp.extend_from_slice(&[0; 4]); // ciaddr
    bootp.extend_from_slice(&[0; 4]); // yiaddr
    bootp.extend_from_slice(&[0; 4]); // siaddr
    bootp.extend_from_slice(&[0; 4]); // giaddr
    bootp.extend_from_slice(source_mac); // chaddr at 28..34
    bootp.extend_from_slice(&[0; 10]); // chaddr padding
    bootp.extend_from_slice(&[0; 64]); // sname
    bootp.extend_from_slice(&[0; 128]); // file
    bootp.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    bootp.extend_from_slice(&[53, 1, 1]); // option 53: DHCPDISCOVER
    // Option 60 (vendor class): several ISPs refuse to answer a DISCOVER
    // without the expected vendor string, or use it to pick an address
    // pool. Optional so the default probe stays protocol-minimal.
    if let Some(class) = vendor_class {
        let bytes = class.as_bytes();
        if !bytes.is_empty() && bytes.len() <= 255 {
            bootp.push(60);
            bootp.push(bytes.len() as u8);
            bootp.extend_from_slice(bytes);
        }
    }
    // Option 61 (client identifier): many ISP servers key their address
    // pools on the client id rather than chaddr alone.
    bootp.extend_from_slice(&[61, 7, 1]);
    bootp.extend_from_slice(source_mac);
    bootp.extend_from_slice(&[
        55, 7, 1,  // subnet mask
        3,  // router
        6,  // dns
        15, // domain name
        51, // lease time (reported only)
        58, // t1
        59, // t2
    ]);
    bootp.push(255); // end
    while bootp.len() < 300 {
        bootp.push(0); // BOOTP minimum packet padding
    }

    let udp_length = (8 + bootp.len()) as u16;
    let mut udp = Vec::with_capacity(8 + bootp.len());
    udp.extend_from_slice(&68u16.to_be_bytes()); // source port
    udp.extend_from_slice(&67u16.to_be_bytes()); // destination port
    udp.extend_from_slice(&udp_length.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    udp.extend_from_slice(&bootp);

    let mut ip = Vec::with_capacity(20 + udp.len());
    ip.push(0x45); // version 4, ihl 5
    ip.push(0x00); // dscp
    // IP total length must count the 20-byte IPv4 header itself, plus the
    // UDP header and BOOTP payload. Using ip.len() here (2 at this point)
    // used to produce 310 instead of 328, making the UDP length exceed the
    // IP payload so the kernel discarded the DISCOVER before any server
    // could see it.
    let total_length = (20 + udp.len()) as u16;
    ip.extend_from_slice(&total_length.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    ip.push(64); // ttl
    ip.push(17); // protocol: udp
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    ip.extend_from_slice(&[0, 0, 0, 0]); // source: 0.0.0.0
    ip.extend_from_slice(&[255, 255, 255, 255]); // destination: broadcast
    let header_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    // UDP checksum with the IPv4 pseudo-header; kept valid so relayed
    // offers from strict servers are not dropped.
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&[0, 0, 0, 0]);
    pseudo.extend_from_slice(&[255, 255, 255, 255]);
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&udp_length.to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let udp_checksum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + ip.len() + udp.len());
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(source_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tagged(frame: &[u8], vlan: u16) -> Vec<u8> {
        tag_frame(frame, vlan).expect("taggable frame")
    }

    #[test]
    fn arp_request_frame_is_well_formed() {
        let frame = build_arp_request(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], "192.168.1.1")
            .expect("valid target");
        assert_eq!(frame.len(), 42);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);
        let info = analyze(&frame, None).expect("analysable");
        assert_eq!(info.vlan, None);
        assert_eq!(info.class, "arp-request");
    }

    #[test]
    fn dhcp_discover_classifies_as_discover() {
        let frame = build_dhcp_discover(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x1234, None);
        let info = analyze(&frame, None).expect("analysable");
        assert_eq!(info.class, "dhcp-discover");
    }

    #[test]
    fn padi_has_service_name_tag() {
        let frame = build_pppoe_padi(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 100);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8863);
        let info = analyze(&frame, None).expect("analysable");
        assert_eq!(info.class, "pppoe-padi");
        assert_eq!(frame[14], 0x11); // version/type
        assert_eq!(frame[15], 0x09); // PADI
        let payload_length = u16::from_be_bytes([frame[18], frame[19]]);
        assert_eq!(payload_length as usize, frame.len() - 20);
    }

    #[test]
    fn tagged_frame_yields_vlan() {
        let frame = build_arp_request(&[0; 6], "10.0.0.1").expect("valid target");
        let tagged = tagged(&frame, 100);
        let info = analyze(&tagged, None).expect("analysable");
        assert_eq!(info.vlan, Some(100));
        assert_eq!(info.class, "arp-request");
    }

    #[test]
    fn tag_frame_inserts_8021q_header() {
        let frame = build_arp_request(&[0x11; 6], "10.0.0.1").expect("valid target");
        let tagged = tagged(&frame, 130);
        assert_eq!(&tagged[12..14], &ETHERTYPE_VLAN.to_be_bytes());
        assert_eq!(u16::from_be_bytes([tagged[14], tagged[15]]) & 0x0fff, 130);
        assert_eq!(&tagged[16..18], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&tagged[18..18 + frame.len() - 14], &frame[14..]);
    }

    #[test]
    fn short_probe_frames_are_padded_to_minimum() {
        // ARP and PADI are far below the 64-byte 802.1Q minimum; without
        // padding some NICs emit runt frames that the peer silently drops.
        let arp = build_arp_request(&[0x11; 6], "10.0.0.1").expect("valid target");
        let padi = build_pppoe_padi(&[0x11; 6], 130);
        assert!(arp.len() + 4 < MIN_TAGGED_FRAME);
        assert!(padi.len() + 4 < MIN_TAGGED_FRAME);
        assert_eq!(tagged(&arp, 130).len(), MIN_TAGGED_FRAME);
        assert_eq!(tagged(&padi, 130).len(), MIN_TAGGED_FRAME);
        // Padding must not change frame semantics.
        let info = analyze(&tagged(&arp, 130), None).expect("analysable");
        assert_eq!(info.vlan, Some(130));
        assert_eq!(info.class, "arp-request");
    }

    #[test]
    fn aux_vlan_recovers_offloaded_tag() {
        // Simulates rx-vlan-offload: the header is stripped before userspace.
        let frame = build_arp_request(&[0x22; 6], "10.0.0.1").expect("valid target");
        let info = analyze(&frame, Some(130)).expect("analysable");
        assert_eq!(info.vlan, Some(130));
    }

    #[test]
    fn offloaded_outer_vid_wins_over_inline_inner_tag() {
        // QinQ with RX offload: the NIC stripped the outer S-VID (130) and
        // left the inner C-VID (200) inline. The scanner must report the
        // outer tag and recognise the frame as double tagged.
        let frame = build_arp_request(&[0x22; 6], "10.0.0.1").expect("valid target");
        let tagged = tagged(&frame, 200);
        let info = analyze(&tagged, Some(130)).expect("analysable");
        assert_eq!(info.vlan, Some(130));
        assert_eq!(info.class, "arp-request (qinq)");
    }

    #[test]
    fn dhcp_total_length_matches_udp_length() {
        let frame = build_dhcp_discover(&[0x33; 6], 0x1234, None);
        let ip = &frame[14..];
        let total_length = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let udp = &ip[20..];
        let udp_length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        assert_eq!(total_length, frame.len() - 14);
        assert_eq!(total_length, 20 + udp_length);
        assert!(total_length >= 20 + udp_length); // UDP fits inside IPv4 payload
    }

    #[test]
    fn parse_mac_accepts_and_rejects() {
        assert_eq!(parse_mac("00:11:22:33:44:55"), Some([0, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("0:11:22:33:44:55"), None);
        assert_eq!(parse_mac("00-11-22-33-44-55"), None);
        assert_eq!(parse_mac("00:11:22:33:44"), None);
    }

    /// Turn a DISCOVER built by build_dhcp_discover() into a plausible OFFER.
    fn make_offer(client_mac: &[u8; 6], xid: u32, vlan: u16, inline_tag: bool) -> Vec<u8> {
        let mut frame = build_dhcp_discover(client_mac, xid, None);
        let udp = 14 + 20;
        let bootp = udp + 8;
        frame[6..12].copy_from_slice(&[0xaa; 6]); // server's source MAC
        frame[udp..udp + 2].copy_from_slice(&67u16.to_be_bytes()); // src port
        frame[udp + 2..udp + 4].copy_from_slice(&68u16.to_be_bytes()); // dst port
        frame[bootp] = 2; // BOOTREPLY
        frame[bootp + 16..bootp + 20].copy_from_slice(&[10, 1, 2, 3]); // yiaddr
        if inline_tag {
            frame = tagged(&frame, vlan);
        }
        frame
    }

    #[test]
    fn probe_reply_detects_dhcp_offer() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = make_offer(&client, 7, 100, true);
        let reply = inspect_probe_reply(&frame, None, &client, 100, 7).expect("offer found");
        let offer = reply.offer.expect("dhcp offer");
        assert_eq!(offer.address, "10.1.2.3");
    }

    #[test]
    fn probe_reply_uses_aux_vlan_when_tag_is_offloaded() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = make_offer(&client, 7, 100, false);
        assert!(inspect_probe_reply(&frame, Some(100), &client, 100, 7).is_some());
        // A reply belonging to a different VLAN must not mark this one alive.
        assert!(inspect_probe_reply(&frame, Some(200), &client, 100, 7).is_none());
    }

    #[test]
    fn probe_reply_rejects_foreign_xid_or_client() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = make_offer(&client, 7, 100, true);
        assert!(inspect_probe_reply(&frame, None, &client, 100, 8).is_none());
        assert!(inspect_probe_reply(&frame, None, &[0x99; 6], 100, 7).is_none());
    }

    /// Build a plausible PADO replying to the PADI for `host_uniq_vlan`.
    fn make_pado(client: &[u8; 6], host_uniq_vlan: u32, unicast: bool) -> Vec<u8> {
        let mut frame = build_pppoe_padi(&[0xaa; 6], host_uniq_vlan);
        frame[6..12].copy_from_slice(&[0xaa; 6]); // AC source MAC
        frame[15] = 0x07; // code: PADO
        if unicast {
            frame[0..6].copy_from_slice(client);
        }
        frame
    }

    #[test]
    fn pado_is_accepted_without_vlan_evidence_when_token_matches() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        // Regression: a previous version required an inline tag or auxdata
        // before accepting any PADO, which silently lost every PPPoE-only
        // VLAN when the kernel stripped the tag before AF_PACKET saw it.
        let pado = make_pado(&client, 100, true);
        assert!(inspect_probe_reply(&pado, None, &client, 100, 7)
            .expect("pado found")
            .pado);
        // Tagged and offloaded variants must work too.
        assert!(inspect_probe_reply(&tagged(&pado, 100), None, &client, 100, 7).is_some());
        assert!(inspect_probe_reply(&pado, Some(100), &client, 100, 7).is_some());
    }

    #[test]
    fn pado_with_foreign_token_or_broadcast_is_ignored() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        // Host-Uniq from another VLAN's PADI must not mark VLAN 100 alive.
        let foreign = make_pado(&client, 200, true);
        assert!(inspect_probe_reply(&foreign, None, &client, 100, 7).is_none());
        // A broadcast PADO could belong to any client; never trust it.
        let broadcast = make_pado(&client, 100, false);
        assert!(inspect_probe_reply(&broadcast, None, &client, 100, 7).is_none());
        // A reply tagged with a different VLAN is always rejected.
        let wrong_vlan = tagged(&make_pado(&client, 100, true), 200);
        assert!(inspect_probe_reply(&wrong_vlan, None, &client, 100, 7).is_none());
    }

    #[test]
    fn arp_reply_reveals_gateway() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut frame = build_arp_request(&client, "10.0.0.1").expect("valid target");
        frame[6..12].copy_from_slice(&[0xaa; 6]); // gateway source MAC
        frame[20..22].copy_from_slice(&2u16.to_be_bytes()); // ARP reply
        frame[28..32].copy_from_slice(&[10, 0, 0, 1]); // sender protocol address
        frame[32..38].copy_from_slice(&client); // target hardware address
        let tagged = tagged(&frame, 130);
        let reply = inspect_probe_reply(&tagged, None, &client, 130, 7).expect("arp reply");
        assert_eq!(reply.gateway.as_deref(), Some("10.0.0.1"));
        // A reply for somebody else's MAC must not count.
        assert!(inspect_probe_reply(&tagged, None, &[0x99; 6], 130, 7).is_none());
    }

    #[test]
    fn dhcp_reply_requires_bootreply_opcode() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        // Untagged frame (VLAN recovered from auxdata), so BOOTP starts at
        // 14 (ethernet) + 20 (IPv4) + 8 (UDP).
        let mut frame = make_offer(&client, 7, 100, false);
        assert!(inspect_probe_reply(&frame, Some(100), &client, 100, 7).is_some());
        frame[14 + 20 + 8] = 1; // BOOTREQUEST instead of BOOTREPLY
        assert!(inspect_probe_reply(&frame, Some(100), &client, 100, 7).is_none());
    }

    #[test]
    fn vendor_class_is_emitted_as_option_60() {
        let frame = build_dhcp_discover(&[0x33; 6], 1, Some("MSFT 5.0"));
        let bootp = &frame[14 + 20 + 8..];
        let option = dhcp_options(bootp)
            .into_iter()
            .find(|(code, _)| *code == 60)
            .expect("option 60 present");
        assert_eq!(option.1, b"MSFT 5.0".to_vec());
        // The extra option must not break the IPv4 / UDP length relation.
        let ip = &frame[14..];
        let udp = &ip[20..];
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        assert_eq!(total, frame.len() - 14);
        assert_eq!(total, 20 + udp_len);
        // No option 60 when unspecified.
        let plain = build_dhcp_discover(&[0x33; 6], 1, None);
        assert!(dhcp_options(&plain[14 + 20 + 8..])
            .iter()
            .all(|(code, _)| *code != 60));
    }

    #[test]
    fn ipv6_extension_header_still_classifies_dhcpv6() {
        let mut frame = vec![0u8; 14 + 40 + 8 + 8];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x60;
        ip[6] = 0; // next header: hop-by-hop options
        ip[40] = 17; // extension header says UDP is next
        ip[41] = 0; // hdr ext len 0 => 8 bytes total
        ip[48..50].copy_from_slice(&547u16.to_be_bytes());
        ip[50..52].copy_from_slice(&546u16.to_be_bytes());
        let info = analyze(&frame, None).expect("analysable");
        assert_eq!(info.class, "dhcpv6");
    }

    #[test]
    fn probe_reply_ignores_own_echoed_frames() {
        let client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut frame = make_offer(&client, 7, 100, true);
        frame[6..12].copy_from_slice(&client);
        assert!(inspect_probe_reply(&frame, None, &client, 100, 7).is_none());
    }
}
