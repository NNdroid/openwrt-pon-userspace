// SPDX-License-Identifier: GPL-2.0-only

//! Frame analysis for the passive scan and fixed construction of the three
//! probe frames. All parsing is bounds-checked slice work; the only frames
//! ever built here are the standard discovery packets (ARP request, PPPoE
//! PADI, DHCP DISCOVER) with no caller-controlled payload.

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

/// Analyse a received ethernet frame. Returns None for runts.
pub fn analyze(frame: &[u8]) -> Option<FrameInfo> {
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
    match payload[6] {
        17 => {
            let l4 = &payload[40..];
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
        58 if payload.len() > 40 => match payload[40] {
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
/// and extract any probe-relevant reply. Frames sourced from our own MAC are
/// ignored, as is anything not tagged with the probed VLAN.
pub fn inspect_probe_reply(frame: &[u8], our_mac: &[u8; 6], vlan: u16) -> Option<ProbeReply> {
    if frame.len() < 14 {
        return None;
    }
    // Replies arrive tagged on the parent interface.
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
    if seen_vlan != Some(vlan) {
        return None;
    }
    if frame.len() < offset + 6 || frame[6..12] == *our_mac {
        return None;
    }
    let payload = &frame[offset..];

    let mut reply = ProbeReply::default();
    match ether_type {
        ETHERTYPE_ARP => {
            if payload.len() >= 28 {
                let opcode = u16::from_be_bytes([payload[6], payload[7]]);
                if opcode == 2 {
                    let sender = [payload[14], payload[15], payload[16], payload[17]];
                    reply.gateway = Some(format_ipv4(&sender));
                }
            }
        }
        ETHERTYPE_PPPOE_DISCOVERY => {
            if payload.len() >= 2 && payload[1] == 0x07 {
                reply.pado = true;
            }
        }
        ETHERTYPE_IPV4 => {
            if payload.len() >= 20 {
                let ihl = ((payload[0] & 0x0f) as usize) * 4;
                if ihl >= 20 && payload.len() >= ihl + 8 && payload[9] == 17 {
                    let l4 = &payload[ihl..];
                    let source_port = u16::from_be_bytes([l4[0], l4[1]]);
                    let destination_port = u16::from_be_bytes([l4[2], l4[3]]);
                    if source_port == 67 && destination_port == 68 && l4.len() >= 8 && l4[8] == 2 {
                        let bootp = &l4[8..];
                        if bootp.len() >= 240 && bootp[236..240] == [0x63, 0x82, 0x53, 0x63] {
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
pub fn build_dhcp_discover(source_mac: &[u8; 6], transaction_id: u32) -> Vec<u8> {
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
    bootp.extend_from_slice(source_mac);
    bootp.extend_from_slice(&[0; 10]); // chaddr padding
    bootp.extend_from_slice(&[0; 64]); // sname
    bootp.extend_from_slice(&[0; 128]); // file
    bootp.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    bootp.extend_from_slice(&[53, 1, 1]); // option 53: DHCPDISCOVER
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
    let total_length = (ip.len() + 8 + bootp.len()) as u16;
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

    #[test]
    fn arp_request_frame_is_well_formed() {
        let frame = build_arp_request(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], "192.168.1.1")
            .expect("valid target");
        assert_eq!(frame.len(), 42);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);
        let info = analyze(&frame).expect("analysable");
        assert_eq!(info.vlan, None);
        assert_eq!(info.class, "arp-request");
    }

    #[test]
    fn dhcp_discover_classifies_as_discover() {
        let frame = build_dhcp_discover(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x1234);
        let info = analyze(&frame).expect("analysable");
        assert_eq!(info.class, "dhcp-discover");
    }

    #[test]
    fn padi_has_service_name_tag() {
        let frame = build_pppoe_padi(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 100);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8863);
        let info = analyze(&frame).expect("analysable");
        assert_eq!(info.class, "pppoe-padi");
        assert_eq!(frame[14], 0x11); // version/type
        assert_eq!(frame[15], 0x09); // PADI
        let payload_length = u16::from_be_bytes([frame[18], frame[19]]);
        assert_eq!(payload_length as usize, frame.len() - 20);
    }

    #[test]
    fn tagged_frame_yields_vlan() {
        let mut frame = build_arp_request(&[0; 6], "10.0.0.1").expect("valid target");
        // Insert an 802.1Q tag with vid 100 after the source MAC.
        let mut tagged = frame[..12].to_vec();
        tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend_from_slice(&100u16.to_be_bytes());
        tagged.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        tagged.extend_from_slice(&frame[14..]);
        frame = tagged;
        let info = analyze(&frame).expect("analysable");
        assert_eq!(info.vlan, Some(100));
        assert_eq!(info.class, "arp-request");
    }

    #[test]
    fn probe_reply_detects_dhcp_offer() {
        let mut offer_frame = build_dhcp_discover(&[0xaa; 6], 7);
        // Turn the discover into a proper offer: swap UDP ports to 67->68,
        // op=2, yiaddr, and option 54 (server identifier) before the end
        // marker.
        let udp = 14 + 20;
        let bootp = udp + 8;
        offer_frame[udp..udp + 2].copy_from_slice(&67u16.to_be_bytes()); // src port
        offer_frame[udp + 2..udp + 4].copy_from_slice(&68u16.to_be_bytes()); // dst port
        offer_frame[bootp] = 2; // bootp op: BOOTREPLY
        offer_frame[bootp + 16..bootp + 20].copy_from_slice(&[10, 1, 2, 3]); // yiaddr
                                                                             // Append option 54 (server identifier) before the end marker. Search
                                                                             // only inside the BOOTP region: the ethernet header is all 0xff.
        let end_position = offer_frame[bootp..]
            .iter()
            .position(|&byte| byte == 255)
            .expect("end marker present")
            + bootp;
        offer_frame[end_position] = 54;
        offer_frame.insert(end_position + 1, 4);
        offer_frame.insert(end_position + 2, 10);
        offer_frame.insert(end_position + 3, 0);
        offer_frame.insert(end_position + 4, 0);
        offer_frame.insert(end_position + 5, 1);
        offer_frame.push(255);
        // Tag it with VLAN 100 like any reply arriving on the parent.
        let mut tagged = offer_frame[..12].to_vec();
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&100u16.to_be_bytes());
        tagged.extend_from_slice(&0x0800u16.to_be_bytes());
        tagged.extend_from_slice(&offer_frame[14..]);
        let reply = inspect_probe_reply(&tagged, &[0x00; 6], 100).expect("offer found");
        let offer = reply.offer.expect("dhcp offer");
        assert_eq!(offer.address, "10.1.2.3");
        assert_eq!(offer.server.as_deref(), Some("10.0.0.1"));
    }
}
