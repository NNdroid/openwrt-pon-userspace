// SPDX-License-Identifier: GPL-2.0-only

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::{fixed_width, CtcSnFormat, OamConfig};
use super::ctc::{hex_bytes, onu_sn, Snapshot};
use crate::config::loid_field;

const CONTROL_PROTOCOL_VERSION: u8 = 1;
const EVENT_CAPACITY: usize = 256;

#[derive(Clone, Debug)]
struct Event {
    sequence: u64,
    timestamp_ms: u128,
    kind: &'static str,
    message: String,
}

#[derive(Debug)]
struct Inner {
    interface: String,
    operator: String,
    loid_configured: bool,
    oam_config: OamConfig,
    source_mac: [u8; 6],
    ieee_operational: bool,
    rx_messages: u64,
    tx_messages: u64,
    parse_errors: u64,
    information_rx: u64,
    event_rx: u64,
    organization_rx: u64,
    last_code: Option<u8>,
    ctc: Snapshot,
    identity_refresh_ok: bool,
    event_sequence: u64,
    events: VecDeque<Event>,
}

#[derive(Clone)]
pub struct StatusHub {
    shared: Arc<Mutex<Inner>>,
}

impl StatusHub {
    pub fn new(
        interface: &str,
        operator: &str,
        loid_configured: bool,
        ctc: Snapshot,
        oam_config: OamConfig,
        source_mac: [u8; 6],
    ) -> Self {
        let hub = Self {
            shared: Arc::new(Mutex::new(Inner {
                interface: interface.to_owned(),
                operator: operator.to_owned(),
                loid_configured,
                oam_config,
                source_mac,
                ieee_operational: false,
                rx_messages: 0,
                tx_messages: 0,
                parse_errors: 0,
                information_rx: 0,
                event_rx: 0,
                organization_rx: 0,
                last_code: None,
                ctc,
                identity_refresh_ok: true,
                event_sequence: 0,
                events: VecDeque::with_capacity(EVENT_CAPACITY),
            })),
        };
        hub.record_event("lifecycle", "OAM daemon started".to_owned());
        hub
    }

    pub fn record_rx(&self, code: u8) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.rx_messages += 1;
        inner.last_code = Some(code);
        match code {
            0x00 => inner.information_rx += 1,
            0x01 => inner.event_rx += 1,
            0xfe => inner.organization_rx += 1,
            _ => {}
        }
    }

    pub fn record_tx(&self) {
        self.shared
            .lock()
            .expect("status mutex poisoned")
            .tx_messages += 1;
    }

    pub fn record_parse_error(&self, error: &str) {
        self.shared
            .lock()
            .expect("status mutex poisoned")
            .parse_errors += 1;
        self.record_event("parse-error", error.to_owned());
    }

    pub fn record_ieee_operational(&self) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");

        /* The first successful Information exchange marks IEEE OAM operational. */
        if !inner.ieee_operational {
            inner.ieee_operational = true;
            drop(inner);
            self.record_event("ieee-oam", "IEEE OAM discovery completed".to_owned());
        }
    }

    pub fn update_ctc(&self, snapshot: Snapshot) {
        self.shared.lock().expect("status mutex poisoned").ctc = snapshot;
    }

    /// Refresh the values that come from the live PON line epoch.
    pub fn update_identity(&self, config: &OamConfig, source_mac: [u8; 6]) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.oam_config = config.clone();
        inner.source_mac = source_mac;
        inner.identity_refresh_ok = true;
    }

    pub fn set_identity_refresh(&self, ok: bool) {
        self.shared
            .lock()
            .expect("status mutex poisoned")
            .identity_refresh_ok = ok;
    }

    pub fn record_event(&self, kind: &'static str, message: String) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.event_sequence += 1;
        let sequence = inner.event_sequence;
        if inner.events.len() == EVENT_CAPACITY {
            inner.events.pop_front();
        }
        inner.events.push_back(Event {
            sequence,
            timestamp_ms: now_ms(),
            kind,
            message,
        });
    }
}

pub fn start_server(
    socket_path: &Path,
    status: StatusHub,
) -> io::Result<crate::control::ControlServer> {
    crate::control::ControlServer::start(socket_path, move |stream| handle_client(stream, &status))
}

fn handle_client(mut stream: UnixStream, status: &StatusHub) -> io::Result<()> {
    let mut request = String::new();
    BufReader::new(&stream).read_line(&mut request)?;
    let fields: Vec<&str> = request.split_whitespace().collect();

    match fields.as_slice() {
        ["STATUS", "1"] => {
            let inner = status.shared.lock().expect("status mutex poisoned");
            writeln!(stream, "{}", status_json(&inner))
        }
        ["EVENTS", "1", after] => {
            let after = after
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid event cursor"))?;
            write_events(&mut stream, status, after)
        }
        _ => writeln!(
            stream,
            "{{\"error\":\"unsupported control request\",\"protocol_version\":{CONTROL_PROTOCOL_VERSION}}}"
        ),
    }
}

fn write_events(stream: &mut UnixStream, status: &StatusHub, after: u64) -> io::Result<()> {
    let inner = status.shared.lock().expect("status mutex poisoned");
    for event in inner.events.iter().filter(|event| event.sequence > after) {
        writeln!(stream, "{}", event_json(event))?;
    }
    stream.flush()
}

#[derive(Clone, Copy)]
struct IdentitySentFlags {
    vendor_id: bool,
    model: bool,
    equipment_id: bool,
    hardware_version: bool,
    software_version: bool,
}

/// Which identity fields are actually carried by CTC leaf 0xC7/0x0001.
/// Composite mode sends every configured field; active mode only sends the
/// latched serial, except that the historical fallback uses vendor ID plus
/// the last four MAC bytes.
fn identity_sent_flags(config: &OamConfig, ctc_active: bool, ctc_v3: bool) -> IdentitySentFlags {
    let composite = ctc_active && config.ctc_sn_format == CtcSnFormat::Composite;
    let active_fallback = ctc_active
        && config.ctc_sn_format == CtcSnFormat::Active
        && config.active_serial_number.is_none();

    IdentitySentFlags {
        vendor_id: composite || active_fallback,
        model: composite,
        equipment_id: composite && ctc_v3,
        hardware_version: composite,
        software_version: composite,
    }
}

fn status_json(inner: &Inner) -> String {
    let carrier = read_carrier(&inner.interface)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let selected_version = inner
        .ctc
        .selected_version
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let authentication_failure = inner
        .ctc
        .authentication_failure
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let last_code = inner
        .last_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let vlan_mode = inner
        .ctc
        .vlan_mode
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let vlan_object = inner
        .ctc
        .vlan_object
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let vlan_ids = inner
        .ctc
        .vlan_ids
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    /* Report the exact bytes the CTC agent puts on the wire, not the raw UCI
     * values: the ONU SN follows the configured active/composite format, and
     * the LOID is right-aligned into a 24-byte field. */
    let onu_sn_hex = hex_bytes(&onu_sn(
        &inner.oam_config,
        inner.source_mac,
        inner.ctc.selected_version,
    ));
    let loid_sent_hex = hex_bytes(&loid_field(
        &inner.oam_config.loid,
        24,
        inner.oam_config.loid_padding,
    ));
    let source_mac = inner
        .source_mac
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    /* Publish each configured identity field with the bytes the CTC agent
     * really returns, so LuCI can show the zero padding and the fields the
     * current ONU SN format uses without duplicating that logic. */
    let config = &inner.oam_config;
    let ctc_active = inner.operator == "ctc";
    let ctc_v3 = ctc_active && inner.ctc.selected_version.unwrap_or(0) >= 0x30;
    let sent = identity_sent_flags(config, ctc_active, ctc_v3);
    let firmware: Vec<u8> = config.firmware_version.iter().copied().take(127).collect();
    let chipset_text = hex_bytes(&config.chipset_id);
    let ports = config.ge_ports.to_string();
    let onu_identity = format!(
        concat!(
            "{{\"vendor_id\":{},\"model\":{},\"equipment_id\":{},",
            "\"hardware_version\":{},\"software_version\":{},",
            "\"firmware_version\":{},\"chipset_id\":{},\"ge_ports\":{}}}"
        ),
        identity_field_json(
            &config.vendor_id,
            &fixed_width(&config.vendor_id, 4),
            sent.vendor_id
        ),
        identity_field_json(&config.model, &fixed_width(&config.model, 4), sent.model),
        identity_field_json(
            &config.equipment_id,
            &fixed_width(&config.equipment_id, 16),
            sent.equipment_id,
        ),
        identity_field_json(
            &config.hardware_version,
            &fixed_width(&config.hardware_version, 8),
            sent.hardware_version,
        ),
        identity_field_json(
            &config.software_version,
            &fixed_width(&config.software_version, 16),
            sent.software_version,
        ),
        identity_field_json(&firmware, &firmware, ctc_active),
        identity_field_json(chipset_text.as_bytes(), &config.chipset_id, ctc_active),
        identity_field_json(ports.as_bytes(), &[config.ge_ports], ctc_active),
    );

    format!(
        concat!(
            "{{\"protocol_version\":{},\"interface\":{},\"channel_available\":{},",
            "\"operator\":{},\"ieee_discovery_completed\":{},\"loid_configured\":{},",
            "\"rx_messages\":{},",
            "\"tx_messages\":{},\"parse_errors\":{},\"information_rx\":{},",
            "\"event_rx\":{},\"organization_rx\":{},\"last_code\":{},",
            "\"ctc_discovery_state\":{},\"ctc_version\":{},",
            "\"source_mac\":{},\"onu_identity\":{},\"onu_sn\":{},\"loid_sent\":{},",
            "\"authentication_status\":{},\"authentication_failure\":{},",
            "\"ctc_get_requests\":{},\"ctc_set_requests\":{},",
            "\"ctc_unsupported_requests\":{},\"vlan_object\":{},\"vlan_mode\":{},",
            "\"vlan_ids\":[{}],\"identity_refresh_ok\":{},\"event_sequence\":{}}}"
        ),
        CONTROL_PROTOCOL_VERSION,
        json_string(&inner.interface),
        carrier,
        json_string(&inner.operator),
        inner.ieee_operational,
        inner.loid_configured,
        inner.rx_messages,
        inner.tx_messages,
        inner.parse_errors,
        inner.information_rx,
        inner.event_rx,
        inner.organization_rx,
        last_code,
        json_string(inner.ctc.discovery_state),
        selected_version,
        json_string(&source_mac),
        onu_identity,
        json_string(&onu_sn_hex),
        json_string(&loid_sent_hex),
        json_string(inner.ctc.authentication),
        authentication_failure,
        inner.ctc.get_requests,
        inner.ctc.set_requests,
        inner.ctc.unsupported_requests,
        vlan_object,
        vlan_mode,
        vlan_ids,
        inner.identity_refresh_ok,
        inner.event_sequence,
    )
}

fn identity_field_json(text: &[u8], wire: &[u8], sent: bool) -> String {
    let text = String::from_utf8_lossy(text);

    format!(
        "{{\"text\":{},\"wire\":{},\"sent\":{}}}",
        json_string(&text),
        json_string(&hex_bytes(wire)),
        sent
    )
}

fn event_json(event: &Event) -> String {
    format!(
        "{{\"sequence\":{},\"timestamp_ms\":{},\"kind\":{},\"message\":{}}}",
        event.sequence,
        event.timestamp_ms,
        json_string(event.kind),
        json_string(&event.message)
    )
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn read_carrier(interface: &str) -> Option<bool> {
    match fs::read_to_string(format!("/sys/class/net/{interface}/carrier"))
        .ok()?
        .trim()
    {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_field_json_reports_wire_bytes_and_sent_flag() {
        assert_eq!(
            identity_field_json(b"AN7581", b"AN7581\0\0", true),
            "{\"text\":\"AN7581\",\"wire\":\"414e3738310000\",\"sent\":true}"
        );
        assert_eq!(
            identity_field_json(b"", &[0; 4], false),
            "{\"text\":\"\",\"wire\":\"00000000\",\"sent\":false}"
        );
    }

    #[test]
    fn identity_sent_flags_follow_the_ctc_sn_format() {
        let mut config = OamConfig::default();

        let active = identity_sent_flags(&config, true, true);
        assert!(active.vendor_id);
        assert!(!active.model);
        assert!(!active.equipment_id);
        assert!(!active.hardware_version);
        assert!(!active.software_version);

        config.active_serial_number = Some(*b"HWTC1234");
        let active_serial = identity_sent_flags(&config, true, true);
        assert!(!active_serial.vendor_id);
        assert!(!active_serial.model);

        config.ctc_sn_format = CtcSnFormat::Composite;
        let composite = identity_sent_flags(&config, true, false);
        assert!(composite.vendor_id);
        assert!(composite.model);
        assert!(!composite.equipment_id);
        assert!(composite.hardware_version);
        assert!(composite.software_version);

        let composite_v3 = identity_sent_flags(&config, true, true);
        assert!(composite_v3.equipment_id);

        let ieee = identity_sent_flags(&config, false, true);
        assert!(!ieee.vendor_id);
        assert!(!ieee.model);
    }

    #[test]
    fn status_json_reports_identity_refresh_state() {
        use super::super::ctc::CtcSession;

        let hub = StatusHub::new(
            "oam0",
            "ctc",
            false,
            CtcSession::new().snapshot(),
            OamConfig::default(),
            [0; 6],
        );
        hub.set_identity_refresh(false);
        let inner = hub.shared.lock().expect("status mutex poisoned");
        let json = status_json(&inner);
        assert!(json.contains("\"identity_refresh_ok\":false"));
    }

    #[test]
    fn update_identity_replaces_status_snapshot_values() {
        use super::super::ctc::CtcSession;

        let hub = StatusHub::new(
            "oam0",
            "ctc",
            false,
            CtcSession::new().snapshot(),
            OamConfig::default(),
            [0; 6],
        );
        let mut config = OamConfig::default();
        config.active_serial_number = Some(*b"HWTC1234");
        let source_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

        hub.set_identity_refresh(false);
        hub.update_identity(&config, source_mac);

        let inner = hub.shared.lock().expect("status mutex poisoned");
        assert_eq!(inner.oam_config.active_serial_number, Some(*b"HWTC1234"));
        assert_eq!(inner.source_mac, source_mac);
        assert!(inner.identity_refresh_ok);
    }
}
