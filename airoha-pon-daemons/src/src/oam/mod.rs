// SPDX-License-Identifier: GPL-2.0-only

//! IEEE 802.3ah and CTC extension OAM state machines.

mod config;
mod control;
mod ctc;
mod frame;
mod ieee;

use std::fs;
use std::io;
use std::path::Path;

use crate::runtime::{parent_interface_mac, parent_xpon_attribute};
use crate::transport::{line_is_down, PacketSocket, PACKET_OUTGOING};

use self::control::{start_server, StatusHub};
use self::ctc::{hex_bytes, CtcSession};
use self::frame::{
    build, OamPdu, CODE_EVENT_NOTIFICATION, CODE_INFORMATION, CODE_LOOPBACK_CONTROL,
    CODE_ORGANIZATION_SPECIFIC, CODE_VARIABLE_REQUEST, FLAGS_STABLE,
};
use self::ieee::IeeeSession;

const RECEIVE_BUFFER_LEN: usize = 2048;

pub use self::config::OamConfig;

pub fn run_agent(interface: &str, mut config: OamConfig, control_socket: &Path) -> io::Result<()> {
    let mut source_mac = parent_interface_mac(interface)?;
    config.active_serial_number = active_serial_number(interface)?;
    let socket = PacketSocket::open(interface)?;
    let service_ready = parent_xpon_attribute(interface, "service_ready")?;
    publish_service_ready(service_ready.as_deref(), false);
    let mut published_service_ready = false;
    let mut line_was_down = false;
    let mut ieee = IeeeSession::new();
    let mut ctc = CtcSession::new();
    let status = StatusHub::new(
        interface,
        &config.operator,
        !config.loid.is_empty(),
        ctc.snapshot(),
        config.clone(),
        source_mac,
    );
    let _control_server = start_server(control_socket, status.clone())?;
    let mut receive_buffer = [0u8; RECEIVE_BUFFER_LEN];

    println!(
        "OAM agent started: interface={} operator={} control_socket={}",
        interface,
        config.operator,
        control_socket.display()
    );

    loop {
        let received = match socket.receive(&mut receive_buffer) {
            Ok(frame) => frame,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if line_is_down(&error) && socket.interface_present() => {
                if !line_was_down {
                    status.record_event("line", "PON control netdev is down".to_owned());
                    published_service_ready = false;
                }
                line_was_down = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        if line_was_down {
            refresh_line_identity(interface, &mut config, &mut source_mac, &status);
            line_was_down = false;
        }
        if received.packet_type == PACKET_OUTGOING {
            continue;
        }

        let pdu = match OamPdu::parse(received.bytes) {
            Ok(pdu) => pdu,
            Err(error) => {
                status.record_parse_error(error);
                continue;
            }
        };
        status.record_rx(pdu.code);

        if config.ctc_enabled()
            && pdu.code == CODE_ORGANIZATION_SPECIFIC
            && ctc.is_authentication_request(pdu.payload, &config)
        {
            refresh_line_identity(interface, &mut config, &mut source_mac, &status);
        }

        let response = match pdu.code {
            CODE_INFORMATION => {
                match ieee.handle_information(pdu.payload, source_mac, &config, &mut ctc) {
                    Ok(payload) => {
                        status.record_ieee_operational();
                        Some(build(source_mac, FLAGS_STABLE, CODE_INFORMATION, &payload))
                    }
                    Err(error) => {
                        status.record_parse_error(error);
                        None
                    }
                }
            }
            CODE_EVENT_NOTIFICATION => {
                ieee.event_rx += 1;
                status.record_event("link-event", "OAM event notification received".to_owned());
                None
            }
            CODE_ORGANIZATION_SPECIFIC if config.ctc_enabled() => {
                match ctc.handle_organization_pdu(pdu.payload, &config, source_mac) {
                    Ok(outcome) => {
                        for event in outcome.events {
                            status.record_event("ctc", event);
                        }
                        outcome.response.map(|payload| {
                            build(
                                source_mac,
                                FLAGS_STABLE,
                                CODE_ORGANIZATION_SPECIFIC,
                                &payload,
                            )
                        })
                    }
                    Err(error) => {
                        status.record_parse_error(error);
                        None
                    }
                }
            }
            CODE_VARIABLE_REQUEST => {
                status.record_event(
                    "unsupported",
                    "IEEE Variable Request received while capability is disabled".to_owned(),
                );
                None
            }
            CODE_LOOPBACK_CONTROL => {
                status.record_event(
                    "unsupported",
                    "IEEE remote loopback request received while capability is disabled".to_owned(),
                );
                None
            }
            code => {
                status.record_event("unsupported", format!("OAM code 0x{code:02x} ignored"));
                None
            }
        };
        let ctc_snapshot = ctc.snapshot();
        let current_service_ready = ctc_snapshot.authentication == "accepted";
        if current_service_ready != published_service_ready {
            publish_service_ready(service_ready.as_deref(), current_service_ready);
            published_service_ready = current_service_ready;
        }
        status.update_ctc(ctc_snapshot);

        if let Some(response) = response {
            if let Err(error) = socket.send(&response) {
                if line_is_down(&error) {
                    if !line_was_down {
                        status.record_event("line", "PON control netdev is down".to_owned());
                        published_service_ready = false;
                    }
                    line_was_down = true;
                    continue;
                }
                return Err(error);
            }
            status.record_tx();
        }
    }
}

fn active_serial_number(interface: &str) -> io::Result<Option<[u8; 8]>> {
    let Some(path) = parent_xpon_attribute(interface, "active_serial_number")? else {
        return Ok(None);
    };
    let text = fs::read_to_string(path)?;
    let text = text.trim();
    if text == "none" {
        return Ok(None);
    }
    if text.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "active PON serial number must contain 16 hexadecimal digits",
        ));
    }
    let serial = u64::from_str_radix(text, 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "active PON serial number contains a non-hex digit",
        )
    })?;
    Ok(Some(serial.to_be_bytes()))
}

/// Re-read the values latched by a new PON line epoch. Keep the previous values
/// on failure so a transient sysfs error cannot change the identity on the wire.
fn refresh_line_identity(
    interface: &str,
    config: &mut OamConfig,
    source_mac: &mut [u8; 6],
    status: &StatusHub,
) {
    let mac = match parent_interface_mac(interface) {
        Ok(mac) => mac,
        Err(error) => {
            status.record_event("line", format!("parent MAC refresh failed: {error}"));
            return;
        }
    };
    let serial = match active_serial_number(interface) {
        Ok(serial) => serial,
        Err(error) => {
            status.record_event("line", format!("active serial refresh failed: {error}"));
            return;
        }
    };

    config.active_serial_number = serial;
    *source_mac = mac;
    status.update_identity(config, mac);

    let serial_text = serial
        .map(|value| hex_bytes(&value))
        .unwrap_or_else(|| "none".to_owned());
    status.record_event(
        "line",
        format!(
            "PON line identity refreshed: mac={} active_serial={}",
            hex_bytes(&mac),
            serial_text
        ),
    );
}

fn publish_service_ready(path: Option<&Path>, ready: bool) {
    let Some(path) = path else {
        return;
    };
    if let Err(error) = fs::write(path, if ready { "1\n" } else { "0\n" }) {
        println!("PON service LED state update failed: {error}");
    }
}
