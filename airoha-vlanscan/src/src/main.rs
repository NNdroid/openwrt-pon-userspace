// SPDX-License-Identifier: GPL-2.0-only

//! vlanscan - safe VLAN id scanner for Airoha PON uplinks.
//!
//! Passive mode (default) listens on the PON interface and reports which
//! 802.1Q VLAN ids carry traffic and what kind of traffic it is. It never
//! transmits anything.
//!
//! Probe mode (--probe) additionally sends exactly three discovery frames
//! per candidate VLAN as 802.1Q-tagged ethernet frames on the parent link:
//! an ARP request, a PPPoE PADI and a DHCP DISCOVER. All three are pure
//! discovery semantics - a PADR (PPPoE session) and a DHCP REQUEST (lease
//! binding) are never sent, so probing cannot establish sessions, bind
//! leases or otherwise alter network state. No temporary subinterface is
//! created, no interface flags or MACs are changed, and UCI configuration
//! is never touched.
//!
//! The source MAC of every probe frame can be overridden with --mac, which
//! is useful when an ISP only answers the MAC already registered for a
//! service VLAN (e.g. the MAC of an existing pon0.<vid> DHCP interface).

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

mod packet;
mod rawsock;

use rawsock::RawPacketSocket;

const NET_CLASS: &str = "/sys/class/net";
const VLAN_CONFIG: &str = "/proc/net/vlan/config";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const RECEIVE_BUFFER_SIZE: usize = 2048;

const DEFAULT_DURATION_SECONDS: u64 = 60;
const DEFAULT_PROBE_WAIT_MS: u64 = 2000;
const DEFAULT_PROBE_INTERVAL_MS: u64 = 200;
const DEFAULT_ARP_TARGET: &str = "192.168.1.1";
const DEFAULT_TRANSACTION_ID: u32 = 0x2b3c4d5e;

/// VLAN ids commonly used by ISPs for internet, IPTV and TR069 services.
/// This is an explicit opt-in preset (`--vlan common`), never an implicit
/// default: service VLAN ids differ by region, so silently probing this list
/// would miss local VLANs while giving the impression that more was scanned.
const COMMON_VLANS: &[u16] = &[
    10, 35, 41, 45, 48, 85, 100, 101, 102, 110, 130, 200, 451, 1000, 1001, 2000, 3000, 3961,
    4001,
];

type Result<T> = std::result::Result<T, Box<dyn Error>>;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_signal: c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc_signal(2, handle_signal as *const () as usize); // SIGINT
        libc_signal(15, handle_signal as *const () as usize); // SIGTERM
    }
}

extern "C" {
    #[link_name = "signal"]
    fn libc_signal(signum: c_int, handler: usize) -> usize;
    fn getpid() -> c_int;
}

/// Escape a string for embedding into a JSON string literal.
fn json_string(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len() + 2);
    for character in text.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' | '\r' => escaped.push(' '),
            control if control.is_control() => {}
            other => escaped.push(other),
        }
    }
    escaped
}

fn mac_text(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Replace a state file atomically. LuCI polls these files every few
/// seconds, so a plain fs::write() can be observed half-written and makes
/// the viewer drop the job's metadata for that poll.
fn atomic_write(path: &Path, temporary: &Path, content: &str) {
    if fs::write(temporary, content).is_ok() {
        let _ = fs::rename(temporary, path);
    }
}

/// Job-mode state file writer. When --job is given the scanner publishes its
/// lifecycle in plain files so that LuCI (or any other supervisor) can
/// display progress across sessions:
///
///   <dir>/pid          our process id (plain text)
///   <dir>/status       running | completed | stopped | failed | interrupted
///   <dir>/job.json     metadata + live progress (rewritten on update)
///   <dir>/results.json final scan results (written once, atomically)
struct Job {
    dir: PathBuf,
    mode: &'static str,
    interface: String,
    params: String,
    id: String,
}

impl Job {
    fn start(dir: PathBuf, mode: &'static str, interface: &str, params: String) -> Result<Self> {
        let id = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        fs::create_dir_all(&dir)?;
        let job = Self {
            dir,
            mode,
            interface: interface.to_owned(),
            params,
            id,
        };
        fs::write(job.dir.join("pid"), unsafe { getpid() }.to_string())?;
        fs::write(job.dir.join("status"), "running")?;
        job.publish("running", "{}");
        Ok(job)
    }

    fn publish(&self, status: &str, progress: &str) {
        let content = format!(
            r#"{{"id":"{}","mode":"{}","interface":"{}","status":"{}","params":{},"progress":{}}}"#,
            json_string(&self.id),
            self.mode,
            json_string(&self.interface),
            status,
            self.params,
            progress
        );
        atomic_write(
            &self.dir.join("job.json"),
            &self.dir.join(".job.tmp"),
            &content,
        );
        let _ = fs::write(self.dir.join("status"), status);
    }

    fn update_progress(&self, progress: &str) {
        self.publish("running", progress);
    }

    /// Write final status and results atomically (tmp file + rename) so a
    /// concurrent reader never sees a partial results.json.
    fn finish(&self, status: &str, results_json: &str) {
        atomic_write(
            &self.dir.join("results.json"),
            &self.dir.join(".results.tmp"),
            results_json,
        );
        self.publish(status, "{}");
    }

    /// Record a fatal error in job.json. results.json stays a valid (empty)
    /// JSON array so the LuCI view never has to special-case an object.
    fn fail(&self, error: &str) {
        let content = format!(
            r#"{{"id":"{}","mode":"{}","interface":"{}","status":"failed","params":{},"progress":{{}},"error":"{}"}}"#,
            json_string(&self.id),
            self.mode,
            json_string(&self.interface),
            self.params,
            json_string(error)
        );
        atomic_write(
            &self.dir.join("job.json"),
            &self.dir.join(".job.tmp"),
            &content,
        );
        let _ = fs::write(self.dir.join("status"), "failed");
        atomic_write(
            &self.dir.join("results.json"),
            &self.dir.join(".results.tmp"),
            "[]",
        );
    }
}

fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

struct Options {
    interface: Option<String>,
    duration_seconds: u64,
    json: bool,
    probe: bool,
    vlans: Option<Vec<u16>>,
    probe_wait: Duration,
    probe_interval: Duration,
    arp_target: String,
    probe_mac: Option<[u8; 6]>,
    vendor_class: Option<String>,
    job_dir: Option<PathBuf>,
}

fn usage() {
    eprintln!(
        "vlanscan {VERSION} - safe VLAN id scanner for Airoha PON uplinks

Usage: vlanscan [options]

Modes:
  (default)        passive listen, never transmits a single byte
  --probe          additionally probe candidate VLANs (ARP + PADI + DHCP
                   DISCOVER, discovery-only, never binds a lease or session)

Options:
  -i, --interface <name>   interface to scan (default: auto-detect the PON
                           device via /sys/class/net/*/xpon)
  --duration <seconds>     passive listen duration (default {DEFAULT_DURATION_SECONDS})
  --probe                  enable active probing
  --vlan <list>            probe candidates: '35,100,1000-1010', 'all' for
                           1-4094, 'common' for a short ISP preset (default:
                           only VLANs already configured on the PON parent)
  --probe-wait <ms>        reply window per VLAN (default {DEFAULT_PROBE_WAIT_MS})
  --probe-interval <ms>    spacing between VLANs (default {DEFAULT_PROBE_INTERVAL_MS})
  --arp-target <a.b.c.d>   address used in the ARP probe (default {DEFAULT_ARP_TARGET})
  --mac <aa:bb:cc:dd:ee:ff>  source MAC for probe frames (default: the PON
                           interface MAC). Use the MAC of the service VLAN
                           interface when the ISP only answers that MAC.
  --vendor-class <text>    DHCP option 60 vendor class (default: omitted).
                           Some ISPs only answer a DISCOVER carrying their
                           expected vendor string.
  --job <dir>              publish job state (status, progress, results) in
                           <dir>; used by the LuCI app for background runs
  --json                   machine-readable output
  -h, --help               show this help
  -V, --version            show version"
    );
}

fn parse_vlan_list(text: &str) -> Result<Vec<u16>> {
    let mut result = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.eq_ignore_ascii_case("all") {
            result.extend(1u16..=4094);
            continue;
        }
        if part.eq_ignore_ascii_case("common") {
            result.extend(COMMON_VLANS.iter().copied());
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("invalid vlan range '{part}'"))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("invalid vlan range '{part}'"))?;
            if start == 0 || start > end || end > 4094 {
                return Err(format!("vlan range '{part}' outside 1-4094").into());
            }
            result.extend(start..=end);
            continue;
        }
        let vlan: u16 = part
            .parse()
            .map_err(|_| format!("invalid vlan id '{part}'"))?;
        if vlan == 0 || vlan > 4094 {
            return Err(format!("vlan id '{vlan}' outside 1-4094").into());
        }
        result.push(vlan);
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

fn parse_arguments(arguments: &[String]) -> Result<Options> {
    let mut options = Options {
        interface: None,
        duration_seconds: DEFAULT_DURATION_SECONDS,
        json: false,
        probe: false,
        vlans: None,
        probe_wait: Duration::from_millis(DEFAULT_PROBE_WAIT_MS),
        probe_interval: Duration::from_millis(DEFAULT_PROBE_INTERVAL_MS),
        arp_target: DEFAULT_ARP_TARGET.to_owned(),
        probe_mac: None,
        vendor_class: None,
        job_dir: None,
    };

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        let mut take = |name: &str| -> Result<String> {
            index += 1;
            arguments
                .get(index)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value").into())
        };
        match argument {
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("vlanscan {VERSION}");
                std::process::exit(0);
            }
            "-i" | "--interface" => options.interface = Some(take("--interface")?),
            "--duration" => {
                let seconds: u64 = take("--duration")?
                    .parse()
                    .map_err(|_| "--duration expects seconds".to_string())?;
                if !(1..=86400).contains(&seconds) {
                    return Err("--duration expects 1-86400 seconds".into());
                }
                options.duration_seconds = seconds;
            }
            "--probe" => options.probe = true,
            "--vlan" => options.vlans = Some(parse_vlan_list(&take("--vlan")?)?),
            "--probe-wait" => {
                let milliseconds: u64 = take("--probe-wait")?
                    .parse()
                    .map_err(|_| "--probe-wait expects milliseconds".to_string())?;
                // Zero would make every VLAN fail silently; an unbounded
                // value would let one job occupy the link for hours.
                if !(100..=60000).contains(&milliseconds) {
                    return Err("--probe-wait expects 100-60000 milliseconds".into());
                }
                options.probe_wait = Duration::from_millis(milliseconds);
            }
            "--probe-interval" => {
                let milliseconds: u64 = take("--probe-interval")?
                    .parse()
                    .map_err(|_| "--probe-interval expects milliseconds".to_string())?;
                if milliseconds > 60000 {
                    return Err("--probe-interval expects 0-60000 milliseconds".into());
                }
                options.probe_interval = Duration::from_millis(milliseconds);
            }
            "--arp-target" => {
                let value = take("--arp-target")?;
                value
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("invalid --arp-target '{value}'"))?;
                options.arp_target = value;
            }
            "--mac" => {
                let value = take("--mac")?;
                options.probe_mac = Some(
                    packet::parse_mac(&value).ok_or_else(|| {
                        format!("invalid --mac '{value}' (expected aa:bb:cc:dd:ee:ff)")
                    })?,
                );
            }
            "--vendor-class" => {
                let value = take("--vendor-class")?;
                if value.is_empty()
                    || value.len() > 255
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                {
                    return Err(
                        "invalid --vendor-class (expected 1-255 printable ASCII characters)".into(),
                    );
                }
                options.vendor_class = Some(value);
            }
            "--job" => options.job_dir = Some(PathBuf::from(take("--job")?)),
            "--json" => options.json = true,
            other => return Err(format!("unknown argument '{other}' (try --help)").into()),
        }
        index += 1;
    }
    Ok(options)
}

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn detect_interface() -> Result<String> {
    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(NET_CLASS)? {
        let entry = entry?;
        if entry.path().join("xpon").is_dir() {
            entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    entries.sort();
    match entries.len() {
        1 => Ok(entries.remove(0)),
        0 => Err("no PON device found under /sys/class/net/*/xpon, pass -i <interface>".into()),
        _ => Err(format!(
            "multiple PON devices found: {}, pass -i <interface>",
            entries.join(", ")
        )
        .into()),
    }
}

fn interface_index(name: &str) -> Result<i32> {
    let value: i32 = read_trimmed(&Path::new(NET_CLASS).join(name).join("ifindex"))?
        .parse()
        .map_err(|_| format!("invalid ifindex for {name}"))?;
    Ok(value)
}

fn interface_mac(name: &str) -> Result<[u8; 6]> {
    let text = read_trimmed(&Path::new(NET_CLASS).join(name).join("address"))?;
    packet::parse_mac(&text).ok_or_else(|| format!("invalid mac address for {name}").into())
}

/// VLAN ids already configured on the PON parent.
///
/// /proc/net/vlan/config is authoritative when present, but it can also be
/// incomplete or absent (802.1Q built into the kernel). Interface names such
/// as `pon0.140` are therefore ALWAYS consulted as a second source. The old
/// either/or fallback silently missed VLANs whenever the config file listed
/// just one of several subinterfaces.
///
/// Kept as a pure function over already-read text/names so the merge can be
/// unit-tested without touching sysfs.
fn merge_configured_vlans(config: &str, names: &[String], interface: &str) -> Vec<u16> {
    let mut vlans: Vec<u16> = Vec::new();
    for line in config.lines().skip(2) {
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() < 3 || fields[2] != interface {
            continue;
        }
        if let Ok(vlan) = fields[1].parse::<u16>() {
            if (1..=4094).contains(&vlan) {
                vlans.push(vlan);
            }
        }
    }
    let prefix = format!("{interface}.");
    for name in names {
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        if let Ok(vlan) = suffix.parse::<u16>() {
            if (1..=4094).contains(&vlan) {
                vlans.push(vlan);
            }
        }
    }
    vlans.sort_unstable();
    vlans.dedup();
    vlans
}

fn configured_vlans(interface: &str) -> Vec<u16> {
    let config = fs::read_to_string(VLAN_CONFIG).unwrap_or_default();
    let names: Vec<String> = fs::read_dir(NET_CLASS)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    merge_configured_vlans(&config, &names, interface)
}

/// The exact candidate list a probe run will use. Shared by run() (for the
/// job metadata) and probe_scan() so the UI always shows the real list.
///
/// With no --vlan argument only the VLANs already configured on the PON
/// parent are probed. ISP assignments differ by region, so guessing a
/// "common" list here would silently miss local VLANs and overstate what was
/// scanned. Widening the search is always an explicit choice: `--vlan
/// common`, `--vlan all`, or an explicit id/range list.
fn build_candidates(options: &Options, interface: &str) -> Vec<u16> {
    let mut candidates = match &options.vlans {
        Some(list) => list.clone(),
        None => configured_vlans(interface),
    };
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn relative_seconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64()
}

#[derive(Default)]
struct TrafficEntry {
    packets: u64,
    classes: BTreeMap<String, u64>,
    first_seen: f64,
    last_seen: f64,
}

fn record(entry: &mut TrafficEntry, class: &str, now: f64) {
    entry.packets += 1;
    *entry.classes.entry(class.to_owned()).or_insert(0) += 1;
    if entry.packets == 1 {
        entry.first_seen = now;
    }
    entry.last_seen = now;
}

fn format_vlan_key(key: Option<u16>) -> String {
    match key {
        Some(vlan) => vlan.to_string(),
        None => "untagged".to_owned(),
    }
}

fn passive_scan(options: &Options, interface: &str, ifindex: i32, job: Option<&Job>) -> Result<()> {
    let socket = RawPacketSocket::bind_interface(ifindex)?;
    let duration = options.duration_seconds.max(1);
    let deadline = Instant::now() + Duration::from_secs(duration);
    let start = Instant::now();
    let mut stats: BTreeMap<Option<u16>, TrafficEntry> = BTreeMap::new();
    let mut buffer = vec![0u8; RECEIVE_BUFFER_SIZE];
    let mut total = 0u64;
    // Option avoids Instant::now() - 1s, which could panic within the first
    // second after boot.
    let mut last_job_update: Option<Instant> = None;
    // Heartbeats are throttled by wall time, not by frame count: a busy PON
    // link can deliver thousands of frames per second, which used to write a
    // log line every 2048 frames and flood the job log.
    let mut last_heartbeat = Instant::now();

    eprintln!("vlanscan: listening on {interface} for {duration}s (passive, no packets are sent)");

    while !stopped() && Instant::now() < deadline {
        // Time-based upkeep must run BEFORE receive(): the socket has a
        // 250ms timeout and returns None on a quiet link. Keeping this work
        // inside the "got a frame" path used to freeze the LuCI progress bar
        // at 0% and emit no heartbeat at all whenever the line went silent.
        let now = relative_seconds(start);
        if let Some(job) = job {
            let due = match last_job_update {
                Some(last) => last.elapsed() >= Duration::from_secs(1),
                None => true,
            };
            if due {
                last_job_update = Some(Instant::now());
                job.update_progress(&format!(
                    r#"{{"seconds":{now:.0},"total_seconds":{duration}}}"#
                ));
            }
        }

        // vlanscan-ctl redirects stderr into a plain log file that LuCI shows
        // inside a <pre>. Always use LF, never CR: a carriage return only
        // overwrites a line on a real terminal, and in a file it concatenates
        // every heartbeat into one unreadable line.
        if !options.json && last_heartbeat.elapsed() >= Duration::from_secs(10) {
            last_heartbeat = Instant::now();
            eprintln!("vlanscan: {total} frames in {now:.0}s of {duration}s (passive)...");
        }

        let Some(received) = socket.receive(&mut buffer)? else {
            continue;
        };
        // Outgoing frames tell the same VLAN story; count them too.
        let Some(info) = packet::analyze(received.data, received.vlan) else {
            continue;
        };
        record(stats.entry(info.vlan).or_default(), &info.class, now);
        total += 1;
    }
    if !options.json {
        eprintln!(
            "vlanscan: passive capture finished after {:.0}s, {total} frames on {} VLAN keys",
            relative_seconds(start),
            stats.len()
        );
    }

    let results = passive_json(&stats);
    if let Some(job) = job {
        let status = if stopped() { "stopped" } else { "completed" };
        job.finish(status, &results);
    }
    if options.json {
        println!("{results}");
    } else {
        print_passive_table(&stats, total);
    }
    Ok(())
}

fn print_passive_table(stats: &BTreeMap<Option<u16>, TrafficEntry>, total: u64) {
    println!("VLAN       packets  first/last (s)   classes");
    println!("---------  -------  ---------------  -------");
    for (vlan, entry) in stats {
        let mut classes: Vec<String> = entry
            .classes
            .iter()
            .map(|(class, count)| format!("{class}={count}"))
            .collect();
        classes.sort();
        println!(
            "{:<9}  {:>7}  {:>6.1} / {:>6.1}  {}",
            format_vlan_key(*vlan),
            entry.packets,
            entry.first_seen,
            entry.last_seen,
            classes.join(", ")
        );
    }
    println!("\n{} frames on {} VLAN keys observed.", total, stats.len());
    if stats.is_empty() {
        eprintln!(
            "vlanscan: nothing seen - is the line up? If the service VLANs are\n\
             currently silent, run again with --probe to actively discover them."
        );
    }
}

fn passive_json(stats: &BTreeMap<Option<u16>, TrafficEntry>) -> String {
    let mut output = String::from("[");
    for (position, (vlan, entry)) in stats.iter().enumerate() {
        if position > 0 {
            output.push(',');
        }
        let vid = match vlan {
            Some(value) => value.to_string(),
            None => "null".to_owned(),
        };
        output.push_str(&format!(
            r#"{{"vid":{vid},"packets":{},"first_seen":{:.2},"last_seen":{:.2},"classes":{{"#,
            entry.packets, entry.first_seen, entry.last_seen
        ));
        for (position, (class, count)) in entry.classes.iter().enumerate() {
            if position > 0 {
                output.push(',');
            }
            output.push_str(&format!(r#""{class}":{count}"#));
        }
        output.push_str("}}");
    }
    output.push(']');
    output
}

/// One probe outcome per candidate VLAN.
#[derive(Default)]
struct ProbeOutcome {
    gateway: Option<String>,
    pado: bool,
    offer_address: Option<String>,
    offer_server: Option<String>,
}

impl ProbeOutcome {
    fn alive(&self) -> bool {
        self.gateway.is_some() || self.pado || self.offer_address.is_some()
    }

    fn services(&self) -> Vec<&str> {
        let mut services = Vec::new();
        if self.pado {
            services.push("pppoe");
        }
        if self.offer_address.is_some() {
            services.push("dhcp");
        }
        if self.gateway.is_some() {
            services.push("l3");
        }
        services
    }
}

fn probe_vlan(
    parent_index: i32,
    probe_mac: [u8; 6],
    vlan: u16,
    options: &Options,
    socket: &RawPacketSocket,
) -> Result<ProbeOutcome> {
    let transaction_id = DEFAULT_TRANSACTION_ID ^ (vlan as u32);
    let mut outcome = ProbeOutcome::default();

    let arp = packet::build_arp_request(&probe_mac, &options.arp_target)
        .ok_or("invalid ARP target")?;
    let frames = [
        packet::tag_frame(&arp, vlan),
        packet::tag_frame(&packet::build_pppoe_padi(&probe_mac, vlan as u32), vlan),
        packet::tag_frame(
            &packet::build_dhcp_discover(
                &probe_mac,
                transaction_id,
                options.vendor_class.as_deref(),
            ),
            vlan,
        ),
    ];

    // The 802.1Q header is part of each frame, so the parent raw socket
    // transmits it verbatim. No subinterface is created: this avoids EEXIST
    // clashes with an already configured service VLAN interface and never
    // changes link state.
    for frame in frames.iter().flatten() {
        socket.send(parent_index, 0x8100, &[0xff; 6], frame)?;
    }

    let deadline = Instant::now() + options.probe_wait;
    let mut buffer = vec![0u8; RECEIVE_BUFFER_SIZE];
    while Instant::now() < deadline && !stopped() {
        let Some(received) = socket.receive(&mut buffer)? else {
            continue;
        };
        if received.pkttype == rawsock::PACKET_OUTGOING {
            continue;
        }
        if let Some(reply) = packet::inspect_probe_reply(
            received.data,
            received.vlan,
            &probe_mac,
            vlan,
            transaction_id,
        ) {
            if let Some(gateway) = reply.gateway {
                outcome.gateway.get_or_insert(gateway);
            }
            outcome.pado |= reply.pado;
            if let Some(offer) = reply.offer {
                outcome.offer_address.get_or_insert(offer.address);
                outcome.offer_server = outcome.offer_server.take().or(offer.server);
            }
            if outcome.pado && outcome.offer_address.is_some() && outcome.gateway.is_some() {
                break;
            }
        }
    }
    Ok(outcome)
}

fn probe_scan(options: &Options, interface: &str, ifindex: i32, job: Option<&Job>) -> Result<()> {
    let candidates = build_candidates(options, interface);
    if candidates.is_empty() {
        return Err(format!(
            "no candidate VLANs: none are configured on {interface}; pass \
             --vlan <ids>, --vlan common or --vlan all, or run a passive scan \
             first to see which VLANs this link actually uses"
        )
        .into());
    }
    let probe_mac = match options.probe_mac {
        Some(mac) => mac,
        None => interface_mac(interface)?,
    };
    let socket = RawPacketSocket::bind_interface(ifindex)?;
    // Unicast DHCP offers addressed to a custom --mac would otherwise be
    // filtered by the NIC. This is socket-scoped and reverted on close.
    if let Err(error) = socket.enable_promiscuous(ifindex) {
        eprintln!(
            "vlanscan: warning: promiscuous receive unavailable ({error}); \
             unicast replies to a custom probe MAC may be missed"
        );
    }

    if !options.json {
        eprintln!(
            "vlanscan: probing {} VLANs on {interface} with source MAC {} \
             (discovery frames only: ARP request, PPPoE PADI, DHCP DISCOVER - \
             no PADR, no DHCP REQUEST)",
            candidates.len(),
            mac_text(&probe_mac)
        );
    }

    let mut alive: Vec<(u16, ProbeOutcome)> = Vec::new();
    // Publishing job.json on every VLAN would mean 4094 writes for an "all"
    // scan. Throttle to once per second, but always publish the last one so
    // the progress bar can actually reach 100%.
    let mut last_progress: Option<Instant> = None;
    let mut consecutive_errors = 0u32;
    for (position, vlan) in candidates.iter().enumerate() {
        if stopped() {
            break;
        }
        if position > 0 {
            std::thread::sleep(options.probe_interval);
            if stopped() {
                break;
            }
        }
        if let Some(job) = job {
            let due = match last_progress {
                Some(last) => last.elapsed() >= Duration::from_secs(1),
                None => true,
            };
            if due || position + 1 == candidates.len() {
                last_progress = Some(Instant::now());
                job.update_progress(&format!(
                    r#"{{"index":{},"total":{},"vlan":{}}}"#,
                    position + 1,
                    candidates.len(),
                    vlan
                ));
            }
        }
        let outcome = match probe_vlan(ifindex, probe_mac, *vlan, options, &socket) {
            Ok(outcome) => {
                consecutive_errors = 0;
                outcome
            }
            Err(error) => {
                consecutive_errors += 1;
                if !options.json {
                    eprintln!("vlanscan: vlan {vlan}: {error}");
                }
                // A failing raw socket fails the same way for every VLAN.
                // Without this guard a dead link turns an "all" scan into
                // hours of identical errors instead of one clear failure.
                if consecutive_errors >= 5 {
                    return Err(format!(
                        "aborting after {consecutive_errors} consecutive probe failures \
                         (last on VLAN {vlan}): {error}"
                    )
                    .into());
                }
                continue;
            }
        };
        if !options.json {
            let gateway = outcome
                .gateway
                .as_deref()
                .map(|value| value.to_owned())
                .unwrap_or_else(|| "-".to_owned());
            let offer = outcome
                .offer_address
                .as_deref()
                .map(|value| value.to_owned())
                .unwrap_or_else(|| "-".to_owned());
            let server = outcome
                .offer_server
                .as_deref()
                .map(|value| format!(" (server {value})"))
                .unwrap_or_default();
            let pado = if outcome.pado { "+" } else { "-" };
            println!(
                "vlan {vlan:<5} arp[{gateway}] pppoe[{pado}] dhcp[{offer}{server}]{}",
                if outcome.alive() { "  ALIVE" } else { "" }
            );
        }
        if outcome.alive() {
            alive.push((*vlan, outcome));
        }
    }

    let results = probe_json(&alive);
    if let Some(job) = job {
        let status = if stopped() { "stopped" } else { "completed" };
        job.finish(status, &results);
    }
    if options.json {
        println!("{results}");
    } else {
        println!();
        if alive.is_empty() {
            println!("No live VLANs found among {} candidates.", candidates.len());
        } else {
            let summary = alive
                .iter()
                .map(|(vlan, outcome)| format!("{}({})", vlan, outcome.services().join("+")))
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "{}/{} candidate VLANs alive: {}",
                alive.len(),
                candidates.len(),
                summary
            );
        }
    }
    Ok(())
}

fn probe_json(alive: &[(u16, ProbeOutcome)]) -> String {
    let mut output = String::from("[");
    for (position, (vlan, outcome)) in alive.iter().enumerate() {
        if position > 0 {
            output.push(',');
        }
        let gateway = outcome
            .gateway
            .as_ref()
            .map(|value| format!(r#""{value}""#))
            .unwrap_or_else(|| "null".to_owned());
        let offer = outcome
            .offer_address
            .as_ref()
            .map(|value| format!(r#""{value}""#))
            .unwrap_or_else(|| "null".to_owned());
        let server = outcome
            .offer_server
            .as_ref()
            .map(|value| format!(r#""{value}""#))
            .unwrap_or_else(|| "null".to_owned());
        output.push_str(&format!(
            r#"{{"vid":{vlan},"pppoe":{},"gateway":{gateway},"dhcp_offer":{offer},"dhcp_server":{server}}}"#,
            outcome.pado
        ));
    }
    output.push(']');
    output
}

fn run() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let options = parse_arguments(&arguments)?;
    install_signal_handlers();

    let interface = match &options.interface {
        Some(name) => name.clone(),
        None => detect_interface()?,
    };
    let ifindex = interface_index(&interface)?;

    let mode = if options.probe { "probe" } else { "passive" };
    let job = match &options.job_dir {
        Some(dir) => {
            let params = if options.probe {
                let candidates = build_candidates(&options, &interface);
                let vlans = format!(
                    "[{}]",
                    candidates
                        .iter()
                        .map(|vlan| vlan.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let mac = match options.probe_mac {
                    Some(value) => value,
                    None => interface_mac(&interface)?,
                };
                let vendor = options
                    .vendor_class
                    .as_ref()
                    .map(|value| format!(r#""{}""#, json_string(value)))
                    .unwrap_or_else(|| "null".to_owned());
                format!(
                    r#"{{"vlans":{vlans},"arp_target":"{}","probe_wait":{},"mac":"{}","vendor_class":{vendor}}}"#,
                    json_string(&options.arp_target),
                    options.probe_wait.as_millis(),
                    mac_text(&mac)
                )
            } else {
                format!(r#"{{"duration":{}}}"#, options.duration_seconds.max(1))
            };
            Some(Job::start(dir.clone(), mode, &interface, params)?)
        }
        None => None,
    };

    let scan_result = if options.probe {
        probe_scan(&options, &interface, ifindex, job.as_ref())
    } else {
        passive_scan(&options, &interface, ifindex, job.as_ref())
    };
    // Normal completion paths finalise the job themselves; only an error
    // return leaves the job running, so mark it failed here.
    if let (Some(job), Err(error)) = (&job, &scan_result) {
        job.fail(&error.to_string());
    }
    scan_result
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vlanscan: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_preset_is_explicit_and_complete() {
        let list = parse_vlan_list("common").expect("valid preset");
        assert_eq!(list.len(), COMMON_VLANS.len());
        assert!(list.contains(&130));
        let mut expected = COMMON_VLANS.to_vec();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(list, expected);
        assert!(parse_vlan_list("common,2001").unwrap().contains(&2001));
        assert!(parse_vlan_list("COMMON").is_ok());
    }

    #[test]
    fn all_preset_covers_8021q_range() {
        let list = parse_vlan_list("all").expect("valid preset");
        assert_eq!(list.len(), 4094);
        assert_eq!(list[0], 1);
        assert_eq!(list[4093], 4094);
    }

    #[test]
    fn explicit_ranges_and_validation() {
        assert_eq!(parse_vlan_list("130,1000-1010").unwrap().len(), 12);
        assert!(parse_vlan_list("0").is_err());
        assert!(parse_vlan_list("4095").is_err());
        assert!(parse_vlan_list("1000-900").is_err());
        assert!(parse_vlan_list("garbage").is_err());
    }

    #[test]
    fn empty_vlan_argument_does_not_implicitly_probe_common_preset() {
        let options = parse_arguments(&[]).expect("default options");
        // An interface name that cannot exist keeps configured_vlans() empty
        // on every host, so any result would have to come from a preset.
        let candidates = build_candidates(&options, "vlanscan-test-no-such-iface");
        assert!(!candidates.iter().any(|vlan| COMMON_VLANS.contains(vlan)));
    }

    #[test]
    fn explicit_common_is_used_when_requested() {
        let mut options = parse_arguments(&[]).expect("default options");
        options.vlans = Some(parse_vlan_list("common").unwrap());
        let candidates = build_candidates(&options, "vlanscan-test-no-such-iface");
        assert_eq!(candidates.len(), COMMON_VLANS.len());
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn configured_vlans_merge_config_and_sysfs() {
        // The config file lists only 130, while pon0.140 exists as a named
        // subinterface. The old either/or fallback returned just 130.
        let config = "VLAN Dev name | VLAN ID\n\
                      Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n\
                      pon0.130 | 130 | pon0\n\
                      eth1.200 | 200 | eth1\n";
        let list = names(&["pon0", "pon0.130", "pon0.140", "wan", "eth1.200"]);
        assert_eq!(
            merge_configured_vlans(config, &list, "pon0"),
            vec![130, 140]
        );
        // Foreign parents must never leak into this interface's candidates.
        assert!(merge_configured_vlans(config, &list, "eth2").is_empty());
    }

    #[test]
    fn configured_vlans_work_without_proc_file() {
        let list = names(&["lo", "pon0", "pon0.130", "pon0.140", "pon0.4095"]);
        assert_eq!(merge_configured_vlans("", &list, "pon0"), vec![130, 140]);
    }

    #[test]
    fn numeric_arguments_are_range_checked() {
        fn args(values: &[&str]) -> Vec<String> {
            values.iter().map(|value| value.to_string()).collect()
        }
        assert!(parse_arguments(&args(&["--probe-wait", "0"])).is_err());
        assert!(parse_arguments(&args(&["--probe-wait", "99"])).is_err());
        assert!(parse_arguments(&args(&["--probe-wait", "999999999999"])).is_err());
        assert!(parse_arguments(&args(&["--probe-wait", "500"])).is_ok());
        assert!(parse_arguments(&args(&["--duration", "0"])).is_err());
        assert!(parse_arguments(&args(&["--duration", "86401"])).is_err());
        assert!(parse_arguments(&args(&["--duration", "60"])).is_ok());
        assert!(parse_arguments(&args(&["--probe-interval", "60001"])).is_err());
        assert!(parse_arguments(&args(&["--probe-interval", "0"])).is_ok());
    }

    #[test]
    fn configured_vlans_deduplicate_and_reject_out_of_range() {
        let config = "header\nheader\npon0.130 | 130 | pon0\npon0.9999 | 9999 | pon0\n";
        let list = names(&["pon0.130", "pon0.0", "pon0.140", "pon0.4095"]);
        assert_eq!(
            merge_configured_vlans(config, &list, "pon0"),
            vec![130, 140]
        );
    }
}
