// SPDX-License-Identifier: GPL-2.0-only

//! vlanscan - safe VLAN id scanner for Airoha PON uplinks.
//!
//! Passive mode (default) listens on the PON interface and reports which
//! 802.1Q VLAN ids carry traffic and what kind of traffic it is. It never
//! transmits anything.
//!
//! Probe mode (--probe) additionally sends exactly three discovery frames
//! per candidate VLAN on a short-lived temporary subinterface: an ARP
//! request, a PPPoE PADI and a DHCP DISCOVER. All three are pure discovery
//! semantics - a PADR (PPPoE session) and a DHCP REQUEST (lease binding)
//! are never sent, so probing cannot establish sessions, bind leases or
//! otherwise alter network state. The temporary subinterface is created and
//! deleted via rtnetlink; UCI configuration is never touched.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

mod packet;
mod rawsock;
mod rtnetlink;

use rawsock::RawPacketSocket;

const NET_CLASS: &str = "/sys/class/net";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const RECEIVE_BUFFER_SIZE: usize = 2048;

const DEFAULT_DURATION_SECONDS: u64 = 60;
const DEFAULT_PROBE_WAIT_MS: u64 = 2000;
const DEFAULT_PROBE_INTERVAL_MS: u64 = 200;
const DEFAULT_ARP_TARGET: &str = "192.168.1.1";
const DEFAULT_TRANSACTION_ID: u32 = 0x2b3c4d5e;

/// Temporary subinterfaces are named vs<vid>; the prefix is distinctive
/// enough that a stale one after a crash is always ours to remove.
const SUBINTERFACE_PREFIX: &str = "vs";

/// Candidate VLANs probed when --vlan is not given: a short list of VLAN ids
/// commonly used by ISPs for internet, IPTV and TR069 services.
const DEFAULT_CANDIDATES: &[u16] = &[
    10, 35, 45, 48, 85, 100, 101, 110, 200, 451, 1000, 1001, 2000, 3000, 4001,
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
            self.id, self.mode, self.interface, status, self.params, progress
        );
        let _ = fs::write(self.dir.join("job.json"), content);
        let _ = fs::write(self.dir.join("status"), status);
    }

    fn update_progress(&self, progress: &str) {
        self.publish("running", progress);
    }

    /// Write final status and results atomically (tmp file + rename) so a
    /// concurrent reader never sees a partial results.json.
    fn finish(&self, status: &str, results_json: &str) {
        let results_path = self.dir.join("results.json");
        let temporary_path = self.dir.join(".results.tmp");
        if fs::write(&temporary_path, results_json).is_ok() {
            let _ = fs::rename(&temporary_path, &results_path);
        }
        self.publish(status, "{}");
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
                           1-4094 (default: a short list of common ISP VLANs)
  --probe-wait <ms>        reply window per VLAN (default {DEFAULT_PROBE_WAIT_MS})
  --probe-interval <ms>    spacing between VLANs (default {DEFAULT_PROBE_INTERVAL_MS})
  --arp-target <a.b.c.d>   address used in the ARP probe (default {DEFAULT_ARP_TARGET})
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
                options.duration_seconds = take("--duration")?
                    .parse()
                    .map_err(|_| "--duration expects seconds".to_string())?;
            }
            "--probe" => options.probe = true,
            "--vlan" => options.vlans = Some(parse_vlan_list(&take("--vlan")?)?),
            "--probe-wait" => {
                let milliseconds: u64 = take("--probe-wait")?
                    .parse()
                    .map_err(|_| "--probe-wait expects milliseconds".to_string())?;
                options.probe_wait = Duration::from_millis(milliseconds);
            }
            "--probe-interval" => {
                let milliseconds: u64 = take("--probe-interval")?
                    .parse()
                    .map_err(|_| "--probe-interval expects milliseconds".to_string())?;
                options.probe_interval = Duration::from_millis(milliseconds);
            }
            "--arp-target" => {
                let value = take("--arp-target")?;
                value
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("invalid --arp-target '{value}'"))?;
                options.arp_target = value;
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
    let bytes = text
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|_| format!("invalid mac address for {name}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("unexpected mac address length for {name}").into())
}

fn link_exists(name: &str) -> bool {
    Path::new(NET_CLASS).join(name).exists()
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

    eprintln!("vlanscan: listening on {interface} for {duration}s (passive, no packets are sent)");

    while !stopped() && Instant::now() < deadline {
        let Some(received) = socket.receive(&mut buffer)? else {
            continue;
        };
        // Outgoing frames tell the same VLAN story; count them too.
        let Some(info) = packet::analyze(received.data) else {
            continue;
        };
        let now = relative_seconds(start);
        record(stats.entry(info.vlan).or_default(), &info.class, now);
        total += 1;

        if let Some(job) = job {
            let due = match last_job_update {
                Some(last) => last.elapsed() >= Duration::from_secs(1),
                None => true,
            };
            if due {
                last_job_update = Some(Instant::now());
                let elapsed = relative_seconds(start);
                job.update_progress(&format!(
                    r#"{{"seconds":{elapsed:.0},"total_seconds":{duration}}}"#
                ));
            }
        }

        // Progress heartbeat on stderr every ~10 seconds of wall time.
        if !options.json && total % 2048 == 0 {
            let elapsed = now;
            let _ = write!(
                std::io::stderr(),
                "vlanscan: {} frames in {elapsed:.0}s...\r",
                total
            );
        }
    }
    let _ = write!(std::io::stderr(), "\n");

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
    our_mac: [u8; 6],
    vlan: u16,
    options: &Options,
    listener: &RawPacketSocket,
) -> Result<ProbeOutcome> {
    let name = format!("{SUBINTERFACE_PREFIX}{vlan}");
    let mut outcome = ProbeOutcome::default();

    // Remove a stale subinterface left over from a crashed run; the name
    // convention makes it unambiguously ours.
    if link_exists(&name) {
        let stale_index = interface_index(&name)?;
        rtnetlink::delete_link(stale_index)?;
    }
    rtnetlink::create_vlan(parent_index, &name, vlan)?;

    // Drop guard: whatever happens below (including ? returns and panics
    // through unwinding), the subinterface is deleted exactly once.
    struct Guard(i32, String);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = rtnetlink::delete_link(self.0);
            eprintln!("vlanscan: removed temporary interface {}", self.1);
        }
    }

    let sub_index = interface_index(&name)?;
    let guard = Guard(sub_index, name.clone());
    let transmit_socket = RawPacketSocket::bind_interface(sub_index)?;
    let sub_mac = interface_mac(&name)?;

    // The three discovery frames, sent one by one through the kernel's
    // standard vlan path. No other traffic is generated.
    if let Some(frame) = packet::build_arp_request(&sub_mac, &options.arp_target) {
        transmit_socket.send(sub_index, 0x0806, &[0xff; 6], &frame)?;
    }
    transmit_socket.send(
        sub_index,
        0x8863,
        &[0xff; 6],
        &packet::build_pppoe_padi(&sub_mac, vlan as u32),
    )?;
    transmit_socket.send(
        sub_index,
        0x0800,
        &[0xff; 6],
        &packet::build_dhcp_discover(&sub_mac, DEFAULT_TRANSACTION_ID ^ (vlan as u32)),
    )?;

    let deadline = Instant::now() + options.probe_wait;
    let mut buffer = vec![0u8; RECEIVE_BUFFER_SIZE];
    while Instant::now() < deadline && !stopped() {
        let Some(received) = listener.receive(&mut buffer)? else {
            continue;
        };
        if received.pkttype == rawsock::PACKET_OUTGOING {
            continue;
        }
        if let Some(reply) = packet::inspect_probe_reply(received.data, &our_mac, vlan) {
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
    let _ = transmit_socket;
    drop(guard);
    Ok(outcome)
}

fn probe_scan(options: &Options, interface: &str, ifindex: i32, job: Option<&Job>) -> Result<()> {
    let candidates = match &options.vlans {
        Some(list) => list.clone(),
        None => DEFAULT_CANDIDATES.to_vec(),
    };
    let our_mac = interface_mac(interface)?;
    let listener = RawPacketSocket::bind_interface(ifindex)?;

    if !options.json {
        eprintln!(
            "vlanscan: probing {} VLANs on {interface} (discovery frames only:\n\
             ARP request, PPPoE PADI, DHCP DISCOVER - no PADR, no DHCP REQUEST)",
            candidates.len()
        );
    }

    let mut alive: Vec<(u16, ProbeOutcome)> = Vec::new();
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
            job.update_progress(&format!(
                r#"{{"index":{},"total":{},"vlan":{}}}"#,
                position + 1,
                candidates.len(),
                vlan
            ));
        }
        let outcome = match probe_vlan(ifindex, our_mac, *vlan, options, &listener) {
            Ok(outcome) => outcome,
            Err(error) => {
                if !options.json {
                    eprintln!("vlanscan: vlan {vlan}: {error}");
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
                let vlans = match &options.vlans {
                    Some(list) => format!(
                        "[{}]",
                        list.iter()
                            .map(|vlan| vlan.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    None => "null".to_owned(),
                };
                format!(
                    r#"{{"vlans":{vlans},"arp_target":"{}","probe_wait":{}}}"#,
                    options.arp_target,
                    options.probe_wait.as_millis()
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
        job.finish("failed", &format!(r#"{{"error":"{error}"}}"#));
    }
    scan_result
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vlanscan: {error}");
        std::process::exit(1);
    }
}
