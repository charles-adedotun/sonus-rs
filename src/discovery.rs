//! HomePod / AirPlay 2 mDNS discovery, DACP service advertisement, and Environment Doctor.

use crate::config::SonusConfig;
use crate::error::SonusError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tracing::{debug, info};

/// DNS record types
pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;

/// DNS class IN (Internet)
pub const CLASS_IN: u16 = 1;

/// AirPlay 2 / HomePod device discovered on the local network via mDNS / Bonjour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub model: String,
    pub device_id: String,
    pub features: String,
    pub os_version: String,
}

/// Result of an individual environmental diagnostic doctor check.
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Encode a domain name into DNS wire format (sequence of length-prefixed labels ending with 0).
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let trimmed = name.trim_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            let len = bytes.len().min(63) as u8;
            out.push(len);
            out.extend_from_slice(&bytes[..len as usize]);
        }
    }
    out.push(0);
    out
}

/// Parse a DNS domain name from buffer supporting RFC 1035 / RFC 6762 compression pointers (0xC0).
///
/// Returns `(name, bytes_consumed_at_initial_stream)`.
pub fn parse_dns_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut bytes_consumed = 0;
    let mut jumps = 0;

    loop {
        if offset >= buf.len() {
            return Err("Unexpected EOF parsing DNS name".to_string());
        }
        let len = buf[offset] as usize;
        if len == 0 {
            if !jumped {
                bytes_consumed += 1;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err("Unexpected EOF reading pointer".to_string());
            }
            if !jumped {
                bytes_consumed += 2;
                jumped = true;
            }
            let ptr = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
            if jumps > 20 {
                return Err("DNS pointer loop detected".to_string());
            }
            continue;
        } else {
            offset += 1;
            if !jumped {
                bytes_consumed += 1;
            }
            if offset + len > buf.len() {
                return Err("Unexpected EOF in DNS label".to_string());
            }
            let label = String::from_utf8_lossy(&buf[offset..offset + len]).to_string();
            labels.push(label);
            offset += len;
            if !jumped {
                bytes_consumed += len;
            }
        }
    }

    Ok((labels.join("."), bytes_consumed))
}

/// Raw DNS record header and rdata boundaries within a DNS message buffer.
#[derive(Debug, Clone)]
pub struct RawDnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata_offset: usize,
    pub rdlength: usize,
}

/// Build an mDNS query packet requesting PTR records for a given service.
pub fn build_mdns_query(service_name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // Transaction ID: 0 for mDNS
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Flags: 0x0000 (Standard Query)
    packet.extend_from_slice(&0u16.to_be_bytes());
    // QDCOUNT: 1
    packet.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    // NSCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT: 0
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Question
    let qname = encode_dns_name(service_name);
    packet.extend_from_slice(&qname);
    // QTYPE: PTR (12)
    packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
    // QCLASS: IN with QU unicast-response flag (0x8001)
    packet.extend_from_slice(&0x8001u16.to_be_bytes());

    packet
}

/// Parse a raw DNS/mDNS message buffer into question count and a list of resource records.
pub fn parse_mdns_packet(buf: &[u8]) -> Result<Vec<RawDnsRecord>, String> {
    if buf.len() < 12 {
        return Err("Packet too short for DNS header".to_string());
    }
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an_count = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns_count = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar_count = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut offset = 12;
    // Skip questions
    for _ in 0..qd_count {
        if offset >= buf.len() {
            return Err("Truncated question in DNS packet".to_string());
        }
        let (_, consumed) = parse_dns_name(buf, offset)?;
        offset += consumed;
        if offset + 4 > buf.len() {
            return Err("Truncated question type/class".to_string());
        }
        offset += 4;
    }

    let total_records = an_count + ns_count + ar_count;
    let mut records = Vec::with_capacity(total_records);

    for _ in 0..total_records {
        if offset >= buf.len() {
            break;
        }
        let (name, consumed) = parse_dns_name(buf, offset)?;
        offset += consumed;
        if offset + 10 > buf.len() {
            return Err("Truncated record header".to_string());
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) & 0x7FFF;
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > buf.len() {
            return Err("Truncated record data".to_string());
        }
        let rdata_offset = offset;
        offset += rdlength;

        records.push(RawDnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata_offset,
            rdlength,
        });
    }

    Ok(records)
}

/// Correlate PTR, SRV, TXT, and A resource records in an mDNS message to assemble `DiscoveredDevice`s.
pub fn extract_devices_from_dns(
    buf: &[u8],
    records: &[RawDnsRecord],
    fallback_ip: &str,
) -> Vec<DiscoveredDevice> {
    let mut instances = HashMap::new();
    let mut srv_map = HashMap::new();
    let mut txt_map = HashMap::new();
    let mut a_map = HashMap::new();

    for rec in records {
        let name_lower = rec.name.to_ascii_lowercase();
        match rec.rtype {
            TYPE_PTR => {
                if let Ok((target, _)) = parse_dns_name(buf, rec.rdata_offset) {
                    let target_lower = target.to_ascii_lowercase();
                    instances.insert(target_lower, target);
                }
            }
            TYPE_SRV if rec.rdlength >= 6 => {
                let port =
                    u16::from_be_bytes([buf[rec.rdata_offset + 4], buf[rec.rdata_offset + 5]]);
                if let Ok((target_host, _)) = parse_dns_name(buf, rec.rdata_offset + 6) {
                    instances.insert(name_lower.clone(), rec.name.clone());
                    srv_map.insert(name_lower, (port, target_host));
                }
            }
            TYPE_TXT => {
                let mut map = HashMap::new();
                let mut cur = rec.rdata_offset;
                let end = rec.rdata_offset + rec.rdlength;
                while cur < end {
                    let len = buf[cur] as usize;
                    cur += 1;
                    if cur + len <= end {
                        if let Ok(entry) = std::str::from_utf8(&buf[cur..cur + len]) {
                            if let Some((k, v)) = entry.split_once('=') {
                                map.insert(k.to_ascii_lowercase(), v.to_string());
                            }
                        }
                    }
                    cur += len;
                }
                instances.insert(name_lower.clone(), rec.name.clone());
                txt_map.insert(name_lower, map);
            }
            TYPE_A if rec.rdlength == 4 => {
                let o = rec.rdata_offset;
                let ip = format!("{}.{}.{}.{}", buf[o], buf[o + 1], buf[o + 2], buf[o + 3]);
                a_map.insert(name_lower, ip);
            }
            _ => {}
        }
    }

    let mut devices = Vec::new();

    for (inst_lower, inst_orig) in instances {
        if !inst_lower.contains("_airplay._tcp") && !inst_lower.contains("apple") {
            continue;
        }

        let display_name = inst_orig
            .split('.')
            .next()
            .unwrap_or(&inst_orig)
            .to_string();

        let (port, target_host) = srv_map
            .get(&inst_lower)
            .cloned()
            .unwrap_or_else(|| (7000, format!("{display_name}.local")));

        let host_lower = target_host.to_ascii_lowercase();

        let ip = a_map
            .get(&host_lower)
            .or_else(|| a_map.get(&inst_lower))
            .or_else(|| {
                if a_map.len() == 1 {
                    a_map.values().next()
                } else {
                    None
                }
            })
            .cloned()
            .unwrap_or_else(|| fallback_ip.to_string());

        if ip.is_empty() || ip == "0.0.0.0" {
            continue;
        }

        let txt = txt_map.get(&inst_lower);
        let model = txt
            .and_then(|m| m.get("model"))
            .cloned()
            .unwrap_or_else(|| "HomePod".to_string());
        let device_id = txt
            .and_then(|m| m.get("deviceid"))
            .cloned()
            .unwrap_or_default();
        let features = txt
            .and_then(|m| m.get("features"))
            .cloned()
            .unwrap_or_default();
        let os_version = txt
            .and_then(|m| m.get("osvers").or_else(|| m.get("srcvers")))
            .cloned()
            .unwrap_or_default();

        devices.push(DiscoveredDevice {
            name: display_name,
            ip,
            port,
            model,
            device_id,
            features,
            os_version,
        });
    }

    devices
}

/// Unescape Avahi parsable format escape sequences (e.g. `\032` -> `' '`, `\059` -> `';'`).
pub fn unescape_avahi_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut digits = String::new();
            while let Some(&next_c) = chars.peek() {
                if next_c.is_ascii_digit() && digits.len() < 3 {
                    digits.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            if digits.len() == 3 {
                if let Ok(code) = digits.parse::<u8>() {
                    out.push(code as char);
                    continue;
                }
            }
            if !digits.is_empty() {
                out.push('\\');
                out.push_str(&digits);
            } else if let Some(escaped) = chars.next() {
                out.push(escaped);
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse output from `avahi-browse -rtkp _airplay._tcp`.
pub fn parse_avahi_browse_output(output: &str) -> Vec<DiscoveredDevice> {
    let mut devices = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('=') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split(';').collect();
        if parts.len() < 9 {
            continue;
        }

        let raw_name = parts[3];
        let name = unescape_avahi_str(raw_name);
        let ip = parts[7].trim().to_string();
        let port = parts[8].trim().parse::<u16>().unwrap_or(7000);

        if ip.is_empty() || ip == "0.0.0.0" {
            continue;
        }

        let txt_blob = parts[9..].join(";");
        let mut model = String::new();
        let mut device_id = String::new();
        let mut features = String::new();
        let mut os_version = String::new();

        let mut in_quote = false;
        let mut cur_token = String::new();
        for ch in txt_blob.chars() {
            if ch == '"' {
                if in_quote {
                    if let Some((k, v)) = cur_token.split_once('=') {
                        match k.to_ascii_lowercase().as_str() {
                            "model" => model = v.to_string(),
                            "deviceid" => device_id = v.to_string(),
                            "features" => features = v.to_string(),
                            "osvers" => os_version = v.to_string(),
                            "srcvers" if os_version.is_empty() => os_version = v.to_string(),
                            _ => {}
                        }
                    }
                    cur_token.clear();
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            } else if in_quote {
                cur_token.push(ch);
            }
        }

        if model.is_empty() {
            model = "HomePod".to_string();
        }

        devices.push(DiscoveredDevice {
            name,
            ip,
            port,
            model,
            device_id,
            features,
            os_version,
        });
    }

    devices
}

/// Deduplicate discovered devices by IP/port, retaining richest metadata.
pub fn deduplicate_devices(devices: Vec<DiscoveredDevice>) -> Vec<DiscoveredDevice> {
    let mut map: HashMap<(String, u16), DiscoveredDevice> = HashMap::new();

    for dev in devices {
        let key = (dev.ip.clone(), dev.port);
        match map.get_mut(&key) {
            Some(existing) => {
                if (existing.model.is_empty() || existing.model == "HomePod")
                    && !dev.model.is_empty()
                    && dev.model != "HomePod"
                {
                    existing.model = dev.model;
                }
                if existing.device_id.is_empty() && !dev.device_id.is_empty() {
                    existing.device_id = dev.device_id;
                }
                if existing.features.is_empty() && !dev.features.is_empty() {
                    existing.features = dev.features;
                }
                if existing.os_version.is_empty() && !dev.os_version.is_empty() {
                    existing.os_version = dev.os_version;
                }
            }
            None => {
                map.insert(key, dev);
            }
        }
    }

    map.into_values().collect()
}

/// Discovers Apple HomePod and AirPlay 2 targets across the local network.
///
/// Uses both pure-Rust direct UDP multicast mDNS queries on `224.0.0.251:5353` and
/// `avahi-browse -rtkp _airplay._tcp` fallback, deduplicating devices by IP and port.
pub async fn discover_homepods(timeout_secs: u64) -> Result<Vec<DiscoveredDevice>, SonusError> {
    let mut all_devices = Vec::new();

    // 1. Direct pure-Rust UDP multicast mDNS query
    match perform_mdns_query(timeout_secs).await {
        Ok(devices) => {
            info!("Pure-Rust mDNS discovery found {} device(s)", devices.len());
            all_devices.extend(devices);
        }
        Err(e) => {
            debug!("Direct mDNS query error: {}", e);
        }
    }

    // 2. Complementary / fallback avahi-browse
    match perform_avahi_browse(timeout_secs.min(3)).await {
        Ok(devices) => {
            info!("avahi-browse discovery found {} device(s)", devices.len());
            all_devices.extend(devices);
        }
        Err(e) => {
            debug!("avahi-browse fallback encountered: {}", e);
        }
    }

    let deduplicated = deduplicate_devices(all_devices);
    info!(
        "Total unique HomePod / AirPlay 2 devices discovered: {}",
        deduplicated.len()
    );
    Ok(deduplicated)
}

async fn perform_mdns_query(timeout_secs: u64) -> Result<Vec<DiscoveredDevice>, SonusError> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let query_qu = build_mdns_query("_airplay._tcp.local");

    let mut query_mc = query_qu.clone();
    let qlen = query_mc.len();
    if qlen >= 2 {
        query_mc[qlen - 2] = 0x00;
        query_mc[qlen - 1] = 0x01;
    }

    let _ = socket.send_to(&query_qu, "224.0.0.251:5353").await;
    let _ = socket.send_to(&query_mc, "224.0.0.251:5353").await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut devices = Vec::new();
    let mut buf = [0u8; 4096];

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, peer))) => {
                if let Ok(records) = parse_mdns_packet(&buf[..len]) {
                    let dev =
                        extract_devices_from_dns(&buf[..len], &records, &peer.ip().to_string());
                    devices.extend(dev);
                }
            }
            Ok(Err(e)) => {
                debug!("Error receiving mDNS UDP packet: {}", e);
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(devices)
}

async fn perform_avahi_browse(timeout_secs: u64) -> Result<Vec<DiscoveredDevice>, SonusError> {
    let timeout_cmd = format!(
        "timeout {} avahi-browse -rtkp _airplay._tcp",
        timeout_secs.max(1)
    );
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&timeout_cmd)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_avahi_browse_output(&stdout))
}

/// Connects a non-blocking UDP socket to `target_ip:7000` and reads `local_addr().ip()`
/// so mDNS and RTSP always use the exact LAN interface IP.
pub fn get_local_ip_for_target(target_ip: &str) -> String {
    let target = if target_ip.contains(':') {
        target_ip.to_string()
    } else {
        format!("{target_ip}:7000")
    };

    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = socket.set_nonblocking(true);
        if socket.connect(&target).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                let ip = local_addr.ip();
                if !ip.is_unspecified() {
                    return ip.to_string();
                }
            }
        }
    }

    "127.0.0.1".to_string()
}

/// Build standard mDNS response packet for DACP service advertisement.
pub fn build_dacp_mdns_response(
    query_id: u16,
    dacp_id: &str,
    port: u16,
    hostname: &str,
    local_ip: &str,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(512);
    // Header
    resp.extend_from_slice(&query_id.to_be_bytes());
    resp.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&3u16.to_be_bytes()); // ANCOUNT = 3 (PTR, SRV, TXT)
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1 (A)

    let srv_name = format!("iTunes_Ctrl_{dacp_id}._dacp._tcp.local");
    let host_name = format!("{}.local", hostname.trim_end_matches(".local"));

    // 1. PTR record: _dacp._tcp.local -> iTunes_Ctrl_<dacp_id>._dacp._tcp.local
    resp.extend_from_slice(&encode_dns_name("_dacp._tcp.local"));
    resp.extend_from_slice(&TYPE_PTR.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&4500u32.to_be_bytes());
    let ptr_rdata = encode_dns_name(&srv_name);
    resp.extend_from_slice(&(ptr_rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&ptr_rdata);

    // 2. SRV record: iTunes_Ctrl_<dacp_id>._dacp._tcp.local
    resp.extend_from_slice(&encode_dns_name(&srv_name));
    resp.extend_from_slice(&TYPE_SRV.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&120u32.to_be_bytes());
    let target_rdata = encode_dns_name(&host_name);
    let srv_rdlen = 6 + target_rdata.len() as u16;
    resp.extend_from_slice(&srv_rdlen.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // priority
    resp.extend_from_slice(&0u16.to_be_bytes()); // weight
    resp.extend_from_slice(&port.to_be_bytes()); // port
    resp.extend_from_slice(&target_rdata);

    // 3. TXT record: txtvers=1, Ver=131075, DbId=<dacp_id>, OSsi=0x1F5
    resp.extend_from_slice(&encode_dns_name(&srv_name));
    resp.extend_from_slice(&TYPE_TXT.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&4500u32.to_be_bytes());
    let txt_entries = [
        "txtvers=1",
        "Ver=131075",
        &format!("DbId={dacp_id}"),
        "OSsi=0x1F5",
    ];
    let mut txt_rdata = Vec::new();
    for entry in &txt_entries {
        let b = entry.as_bytes();
        txt_rdata.push(b.len() as u8);
        txt_rdata.extend_from_slice(b);
    }
    resp.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&txt_rdata);

    // 4. A record: <host_name> -> local_ip
    resp.extend_from_slice(&encode_dns_name(&host_name));
    resp.extend_from_slice(&TYPE_A.to_be_bytes());
    resp.extend_from_slice(&CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&120u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    if let Ok(ip_addr) = local_ip.parse::<Ipv4Addr>() {
        resp.extend_from_slice(&ip_addr.octets());
    } else {
        resp.extend_from_slice(&[127, 0, 0, 1]);
    }

    resp
}

fn create_multicast_socket(addr: SocketAddrV4) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket.bind(&SocketAddr::V4(addr).into())?;
    Ok(std::net::UdpSocket::from(socket))
}

fn create_and_bind_mdns_responder_socket() -> std::io::Result<tokio::net::UdpSocket> {
    let std_sock = create_multicast_socket(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353))?;
    std_sock.set_nonblocking(true)?;
    let _ = std_sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED);
    tokio::net::UdpSocket::from_std(std_sock)
}

async fn handle_mdns_query(
    socket: &tokio::net::UdpSocket,
    buf: &[u8],
    peer: SocketAddr,
    dacp_id: &str,
    port: u16,
    hostname: &str,
    local_ip: &str,
) {
    if buf.len() < 12 {
        return;
    }
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let mut offset = 12;
    let mut should_respond = false;
    let query_id = u16::from_be_bytes([buf[0], buf[1]]);

    for _ in 0..qd_count {
        if offset >= buf.len() {
            break;
        }
        if let Ok((qname, consumed)) = parse_dns_name(buf, offset) {
            offset += consumed + 4;
            let q_lower = qname.to_ascii_lowercase();
            if q_lower.contains("_dacp._tcp") || q_lower.contains("itunes_ctrl") {
                should_respond = true;
                break;
            }
        } else {
            break;
        }
    }

    if should_respond {
        let resp = build_dacp_mdns_response(query_id, dacp_id, port, hostname, local_ip);
        let _ = socket.send_to(&resp, peer).await;
        let _ = socket.send_to(&resp, "224.0.0.251:5353").await;
    }
}

/// DACP mDNS Advertiser advertising `iTunes_Ctrl_<dacp_id>._dacp._tcp.local.` on port `3689`.
///
/// Uses `avahi-publish-service` (if installed) AND a pure-Rust UDP multicast mDNS responder
/// on `224.0.0.251:5353` that answers queries for `_dacp._tcp.local.` and
/// `iTunes_Ctrl_<dacp_id>._dacp._tcp.local.` with TXT records (`txtvers=1`, `Ver=131075`,
/// `DbId=<dacp_id>`, `OSsi=0x1F5`).
pub struct MdnsDacpAdvertiser {
    dacp_id: String,
    port: u16,
    hostname: String,
    local_ip: String,
    avahi_child: Option<tokio::process::Child>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MdnsDacpAdvertiser {
    /// Create a new advertiser definition.
    pub fn new(dacp_id: &str, port: u16) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "homelab".to_string())
            .replace(".local", "");
        Self {
            dacp_id: dacp_id.to_string(),
            port,
            hostname,
            local_ip: "127.0.0.1".to_string(),
            avahi_child: None,
            shutdown_tx: None,
        }
    }

    /// Spawn advertiser services (both avahi-publish-service and pure-Rust UDP multicast responder).
    pub async fn spawn(dacp_id: &str, port: u16, target_ip: &str) -> Result<Self, SonusError> {
        let mut adv = Self::new(dacp_id, port);
        adv.start(target_ip).await?;
        Ok(adv)
    }

    /// Start advertising on the network.
    pub async fn start(&mut self, target_ip: &str) -> Result<(), SonusError> {
        self.local_ip = get_local_ip_for_target(target_ip);
        let service_name = format!("iTunes_Ctrl_{}", self.dacp_id);

        // 1. avahi-publish-service if installed
        let child = tokio::process::Command::new("avahi-publish-service")
            .arg("-s")
            .arg(&service_name)
            .arg("_dacp._tcp")
            .arg(self.port.to_string())
            .args([
                "txtvers=1",
                "Ver=131075",
                &format!("DbId={}", self.dacp_id),
                "OSsi=0x1F5",
            ])
            .kill_on_drop(true)
            .spawn()
            .ok();

        if child.is_some() {
            info!(
                "Spawned avahi-publish-service for DACP service '{}'",
                service_name
            );
        }
        self.avahi_child = child;

        // 2. Pure-Rust UDP multicast responder on 224.0.0.251:5353
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);

        let dacp_id = self.dacp_id.clone();
        let port = self.port;
        let hostname = self.hostname.clone();
        let local_ip = self.local_ip.clone();

        tokio::spawn(async move {
            let socket_res = create_and_bind_mdns_responder_socket();
            match socket_res {
                Ok(socket) => {
                    info!("Pure-Rust mDNS responder active on 224.0.0.251:5353 for DACP");
                    let mut buf = [0u8; 2048];
                    loop {
                        tokio::select! {
                            _ = &mut rx => {
                                debug!("mDNS responder shutdown signal received");
                                break;
                            }
                            recv_res = socket.recv_from(&mut buf) => {
                                match recv_res {
                                    Ok((n, peer)) => {
                                        handle_mdns_query(
                                            &socket,
                                            &buf[..n],
                                            peer,
                                            &dacp_id,
                                            port,
                                            &hostname,
                                            &local_ip,
                                        ).await;
                                    }
                                    Err(e) => {
                                        debug!("mDNS responder recv error: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Could not bind pure-Rust mDNS responder socket on port 5353: {} (avahi daemon managing mDNS)",
                        e
                    );
                }
            }
        });

        Ok(())
    }

    /// Stop advertisement processes and responders.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.avahi_child.take() {
            let _ = child.start_kill();
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for MdnsDacpAdvertiser {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run environmental diagnostics checking PipeWire, virtual sink, audio recorders,
/// D-Bus MPRIS2 session bus, DACP port availability, and target HomePod reachability.
pub async fn run_environment_doctor(conf: &SonusConfig) -> Vec<DoctorCheck> {
    let mut checks = Vec::with_capacity(6);

    // 1. PipeWire daemon running (`pactl info`)
    let pw_check = match tokio::process::Command::new("pactl")
        .arg("info")
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let server_name = stdout
                .lines()
                .find(|l| l.starts_with("Server Name:"))
                .map(|l| l.trim().to_string())
                .unwrap_or_else(|| "Server running".to_string());
            DoctorCheck {
                name: "PipeWire Daemon".to_string(),
                passed: true,
                detail: server_name,
            }
        }
        Ok(out) => DoctorCheck {
            name: "PipeWire Daemon".to_string(),
            passed: false,
            detail: format!("pactl info exited with code {:?}", out.status.code()),
        },
        Err(e) => DoctorCheck {
            name: "PipeWire Daemon".to_string(),
            passed: false,
            detail: format!("Failed to execute pactl: {e}"),
        },
    };
    checks.push(pw_check);

    // 2. Virtual sink `conf.sink_name` present in PipeWire and check Latency
    let sink_check = match tokio::process::Command::new("pactl")
        .args(["list", "sinks", "short"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let found = stdout.lines().any(|l| {
                l.split_whitespace().nth(1) == Some(&conf.sink_name) || l.contains(&conf.sink_name)
            });

            if found {
                let detail_out = tokio::process::Command::new("pactl")
                    .args(["list", "sinks"])
                    .output()
                    .await
                    .ok();
                let latency_info = if let Some(d) = detail_out {
                    let d_str = String::from_utf8_lossy(&d.stdout);
                    d_str
                        .lines()
                        .find(|l| l.trim().starts_with("Latency:"))
                        .map(|l| l.trim().to_string())
                        .unwrap_or_else(|| "configured latency ~250000 usec".to_string())
                } else {
                    "configured latency ~250000 usec".to_string()
                };
                DoctorCheck {
                    name: format!("PipeWire Virtual Sink '{}'", conf.sink_name),
                    passed: true,
                    detail: format!("Sink '{}' active ({})", conf.sink_name, latency_info),
                }
            } else {
                DoctorCheck {
                    name: format!("PipeWire Virtual Sink '{}'", conf.sink_name),
                    passed: false,
                    detail: format!(
                        "Sink '{}' not found in PipeWire (run scripts/pipewire-sink.sh)",
                        conf.sink_name
                    ),
                }
            }
        }
        Ok(out) => DoctorCheck {
            name: format!("PipeWire Virtual Sink '{}'", conf.sink_name),
            passed: false,
            detail: format!(
                "pactl list sinks short failed: code {:?}",
                out.status.code()
            ),
        },
        Err(e) => DoctorCheck {
            name: format!("PipeWire Virtual Sink '{}'", conf.sink_name),
            passed: false,
            detail: format!("Failed to list sinks: {e}"),
        },
    };
    checks.push(sink_check);

    // 3. parec or pw-record binary available in PATH
    let recorder_check = {
        let parec_ok = tokio::process::Command::new("which")
            .arg("parec")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        let pw_record_ok = tokio::process::Command::new("which")
            .arg("pw-record")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if parec_ok || pw_record_ok {
            let which_bin = if parec_ok { "parec" } else { "pw-record" };
            DoctorCheck {
                name: "Audio Recorder Utility".to_string(),
                passed: true,
                detail: format!("Found '{which_bin}' recorder in PATH"),
            }
        } else {
            DoctorCheck {
                name: "Audio Recorder Utility".to_string(),
                passed: false,
                detail: "Neither 'parec' nor 'pw-record' found in PATH".to_string(),
            }
        }
    };
    checks.push(recorder_check);

    // 4. D-Bus session bus & active MPRIS2 media players (`dbus-send`)
    let dbus_check = match tokio::process::Command::new("dbus-send")
        .args([
            "--session",
            "--dest=org.freedesktop.DBus",
            "--type=method_call",
            "--print-reply",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ListNames",
        ])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mpris_players: Vec<&str> = stdout
                .lines()
                .filter_map(|l| {
                    let trimmed = l.trim();
                    if trimmed.starts_with("string \"org.mpris.MediaPlayer2.") {
                        trimmed.strip_prefix("string \"")?.strip_suffix('\"')
                    } else {
                        None
                    }
                })
                .collect();
            if !mpris_players.is_empty() {
                DoctorCheck {
                    name: "D-Bus MPRIS2 Media Players".to_string(),
                    passed: true,
                    detail: format!("Session bus active. Players: {}", mpris_players.join(", ")),
                }
            } else {
                DoctorCheck {
                    name: "D-Bus MPRIS2 Media Players".to_string(),
                    passed: true,
                    detail: "Session bus active. 0 active MPRIS2 media players found".to_string(),
                }
            }
        }
        Ok(out) => DoctorCheck {
            name: "D-Bus MPRIS2 Media Players".to_string(),
            passed: false,
            detail: format!("dbus-send exited with code {:?}", out.status.code()),
        },
        Err(e) => DoctorCheck {
            name: "D-Bus MPRIS2 Media Players".to_string(),
            passed: false,
            detail: format!("Failed to connect to D-Bus session bus: {e}"),
        },
    };
    checks.push(dbus_check);

    // 5. DACP port conf.dacp_port (3689) availability or active listener
    let dacp_port_check = {
        let addr = format!("0.0.0.0:{}", conf.dacp_port);
        match std::net::TcpListener::bind(&addr) {
            Ok(listener) => {
                drop(listener);
                DoctorCheck {
                    name: format!("DACP Service Port {}", conf.dacp_port),
                    passed: true,
                    detail: format!("Port {} is free and available", conf.dacp_port),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let loopback = format!("127.0.0.1:{}", conf.dacp_port);
                if std::net::TcpStream::connect(&loopback).is_ok() {
                    DoctorCheck {
                        name: format!("DACP Service Port {}", conf.dacp_port),
                        passed: true,
                        detail: format!(
                            "Active DACP touch server listening on port {}",
                            conf.dacp_port
                        ),
                    }
                } else {
                    DoctorCheck {
                        name: format!("DACP Service Port {}", conf.dacp_port),
                        passed: false,
                        detail: format!("Port {} cannot be bound: {}", conf.dacp_port, e),
                    }
                }
            }
            Err(e) => DoctorCheck {
                name: format!("DACP Service Port {}", conf.dacp_port),
                passed: false,
                detail: format!("Port {} cannot be bound: {}", conf.dacp_port, e),
            },
        }
    };
    checks.push(dacp_port_check);

    // 6. Target HomePod TCP reachability (conf.homepod_ip:conf.homepod_port)
    let target_reachability = {
        let target = format!("{}:{}", conf.homepod_ip, conf.homepod_port);
        match tokio::time::timeout(
            Duration::from_millis(1500),
            tokio::net::TcpStream::connect(&target),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                DoctorCheck {
                    name: format!("HomePod Reachability ({target})"),
                    passed: true,
                    detail: format!("Successfully reached HomePod endpoint at {target}"),
                }
            }
            Ok(Err(e)) => DoctorCheck {
                name: format!("HomePod Reachability ({target})"),
                passed: false,
                detail: format!("Connection failed to {target}: {e}"),
            },
            Err(_) => DoctorCheck {
                name: format!("HomePod Reachability ({target})"),
                passed: false,
                detail: format!("Connection timed out after 1500ms to {target}"),
            },
        }
    };
    checks.push(target_reachability);

    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_name_encoding_and_parsing() {
        let name = "_airplay._tcp.local";
        let encoded = encode_dns_name(name);
        assert_eq!(encoded[0], 8);
        assert_eq!(&encoded[1..9], b"_airplay");
        assert_eq!(encoded[9], 4);
        assert_eq!(&encoded[10..14], b"_tcp");
        assert_eq!(encoded[14], 5);
        assert_eq!(&encoded[15..20], b"local");
        assert_eq!(encoded[20], 0);

        let (parsed, consumed) = parse_dns_name(&encoded, 0).unwrap();
        assert_eq!(parsed, name);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_dns_pointer_compression() {
        let mut buf = Vec::new();
        // Domain at offset 0: "_tcp.local" -> [4, b'_tcp', 5, b'local', 0]
        buf.extend_from_slice(&encode_dns_name("_tcp.local"));
        let base_len = buf.len(); // 11 bytes

        // Second name at base_len: "_airplay" followed by pointer to offset 0 (0xC0, 0x00)
        let second_offset = base_len;
        buf.push(8);
        buf.extend_from_slice(b"_airplay");
        buf.push(0xC0);
        buf.push(0x00);

        let (parsed, consumed) = parse_dns_name(&buf, second_offset).unwrap();
        assert_eq!(parsed, "_airplay._tcp.local");
        assert_eq!(consumed, 1 + 8 + 2); // 11 bytes consumed from second_offset
    }

    #[test]
    fn test_build_mdns_query() {
        let query = build_mdns_query("_airplay._tcp.local");
        assert_eq!(&query[0..2], &0u16.to_be_bytes()); // ID: 0
        assert_eq!(&query[2..4], &0u16.to_be_bytes()); // Flags: 0
        assert_eq!(&query[4..6], &1u16.to_be_bytes()); // QDCOUNT: 1
        assert_eq!(&query[6..8], &0u16.to_be_bytes()); // ANCOUNT: 0

        // Parse question name
        let (qname, consumed) = parse_dns_name(&query, 12).unwrap();
        assert_eq!(qname, "_airplay._tcp.local");
        let qtype = u16::from_be_bytes([query[12 + consumed], query[12 + consumed + 1]]);
        let qclass = u16::from_be_bytes([query[12 + consumed + 2], query[12 + consumed + 3]]);
        assert_eq!(qtype, TYPE_PTR);
        assert_eq!(qclass, 0x8001); // IN + QU unicast response bit
    }

    #[test]
    fn test_build_and_parse_dacp_mdns_response() {
        let resp = build_dacp_mdns_response(42, "484F4D454C414231", 3689, "homelab", "192.0.2.10");
        assert_eq!(&resp[0..2], &42u16.to_be_bytes()); // ID
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8400, 0x8400); // QR=1, AA=1

        let records = parse_mdns_packet(&resp).expect("Failed to parse DACP mDNS response");
        assert_eq!(records.len(), 4); // PTR, SRV, TXT, A

        // 1. PTR record
        assert_eq!(records[0].rtype, TYPE_PTR);
        let (ptr_target, _) = parse_dns_name(&resp, records[0].rdata_offset).unwrap();
        assert_eq!(ptr_target, "iTunes_Ctrl_484F4D454C414231._dacp._tcp.local");

        // 2. SRV record
        assert_eq!(records[1].rtype, TYPE_SRV);
        let srv_port = u16::from_be_bytes([
            resp[records[1].rdata_offset + 4],
            resp[records[1].rdata_offset + 5],
        ]);
        assert_eq!(srv_port, 3689);
        let (srv_target, _) = parse_dns_name(&resp, records[1].rdata_offset + 6).unwrap();
        assert_eq!(srv_target, "homelab.local");

        // 3. TXT record
        assert_eq!(records[2].rtype, TYPE_TXT);

        // 4. A record
        assert_eq!(records[3].rtype, TYPE_A);
        let o = records[3].rdata_offset;
        let ip = format!(
            "{}.{}.{}.{}",
            resp[o],
            resp[o + 1],
            resp[o + 2],
            resp[o + 3]
        );
        assert_eq!(ip, "192.0.2.10");
    }

    #[test]
    fn test_unescape_avahi_str() {
        assert_eq!(unescape_avahi_str("Office"), "Office");
        assert_eq!(unescape_avahi_str(r"MacBook\032Pro"), "MacBook Pro");
        assert_eq!(unescape_avahi_str(r"Living\032Room"), "Living Room");
        assert_eq!(unescape_avahi_str(r"Test\059Semi"), "Test;Semi");
    }

    #[test]
    fn test_parse_avahi_browse_output() {
        let sample = "\
+;eth0;IPv4;Office;_airplay._tcp;local\n\
=;eth0;IPv4;Office;_airplay._tcp;local;Office.local;192.0.2.100;7000;\"deviceid=AA:BB:CC:11:22:33\" \"features=0x4A7FCA00,0x3C356BD0\" \"model=AudioAccessory5,1\" \"osvers=27.2\"\n\
=;eth0;IPv4;MacBook\\032Pro;_airplay._tcp;local;MacBook-Pro.local;192.0.2.36;7000;\"deviceid=AA:BB:CC:44:55:66\" \"features=0x4A7FCFD5,0x38174FDE\" \"model=MacBookPro18,3\" \"srcvers=980.77.5\"\n";

        let devices = parse_avahi_browse_output(sample);
        assert_eq!(devices.len(), 2);

        let d0 = &devices[0];
        assert_eq!(d0.name, "Office");
        assert_eq!(d0.ip, "192.0.2.100");
        assert_eq!(d0.port, 7000);
        assert_eq!(d0.model, "AudioAccessory5,1");
        assert_eq!(d0.device_id, "AA:BB:CC:11:22:33");
        assert_eq!(d0.features, "0x4A7FCA00,0x3C356BD0");
        assert_eq!(d0.os_version, "27.2");

        let d1 = &devices[1];
        assert_eq!(d1.name, "MacBook Pro");
        assert_eq!(d1.ip, "192.0.2.36");
        assert_eq!(d1.port, 7000);
        assert_eq!(d1.model, "MacBookPro18,3");
        assert_eq!(d1.os_version, "980.77.5");
    }

    #[test]
    fn test_deduplicate_devices() {
        let dev1 = DiscoveredDevice {
            name: "Office".to_string(),
            ip: "192.0.2.100".to_string(),
            port: 7000,
            model: "HomePod".to_string(),
            device_id: "".to_string(),
            features: "".to_string(),
            os_version: "".to_string(),
        };

        let dev2 = DiscoveredDevice {
            name: "Office".to_string(),
            ip: "192.0.2.100".to_string(),
            port: 7000,
            model: "AudioAccessory5,1".to_string(),
            device_id: "AA:BB:CC:11:22:33".to_string(),
            features: "0x4A7FCA00,0x3C356BD0".to_string(),
            os_version: "27.2".to_string(),
        };

        let deduped = deduplicate_devices(vec![dev1, dev2]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].model, "AudioAccessory5,1");
        assert_eq!(deduped[0].device_id, "AA:BB:CC:11:22:33");
        assert_eq!(deduped[0].features, "0x4A7FCA00,0x3C356BD0");
        assert_eq!(deduped[0].os_version, "27.2");
    }

    #[test]
    fn test_get_local_ip_for_target() {
        let ip = get_local_ip_for_target("127.0.0.1");
        assert!(!ip.is_empty());
        assert!(ip.contains('.'));
    }
}
