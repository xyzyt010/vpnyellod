//! vpnyellod — YellowD VPN server agent.
//!
//!   sudo vpnyellod on    detect global IP, set up WireGuard, register on the
//!                        website, start background daemon (peer sync)
//!   sudo vpnyellod off   deregister from website, stop daemon, bring wg down
//!   vpnyellod status     local tunnel + registration state
//!   sudo vpnyellod daemon  (run by systemd; heartbeat + apply client peers)
//!
//! Std-only. Registry HTTPS calls go through `curl` (installed by install.sh).
//! Env overrides (also accepted in /etc/vpnyellod/config.env):
//!   VY_REGISTRY  default https://vpn.yellod.dpdns.org
//!   VY_IFACE     default wg0        VY_PORT default 51820
//!   VY_VPN4      default 10.8.0.1/24   VY_VPN6 default fd86:ea04::1/64
//!   VY_NAME      server display name (default: hostname)
//!   VY_POLL      heartbeat seconds (default 30, server may suggest other)

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_REGISTRY: &str = "https://vpn.yellod.dpdns.org";
const CONF_DIR: &str = "/etc/vpnyellod";
const STATE_FILE: &str = "/etc/vpnyellod/state.env";
const LAST_FILE: &str = "/var/lib/vpnyellod/last.json";
const PID_FILE: &str = "/run/vpnyellod.pid";

#[derive(Debug, Clone)]
struct Cfg {
    registry: String,
    iface: String,
    port: u16,
    vpn4: String,
    vpn6: String,
    name: String,
    poll: u64,
    conf_path: String,
    key_path: String,
}

fn cfg_get(key: &str) -> String {
    if let Ok(v) = std::env::var(key) {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    if let Ok(c) = fs::read_to_string(format!("{CONF_DIR}/config.env")) {
        for line in c.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    let v = v.trim().trim_matches('"').to_string();
                    if !v.is_empty() {
                        return v;
                    }
                }
            }
        }
    }
    String::new()
}

fn hostname() -> String {
    let h = Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "server".into());
    let clean: String = h.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let clean = clean.trim_matches('-').to_string();
    let short = clean.split('.').next().unwrap_or("server").to_string();
    short.chars().take(32).collect::<String>()
}

impl Cfg {
    fn load() -> Cfg {
        let iface = non_empty(cfg_get("VY_IFACE"), "wg0");
        let poll: u64 = cfg_get("VY_POLL").parse().unwrap_or(30);
        Cfg {
            registry: non_empty(cfg_get("VY_REGISTRY"), DEFAULT_REGISTRY).trim_end_matches('/').to_string(),
            port: cfg_get("VY_PORT").parse().unwrap_or(51820),
            vpn4: non_empty(cfg_get("VY_VPN4"), "10.8.0.1/24"),
            vpn6: non_empty(cfg_get("VY_VPN6"), "fd86:ea04::1/64"),
            name: non_empty(cfg_get("VY_NAME"), &hostname()),
            poll: poll.clamp(5, 600),
            conf_path: format!("/etc/wireguard/{iface}.conf"),
            key_path: non_empty(cfg_get("VY_KEY"), "/etc/wireguard/server_private.key"),
            iface,
        }
    }
}

fn non_empty(v: String, def: &str) -> String {
    if v.trim().is_empty() { def.to_string() } else { v }
}

fn is_root() -> bool {
    Command::new("id").arg("-u").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

fn run_out(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

// ============================ IP detection ============================

#[derive(Debug, Clone)]
struct Addr {
    ip: String,
    stable: bool,
    deprecated: bool,
    preferred_lft: u64,
}

fn preferred_lft(line: &str) -> u64 {
    let mut it = line.split_whitespace();
    while let Some(t) = it.next() {
        if t == "preferred_lft" {
            return match it.next().unwrap_or("") {
                "forever" => u64::MAX,
                s => s.trim_end_matches("sec").parse().unwrap_or(0),
            };
        }
    }
    0
}

fn v4_global(ip: &str) -> bool {
    let o: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 || o.iter().any(|&x| x > 255) {
        return false;
    }
    let (a, b) = (o[0], o[1]);
    if a == 10 || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168) { return false; }
    if a == 127 || (a == 169 && b == 254) || (a == 100 && (64..128).contains(&b)) { return false; }
    if a == 0 || a >= 224 { return false; }
    true
}

fn v6_global(ip: &str) -> bool {
    let ip = ip.split('%').next().unwrap_or("").to_lowercase();
    if ip == "::1" || ip.is_empty() {
        return false;
    }
    let head = ip.split(':').next().unwrap_or("");
    if head.is_empty() {
        return false;
    }
    match head.chars().next() {
        Some('2') | Some('3') => {}
        _ => return false, // link-local, ULA (incl. VPN nets), multicast...
    }
    if ip.starts_with("2001:db8") {
        return false;
    }
    true
}

fn list_addrs(family: &str) -> Vec<Addr> {
    let flag = if family == "inet" { "-4" } else { "-6" };
    let out = match run_out("ip", &[flag, "-o", "addr", "show"]) {
        Some(s) => s,
        None => return vec![],
    };
    let mut v = vec![];
    for line in out.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 4 || t[2] != family || !line.contains("scope global") {
            continue;
        }
        let ip = t[3].split('/').next().unwrap_or("").to_string();
        if !(if family == "inet" { v4_global(&ip) } else { v6_global(&ip) }) {
            continue;
        }
        v.push(Addr {
            ip,
            stable: !line.contains(" temporary"),
            deprecated: line.contains(" deprecated"),
            preferred_lft: preferred_lft(line),
        });
    }
    v
}

fn default_src(v6: bool) -> Option<String> {
    let args: &[&str] = if v6 { &["-6", "route", "get", "2001:4860:4860::8888"] } else { &["route", "get", "8.8.8.8"] };
    let out = run_out("ip", args)?;
    let mut it = out.split_whitespace();
    while let Some(t) = it.next() {
        if t == "src" {
            return it.next().map(|s| s.to_string());
        }
    }
    None
}

fn nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1)
}

fn select_best(cands: &[Addr], def: &Option<String>) -> Option<String> {
    if cands.is_empty() {
        return None;
    }
    // Most important = default-route source, but never a rotating temporary
    // IPv6 when a stable global exists (temp expires within the hour).
    if let Some(src) = def {
        if let Some(a) = cands.iter().find(|a| &a.ip == src && !a.deprecated && a.stable) {
            return Some(a.ip.clone());
        }
    }
    let mut bs = i64::MIN;
    let mut bl = 0u64;
    for a in cands {
        let mut s = 0i64;
        if a.deprecated { s -= 1000; }
        if !a.stable { s -= 100; }
        if s > bs || (s == bs && a.preferred_lft > bl) { bs = s; bl = a.preferred_lft; }
    }
    let tied: Vec<&Addr> = cands.iter().filter(|a| {
        let mut s = 0i64;
        if a.deprecated { s -= 1000; }
        if !a.stable { s -= 100; }
        s == bs && a.preferred_lft == bl
    }).collect();
    Some(tied[(nanos() % tied.len() as u64) as usize].ip.clone())
}

fn detect() -> (Option<String>, Option<String>) {
    let v4 = select_best(&list_addrs("inet"), &default_src(false));
    let v6 = select_best(&list_addrs("inet6"), &default_src(true));
    (v4, v6)
}

fn default_iface() -> Option<String> {
    for args in [&["route", "get", "8.8.8.8"][..], &["-6", "route", "get", "2001:4860:4860::8888"][..]] {
        if let Some(out) = run_out("ip", args) {
            let mut it = out.split_whitespace();
            while let Some(t) = it.next() {
                if t == "dev" {
                    if let Some(d) = it.next() {
                        if !d.is_empty() {
                            return Some(d.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

// ============================ WireGuard setup ============================

fn ensure_keys(key_path: &str) -> Result<String, String> {
    if let Ok(k) = fs::read_to_string(key_path) {
        let k = k.trim().to_string();
        if !k.is_empty() {
            return Ok(k);
        }
    }
    let key = run_out("wg", &["genkey"]).ok_or("wg genkey failed — install wireguard-tools first")?;
    if let Some(p) = std::path::Path::new(key_path).parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .open(key_path).and_then(|mut f| f.write_all(key.as_bytes()))
        .map_err(|e| format!("write {key_path}: {e}"))?;
    Ok(key)
}

fn pubkey_of(privkey: &str) -> Result<String, String> {
    let mut c = Command::new("wg");
    c.args(["pubkey"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = c.spawn().map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("stdin")?.write_all(privkey.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("wg pubkey failed".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn v4net(vpn4: &str) -> String {
    let (ip, prefix) = vpn4.split_once('/').unwrap_or((vpn4, "24"));
    let o: Vec<u32> = ip.split('.').filter_map(|x| x.parse().ok()).collect();
    if o.len() == 4 {
        let p: u32 = prefix.parse().unwrap_or(24).min(32);
        let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
        let addr = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
        let net = addr & mask;
        return format!("{}.{}.{}.{}/{}", (net >> 24) & 255, (net >> 16) & 255, (net >> 8) & 255, net & 255, p);
    }
    vpn4.to_string()
}

fn write_conf(cfg: &Cfg, privkey: &str) -> Result<(), String> {
    let wan = default_iface().unwrap_or_else(|| "eth0".into());
    let net4 = v4net(&cfg.vpn4);
    let net6 = if cfg.vpn6.contains("/64") {
        let base = cfg.vpn6.split("::").next().unwrap_or("fd86:ea04");
        let h: Vec<&str> = base.split(':').collect();
        format!("{}::/64", h.iter().take(4).cloned().collect::<Vec<_>>().join(":"))
    } else {
        cfg.vpn6.clone()
    };
    let header = format!(
        "# Generated by vpnyellod — peers below are managed (do not hand-edit header).\n\
         [Interface]\n\
         Address = {a4}, {a6}\n\
         ListenPort = {port}\n\
         PrivateKey = {key}\n\
         PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s {n4} -o {wan} -j MASQUERADE\n\
         PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s {n4} -o {wan} -j MASQUERADE\n\
         PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -s {n6} -o {wan} -j MASQUERADE\n\
         PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -s {n6} -o {wan} -j MASQUERADE\n\n",
        a4 = cfg.vpn4, a6 = cfg.vpn6, port = cfg.port, key = privkey.trim(), n4 = net4, n6 = net6, wan = wan,
    );
    if let Some(p) = std::path::Path::new(&cfg.conf_path).parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut peers = String::new();
    if let Ok(old) = fs::read_to_string(&cfg.conf_path) {
        let mut in_peer = false;
        for line in old.lines() {
            let t = line.trim();
            if t == "[Peer]" { in_peer = true; }
            else if t == "[Interface]" { in_peer = false; }
            if in_peer { peers.push_str(line); peers.push('\n'); }
        }
    }
    fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .open(&cfg.conf_path).and_then(|mut f| { f.write_all(header.as_bytes())?; f.write_all(peers.as_bytes()) })
        .map_err(|e| format!("write {}: {e}", cfg.conf_path))?;
    Ok(())
}

fn iface_exists(cfg: &Cfg) -> bool {
    run("ip", &["link", "show", "dev", &cfg.iface])
}

fn ensure_addrs(cfg: &Cfg) {
    let _ = run("ip", &["addr", "replace", &cfg.vpn4, "dev", &cfg.iface]);
    let _ = run("ip", &["-6", "addr", "replace", &cfg.vpn6, "dev", &cfg.iface]);
}

fn bring_up(cfg: &Cfg) -> Result<(), String> {
    let _ = run("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    let _ = run("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);
    if iface_exists(cfg) {
        ensure_addrs(cfg);
    } else if !run("wg-quick", &["up", &cfg.iface]) {
        return Err(format!("wg-quick up {} failed", cfg.iface));
    }
    ensure_addrs(cfg);
    Ok(())
}

// ============================ Registry HTTP (via curl) ============================

fn curl_post(url: &str, body: &str) -> Result<String, String> {
    let mut c = Command::new("curl");
    c.args(["-fsSL", "-m", "25", "-X", "POST", url]);
    c.args(["-H", "Content-Type: application/json"]);
    c.args(["--data-binary", "@-"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("spawn curl: {e} (install curl first)"))?;
    child.stdin.take().ok_or("curl stdin")?.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("registry unreachable: {} {}", url, String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Extract first `"field":"value"` (string) after optional marker.
fn jstr(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut rest = body;
    loop {
        let i = rest.find(&needle)?;
        rest = &rest[i + needle.len()..];
        let r = rest.trim_start().strip_prefix(':')?.trim_start();
        if r.starts_with('"') {
            // no escapes expected in our values (base64/ips/hex); scan to closing quote
            let end = r[1..].find('"')?;
            return Some(r[1..1 + end].to_string());
        }
    }
}

fn jnum(body: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{field}\"");
    let i = body.find(&needle)?;
    let r = body[i + needle.len()..].trim_start().strip_prefix(':')?.trim_start();
    r.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
}

#[derive(Debug, Clone)]
struct WantedPeer {
    client_pubkey: String,
    preshared_b64: String,
    ip4: String,
    ip6: String,
}

/// Parse `"peers":[{...},{...}]` — objects with string fields only (+id number, ignored).
fn parse_peers(body: &str) -> Vec<WantedPeer> {
    let mut out = vec![];
    let start = match body.find("\"peers\"") {
        Some(i) => i,
        None => return out,
    };
    let arr = match body[start..].find('[') {
        Some(i) => &body[start + i..],
        None => return out,
    };
    // Walk top-level {...} objects inside the array.
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in arr.chars() {
        match ch {
            '[' if depth == 0 => { depth = 1; }
            '{' => { depth += 1; cur.push(ch); }
            '}' => { depth -= 1; cur.push(ch); if depth == 1 {
                let pk = jstr(&cur, "client_pubkey").unwrap_or_default();
                if !pk.is_empty() {
                    out.push(WantedPeer {
                        client_pubkey: pk,
                        preshared_b64: jstr(&cur, "preshared").unwrap_or_default(),
                        ip4: jstr(&cur, "client_ip4").unwrap_or_default(),
                        ip6: jstr(&cur, "client_ip6").unwrap_or_default(),
                    });
                }
                cur.clear();
            }}
            ']' if depth == 1 => break,
            _ => { if depth >= 1 { cur.push(ch); } }
        }
    }
    out
}

fn applied_peers(cfg: &Cfg) -> Vec<String> {
    run_out("wg", &["show", &cfg.iface, "peers"]).map(|s| s.split_whitespace().map(|x| x.to_string()).collect()).unwrap_or_default()
}

fn apply_peer(cfg: &Cfg, p: &WantedPeer) -> Result<(), String> {
    if p.ip4.is_empty() || p.ip6.is_empty() || p.preshared_b64.is_empty() {
        return Err("peer record incomplete".into());
    }
    // NOTE: `wg set ... preshared-key <file>` expects the file to contain the
    // BASE64 string (same as config files), not raw bytes.
    if p.preshared_b64.len() != 44 {
        return Err("bad preshared key".into());
    }
    let tmp = format!("/tmp/vpnyellod-{}.psk", &p.client_pubkey[..8.min(p.client_pubkey.len())]);
    fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .open(&tmp).and_then(|mut f| f.write_all(p.preshared_b64.as_bytes())).map_err(|e| e.to_string())?;
    let ok = run("wg", &["set", &cfg.iface, "peer", &p.client_pubkey, "preshared-key", &tmp,
        "allowed-ips", &format!("{}/32,{}/128", p.ip4, p.ip6)]);
    let _ = fs::remove_file(&tmp);
    if !ok {
        return Err("wg set failed".into());
    }
    // Persist in conf (idempotent).
    let conf = fs::read_to_string(&cfg.conf_path).unwrap_or_default();
    if !conf.contains(&format!("PublicKey = {}", p.client_pubkey)) {
        let block = format!("\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}/32, {}/128\n",
            p.client_pubkey, p.preshared_b64, p.ip4, p.ip6);
        fs::OpenOptions::new().append(true).open(&cfg.conf_path)
            .and_then(|mut f| f.write_all(block.as_bytes())).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn remove_peer(cfg: &Cfg, pubkey: &str) {
    let _ = run("wg", &["set", &cfg.iface, "peer", pubkey, "remove"]);
    if let Ok(conf) = fs::read_to_string(&cfg.conf_path) {
        let mut out = String::new();
        let mut skip = false;
        for line in conf.lines() {
            let t = line.trim();
            if t == "[Peer]" { skip = false; out.push_str(line); out.push('\n'); continue; }
            if t == "[Interface]" { skip = false; out.push_str(line); out.push('\n'); continue; }
            if t == format!("PublicKey = {pubkey}") { skip = true; continue; }
            if t.starts_with("PublicKey = ") { skip = false; }
            if !skip { out.push_str(line); out.push('\n'); }
        }
        // Drop the "[Peer]" header line left dangling by a removed block.
        let cleaned = out.replace("[Peer]\n\n[Peer]", "[Peer]");
        let _ = fs::write(&cfg.conf_path, cleaned);
    }
}

fn save_state(server_id: &str, secret: &str) {
    let _ = fs::create_dir_all(CONF_DIR);
    let _ = fs::write(STATE_FILE, format!("SERVER_ID={server_id}\nSECRET={secret}\n"));
}

fn load_state() -> (String, String) {
    let c = fs::read_to_string(STATE_FILE).unwrap_or_default();
    let mut id = String::new();
    let mut sec = String::new();
    for line in c.lines() {
        if let Some(v) = line.strip_prefix("SERVER_ID=") { id = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("SECRET=") { sec = v.trim().to_string(); }
    }
    (id, sec)
}

fn heartbeat(cfg: &Cfg, server_id: &str, secret: &str, v4: &Option<String>, v6: &Option<String>) -> Result<Vec<WantedPeer>, String> {
    let body = format!(
        "{{\"secret\":\"{sec}\",\"ipv4\":\"{v4}\",\"ipv6\":\"{v6}\",\"port\":{port}}}",
        sec = secret,
        v4 = v4.clone().unwrap_or_default(),
        v6 = v6.clone().unwrap_or_default(),
        port = cfg.port,
    );
    let url = format!("{}/api/servers/{server_id}/heartbeat", cfg.registry);
    let resp = curl_post(&url, &body)?;
    if let Some(p) = jnum(&resp, "poll_interval_secs") {
        if p >= 5 && p <= 600 {
            std::env::set_var("VY_POLL_EFFECTIVE", p.to_string());
        }
    }
    Ok(parse_peers(&resp))
}

fn effective_poll(cfg: &Cfg) -> u64 {
    std::env::var("VY_POLL_EFFECTIVE").ok().and_then(|v| v.parse().ok()).unwrap_or(cfg.poll)
}

fn record_heartbeat(server_id: &str, applied: usize) {
    let _ = fs::create_dir_all("/var/lib/vpnyellod");
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let _ = fs::write(LAST_FILE, format!("{{\"server_id\":\"{server_id}\",\"last_ok\":{ts},\"peers_applied\":{applied}}}"));
}

fn sync_once(cfg: &Cfg, server_id: &str, secret: &str) -> Result<usize, String> {
    let (v4, v6) = detect();
    let wanted = heartbeat(cfg, server_id, secret, &v4, &v6)?;
    if !iface_exists(cfg) {
        bring_up(cfg)?;
    }
    ensure_addrs(cfg);
    let applied = applied_peers(cfg);
    let mut n = 0;
    for p in &wanted {
        if !applied.contains(&p.client_pubkey) {
            match apply_peer(cfg, p) {
                Ok(_) => { n += 1; println!("[vpnyellod] + peer {} ({}/{})", &p.client_pubkey[..12.min(p.client_pubkey.len())], p.ip4, p.ip6); }
                Err(e) => eprintln!("[vpnyellod] apply peer failed: {e}"),
            }
        }
    }
    let want_set: Vec<&str> = wanted.iter().map(|p| p.client_pubkey.as_str()).collect();
    for a in &applied {
        if !want_set.contains(&a.as_str()) {
            println!("[vpnyellod] - stale peer {}...", &a[..12.min(a.len())]);
            remove_peer(cfg, a);
        }
    }
    let total = applied_peers(cfg).len();
    record_heartbeat(server_id, total);
    Ok(n)
}

fn has_systemd() -> bool {
    std::path::Path::new("/run/systemd/system").exists()
        && std::path::Path::new("/etc/systemd/system/vpnyellod.service").exists()
}

fn cmd_on(args: &[String]) {
    if !is_root() {
        eprintln!("error: run as root: sudo vpnyellod on");
        std::process::exit(1);
    }
    let mut cfg = Cfg::load();
    // CLI overrides: --name X --registry URL
    let mut it = args.iter().skip(1).peekable();
    while let Some(a) = it.next() {
        if a == "--name" {
            if let Some(v) = it.next() { cfg.name = v.clone(); }
        } else if a == "--registry" {
            if let Some(v) = it.next() { cfg.registry = v.trim_end_matches('/').to_string(); }
        }
    }
    for bin in ["wg", "wg-quick", "ip", "curl"] {
        if run_out("sh", &["-c", &format!("command -v {bin}")]).is_none() {
            eprintln!("error: missing `{bin}` — install it first (or use install.sh which handles debian/fedora/arch/gentoo)");
            std::process::exit(1);
        }
    }
    let (v4, v6) = detect();
    println!("[vpnyellod] detected: ipv4={} ipv6={}", v4.as_deref().unwrap_or("-"), v6.as_deref().unwrap_or("-"));
    if v4.is_none() && v6.is_none() {
        eprintln!("error: no global IPv4 or IPv6 found — connect to the internet first");
        std::process::exit(1);
    }
    let privkey = ensure_keys(&cfg.key_path).unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(1); });
    let pubkey = pubkey_of(&privkey).unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(1); });
    println!("[vpnyellod] server pubkey: {pubkey}");
    write_conf(&cfg, &privkey).unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(1); });
    bring_up(&cfg).unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(1); });
    println!("[vpnyellod] {} up on port {}", cfg.iface, cfg.port);

    // Register (open, no account). Same pubkey re-registering refreshes + new secret.
    let body = format!(
        "{{\"name\":\"{n}\",\"pubkey\":\"{pk}\",\"ipv4\":\"{v4}\",\"ipv6\":\"{v6}\",\"port\":{port},\"version\":\"vpnyellod {ver}\"}}",
        n = cfg.name, pk = pubkey,
        v4 = v4.clone().unwrap_or_default(), v6 = v6.clone().unwrap_or_default(),
        port = cfg.port, ver = VERSION,
    );
    let url = format!("{}/api/servers/register", cfg.registry);
    let resp = curl_post(&url, &body).unwrap_or_else(|e| { eprintln!("error: register failed: {e}"); std::process::exit(1); });
    let sid = jstr(&resp, "server_id").unwrap_or_else(|| { eprintln!("error: bad register response: {resp}"); std::process::exit(1); });
    let sec = jstr(&resp, "secret").unwrap_or_default();
    save_state(&sid, &sec);
    println!("[vpnyellod] registered as \"{}\" → {}/ (id {sid})", cfg.name, cfg.registry);

    // Daemon: systemd if available, else detached background loop.
    if has_systemd() {
        let _ = run("systemctl", &["daemon-reload"]);
        if !run("systemctl", &["enable", "--now", "vpnyellod.service"]) {
            eprintln!("warn: could not start systemd unit — run `sudo vpnyellod daemon &` manually");
        } else {
            println!("[vpnyellod] daemon started (systemctl status vpnyellod)");
        }
    } else {
        let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or("/usr/local/bin/vpnyellod".into());
        let _ = run("sh", &["-c", &format!("setsid nohup {exe} daemon >/var/log/vpnyellod.log 2>&1 < /dev/null & echo $! > {PID_FILE}")]);
        println!("[vpnyellod] daemon started in background (no systemd; log /var/log/vpnyellod.log)");
    }
    println!("[vpnyellod] ON — clients can now fetch a .conf for \"{}\" from the website", cfg.name);
}

fn cmd_off() {
    if !is_root() {
        eprintln!("error: run as root: sudo vpnyellod off");
        std::process::exit(1);
    }
    let cfg = Cfg::load();
    let (sid, sec) = load_state();
    if !sid.is_empty() && !sec.is_empty() {
        let url = format!("{}/api/servers/{sid}/offline", cfg.registry);
        match curl_post(&url, &format!("{{\"secret\":\"{sec}\"}}")) {
            Ok(_) => println!("[vpnyellod] deregistered from website"),
            Err(e) => eprintln!("[vpnyellod] deregister skipped ({e})"),
        }
    }
    if has_systemd() {
        let _ = run("systemctl", &["disable", "--now", "vpnyellod.service"]);
    }
    if let Ok(pid) = fs::read_to_string(PID_FILE) {
        let _ = run("kill", &[pid.trim()]);
        let _ = fs::remove_file(PID_FILE);
    }
    let _ = run("pkill", &["-f", "vpnyellod daemon"]);
    if iface_exists(&cfg) {
        let _ = run("wg-quick", &["down", &cfg.iface]);
        println!("[vpnyellod] {} down", cfg.iface);
    }
    println!("[vpnyellod] OFF");
}

fn cmd_status() {
    let cfg = Cfg::load();
    let (v4, v6) = detect();
    println!("vpnyellod {VERSION}");
    println!("registry : {}", cfg.registry);
    println!("detected : ipv4={} ipv6={}", v4.as_deref().unwrap_or("-"), v6.as_deref().unwrap_or("-"));
    println!("tunnel   : {} (port {}) {}", cfg.iface, cfg.port, if iface_exists(&cfg) { "UP" } else { "DOWN" });
    if iface_exists(&cfg) {
        if let Some(peers) = run_out("wg", &["show", &cfg.iface, "peers"]) {
            let n = if peers.is_empty() { 0 } else { peers.split_whitespace().count() };
            println!("peers    : {n} client(s)");
        }
    }
    let (sid, _) = load_state();
    if !sid.is_empty() {
        println!("server_id: {sid}");
        if let Ok(l) = fs::read_to_string(LAST_FILE) {
            println!("last sync: {l}");
        }
    } else {
        println!("state    : not registered (run `sudo vpnyellod on`)");
    }
    if has_systemd() {
        let active = run_out("systemctl", &["is-active", "vpnyellod.service"]).unwrap_or_default();
        println!("daemon   : systemd {active}");
    } else if fs::read_to_string(PID_FILE).is_ok() {
        println!("daemon   : background pidfile present");
    } else {
        println!("daemon   : not running");
    }
}

fn cmd_daemon() {
    if !is_root() {
        eprintln!("error: daemon needs root");
        std::process::exit(1);
    }
    let cfg = Cfg::load();
    let (sid, sec) = load_state();
    if sid.is_empty() || sec.is_empty() {
        eprintln!("error: not registered — run `sudo vpnyellod on` first");
        std::process::exit(1);
    }
    println!("[vpnyellod] daemon: syncing {sid} every ~{}s", cfg.poll);
    loop {
        match sync_once(&cfg, &sid, &sec) {
            Ok(n) => if n > 0 { println!("[vpnyellod] applied {n} new peer(s)"); },
            Err(e) => eprintln!("[vpnyellod] sync failed: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(effective_poll(&cfg)));
    }
}

fn usage() -> ! {
    eprintln!("vpnyellod {VERSION} — YellowD VPN server agent");
    eprintln!("  sudo vpnyellod on [--name NAME] [--registry URL]");
    eprintln!("  sudo vpnyellod off");
    eprintln!("  vpnyellod status");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()).unwrap_or("") {
        "on" => cmd_on(&args[1..].to_vec()),
        "off" => cmd_off(),
        "status" => cmd_status(),
        "daemon" => cmd_daemon(),
        "version" | "--version" => println!("vpnyellod {VERSION}"),
        _ => usage(),
    }
}
