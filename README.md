# vpnyellod — turn any Linux box into a YellowD VPN server

One static binary (x86_64 + arm64), one codebase. It auto-detects your global
IPv4/IPv6 (picks the best when there are several, works IPv4-only, IPv6-only,
or both), sets up WireGuard, and registers on
**https://vpn.yellod.dpdns.org** — no account needed. Users pick your server on
the site and download a `.conf`; your box pulls their keys automatically.

## Install (any: debian · fedora · arch · gentoo + derivatives)

```bash
curl -fsSL https://raw.githubusercontent.com/xyzyt010/vpnyellod/main/install.sh | sudo bash
```

The script installs `wireguard-tools`, `iproute2`, `curl`, downloads the right
CPU binary, and installs the systemd unit (not started until you say `on`).

## Use

```bash
sudo vpnyellod on                 # set up + register + start daemon
sudo vpnyellod on --name my-box   # custom display name
vpnyellod status                  # tunnel, IPs, peers, last sync
sudo vpnyellod off                # deregister + stop (keeps files, re-on anytime)
sudo vpnyellod uninstall          # remove EVERYTHING: entry, daemon, rules, configs, keys
```

`on` is idempotent — re-running refreshes IPs/registration (same server entry,
clients keep working). Keys in `/etc/wireguard/server_private.key` are reused,
never rotated. Settings via env or `/etc/vpnyellod/config.env`:
`VY_REGISTRY, VY_IFACE, VY_PORT, VY_VPN4, VY_VPN6, VY_NAME, VY_POLL`.

## How it works

- Detects globals from `ip addr` (skips private/CGNAT/link-local/ULA/VPN nets);
  prefers the default-route source, but never a rotating temporary IPv6 when a
  stable one exists; random among true ties.
- Writes `/etc/wireguard/<iface>.conf` (existing `[Peer]`s preserved), enables
  forwarding + NAT, `wg-quick up`.
- `POST /api/servers/register` → heartbeat every ~30 s →
  `GET`-style peer list in heartbeat response → `wg set` + persist to conf.
  Stale peers (revoked/expired on the site) are removed automatically.
- `off` tells the site it went away; the site also marks servers offline after
  ~90 s without heartbeat.

## Dev

```bash
cargo build --release
sudo ./target/release/vpnyellod on --registry http://localhost:8080
```

Releases: tag `vX.Y.Z` → Actions cross-builds x86_64 + aarch64 tarballs.

License: MIT.
