#!/usr/bin/env bash
# vpnyellod installer — one command, any distro, any CPU.
# Installs WireGuard + friends (debian/fedora/arch/gentoo), drops the agent,
# and leaves it ready:  sudo vpnyellod on
#
#   curl -fsSL https://raw.githubusercontent.com/xyzyt010/vpnyellod/main/install.sh | sudo bash
#   sudo ./install.sh --local        # build from source with cargo (dev)
set -euo pipefail

REPO="${VPNYELLOD_REPO:-xyzyt010/vpnyellod}"
LOCAL_BUILD=0
BIN="/usr/local/bin/vpnyellod"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --local) LOCAL_BUILD=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)" >&2; exit 1; fi
# shellcheck disable=SC1091
. /etc/os-release
echo "[install] distro: ${ID} (like: ${ID_LIKE:-n/a})"

install_pkgs() {
  case "${ID} ${ID_LIKE:-}" in
    *debian*|*ubuntu*|*linuxmint*|*pop*)
      apt-get update -y && apt-get install -y wireguard-tools iproute2 curl ca-certificates;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*)
      dnf install -y wireguard-tools iproute curl ca-certificates;;
    *arch*|*manjaro*|*endeavouros*)
      pacman -Sy --noconfirm wireguard-tools iproute2 curl ca-certificates;;
    *gentoo*)
      emerge -q net-vpn/wireguard-tools sys-apps/iproute2 net-misc/curl app-misc/ca-certificates;;
    *)
      echo "[install] unsupported distro '${ID}' — install wireguard-tools, iproute2, curl manually, then re-run" >&2; exit 1;;
  esac
}
need() { command -v "$1" >/dev/null 2>&1 || { echo "[install] installing $1..."; install_pkgs; }; }
need wg; need ip; need curl

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ASSET="vpnyellod-x86_64-linux.tar.gz";;
  aarch64|arm64) ASSET="vpnyellod-aarch64-linux.tar.gz";;
  *) echo "[install] unsupported cpu: $ARCH" >&2; exit 1;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$LOCAL_BUILD" -eq 1 ]; then
  echo "[install] local cargo build..."
  command -v cargo >/dev/null 2>&1 || { echo "install rust first: https://rustup.rs" >&2; exit 1; }
  (cd "$SCRIPT_DIR" && cargo build --release)
  install -m 0755 "$SCRIPT_DIR/target/release/vpnyellod" "$BIN"
else
  echo "[install] downloading $ASSET from github.com/$REPO ..."
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "https://github.com/${REPO}/releases/latest/download/${ASSET}" -o "$TMP/pkg.tar.gz"
  tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
  install -m 0755 "$TMP/vpnyellod" "$BIN"
  [ -f "$TMP/vpnyellod.service" ] && cp "$TMP/vpnyellod.service" /etc/systemd/system/vpnyellod.service
fi

[ -f "$SCRIPT_DIR/systemd/vpnyellod.service" ] && cp "$SCRIPT_DIR/systemd/vpnyellod.service" /etc/systemd/system/vpnyellod.service
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true

echo "[install] done → next:  sudo vpnyellod on"
echo "          check:  vpnyellod status   |   site: https://vpn.yellod.dpdns.org"
