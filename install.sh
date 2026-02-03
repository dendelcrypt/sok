#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "ERROR on line $LINENO" >&2' ERR

# ---------- helpers ----------
die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

detect_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

detect_src_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

ufw_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | grep -q "Status: active"
}

port_free() {
  local p="$1"
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ":${p}$" && return 1
  return 0
}

pick_port() {
  local lo="${1:-20000}" hi="${2:-45000}" p tries=0
  while true; do
    tries=$((tries+1))
    p="$(shuf -i "${lo}-${hi}" -n 1 2>/dev/null || true)"
    [[ -n "$p" ]] || die "shuf failed (coreutils missing?)"
    if port_free "$p"; then
      echo "$p"
      return 0
    fi
    [[ "$tries" -lt 2000 ]] || die "could not find a free port in range ${lo}-${hi}"
  done
}

# Stable random generators (no tr|head pipe issues)
rand_user() {
  # u + 10 hex chars => u + [0-9a-f]
  echo "u$(openssl rand -hex 5)"
}

rand_pass() {
  # 18 chars safe for URLs (A-Za-z0-9_.-)
  # Take base64, map +/ to _-, strip =, cut 18
  openssl rand -base64 24 | tr '+/' '_-' | tr -d '=' | cut -c1-18
}

install_deps() {
  info "Updating apt & installing deps..."
  apt-get update -y
  apt-get install -y \
    git build-essential make gcc \
    curl ca-certificates \
    iproute2 procps coreutils openssl
}

install_3proxy_from_source() {
  if command -v 3proxy >/dev/null 2>&1; then
    info "3proxy already installed: $(command -v 3proxy)"
    return 0
  fi

  info "Installing 3proxy from source (Ubuntu 24.04 compatible)..."
  rm -rf /opt/3proxy-src
  git clone --depth 1 https://github.com/z3APA3A/3proxy.git /opt/3proxy-src
  pushd /opt/3proxy-src >/dev/null
  make -f Makefile.Linux
  install -m 0755 bin/3proxy /usr/local/bin/3proxy
  popd >/dev/null

  info "3proxy installed: /usr/local/bin/3proxy"
}

write_cfg() {
  local cfg="/etc/3proxy/3proxy.cfg"
  local logdir="/var/log/3proxy"
  mkdir -p "$(dirname "$cfg")" "$logdir"
  chmod 0755 "$logdir"

  info "Writing 3proxy config: $cfg"

  {
    echo "daemon"
    echo "nscache 65536"
    echo "timeouts 1 5 30 60 180 1800 15 60"
    echo "log ${logdir}/3proxy.log D"
    echo "rotate 30"
    echo ""
    echo "auth strong"
    echo ""

    echo -n "users"
    for i in "${!PORTS[@]}"; do
      echo -n " ${USERS[$i]}:CL:${PASSS[$i]}"
    done
    echo ""
    echo ""

    for i in "${!PORTS[@]}"; do
      echo "allow ${USERS[$i]}"
      echo "socks -p${PORTS[$i]}"
      echo "flush"
      echo ""
    done
  } > "$cfg"
}

ensure_systemd() {
  local unit="/etc/systemd/system/3proxy.service"
  local bin="/usr/local/bin/3proxy"

  [[ -x "$bin" ]] || die "3proxy binary not found at $bin"

  info "Creating/updating systemd unit: $unit"
  cat > "$unit" <<EOF
[Unit]
Description=3proxy - tiny proxy server
After=network.target

[Service]
Type=simple
ExecStart=${bin} /etc/3proxy/3proxy.cfg
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
}

restart_service() {
  info "Enabling & restarting 3proxy..."
  systemctl enable --now 3proxy
  systemctl restart 3proxy
}

open_ufw_ports_if_needed() {
  if ufw_active; then
    info "UFW is active: opening proxy ports..."
    for p in "${PORTS[@]}"; do
      ufw allow "${p}/tcp" >/dev/null || true
    done
    ufw reload >/dev/null || true
  else
    info "UFW not active (or not installed): skipping firewall rules."
  fi
}

test_proxy_local() {
  local port="$1" user="$2" pass="$3"
  local out
  out="$(curl -fsS --max-time 15 \
    --socks5-hostname "127.0.0.1:${port}" \
    --proxy-user "${user}:${pass}" \
    https://ifconfig.me 2>/dev/null || true)"
  if [[ "$out" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "OK:$out"
  else
    echo "FAIL:${out}"
  fi
}

save_proxies() {
  local out="/root/proxies.txt"
  : > "$out"
  chmod 0600 "$out"
  for i in "${!PORTS[@]}"; do
    echo "socks5://${USERS[$i]}:${PASSS[$i]}@${SERVER_IP}:${PORTS[$i]}" >> "$out"
  done
  info "Saved: $out (chmod 600)"
}

# ---------- main ----------
need_root

IFACE="$(detect_iface)"
[[ -n "$IFACE" ]] || die "Could not detect network interface (ip route)."

SERVER_IP="$(detect_src_ip)"
SERVER_IP="${SERVER_IP:-SERVER_IP}"

COUNT="${COUNT:-}"
if [[ -z "$COUNT" ]]; then
  echo ""
  echo "How many SOCKS5 proxies to create on this server? (1-10)"
  read -r COUNT </dev/tty || true
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
  die "Please enter a number 1-10."
fi
if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 10 ]; then
  die "Number must be between 1 and 10."
fi

info "Detected interface: ${IFACE}"
info "Detected server IP (src): ${SERVER_IP}"

install_deps
install_3proxy_from_source

declare -a PORTS USERS PASSS
info "Generating ${COUNT} proxies (free random ports, random creds)..."
for ((i=0; i<COUNT; i++)); do
  PORTS[$i]="$(pick_port 20000 45000)"
  USERS[$i]="$(rand_user)"
  PASSS[$i]="$(rand_pass)"
done

# Save immediately so you never lose results
save_proxies

write_cfg
ensure_systemd
open_ufw_ports_if_needed
restart_service

echo ""
info "3proxy status:"
systemctl --no-pager -l status 3proxy || true

echo ""
info "Listening ports:"
ss -lntp 2>/dev/null | grep 3proxy || true

echo ""
info "Testing proxies locally (127.0.0.1:PORT -> ifconfig.me)..."
ALL_OK=1
for i in "${!PORTS[@]}"; do
  res="$(test_proxy_local "${PORTS[$i]}" "${USERS[$i]}" "${PASSS[$i]}")"
  if [[ "$res" == OK:* ]]; then
    ip="${res#OK:}"
    echo "  [OK]  port=${PORTS[$i]} user=${USERS[$i]} test_ip=${ip}"
  else
    ALL_OK=0
    echo "  [FAIL] port=${PORTS[$i]} user=${USERS[$i]} (provider firewall/outbound https may block test)"
  fi
done

echo ""
echo "===== RESULT (copy/paste) ====="
cat /root/proxies.txt
echo "==============================="
echo ""
echo "Notes:"
echo " - If you use a provider firewall (e.g. Vultr Firewall), open these TCP ports there too."
echo " - Service logs: journalctl -u 3proxy -n 100 --no-pager"
echo " - 3proxy log file: /var/log/3proxy/3proxy.log"

if [[ "$ALL_OK" -eq 0 ]]; then
  echo ""
  echo "Some tests failed. Most common reasons:"
  echo " - Provider firewall blocks ports"
  echo " - Outbound HTTPS is restricted"
  echo " - DNS issues"
fi

