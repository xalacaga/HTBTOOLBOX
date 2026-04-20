#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
BOOTSTRAP_OUTDIR="${BOOTSTRAP_OUTDIR:-/tmp/htbtoolbox-bootstrap}"
INSTALL_AI=0
SKIP_TOOLS=0

usage() {
  cat <<'USAGE'
Usage: ./install.sh [--with-ai] [--skip-tools]

Options:
  --with-ai     Installe aussi le client Anthropic pour la vue Analyse IA
  --skip-tools  Prépare seulement Python/web UI, sans installer les outils offensifs
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ai) INSTALL_AI=1; shift ;;
    --skip-tools) SKIP_TOOLS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[!] Option inconnue: $1"; usage; exit 1 ;;
  esac
done

log() { printf '[*] %s\n' "$*"; }
good() { printf '[+] %s\n' "$*"; }
warn() { printf '[~] %s\n' "$*"; }
bad() { printf '[!] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

run_priv() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    bad "sudo est requis pour installer les paquets système."
    exit 1
  fi
}

apt_install() {
  run_priv apt-get install -y "$@"
}

ensure_apt() {
  local bin="$1"
  local pkg="$2"
  if have "$bin"; then
    good "$bin déjà présent"
    return 0
  fi
  log "Installation apt de $pkg"
  if ! apt_install "$pkg"; then
    warn "Impossible d'installer $pkg automatiquement"
    return 1
  fi
}

ensure_pipx() {
  local bin="$1"
  local spec="$2"
  if have "$bin"; then
    good "$bin déjà présent"
    return 0
  fi
  log "Installation pipx de $spec"
  if ! pipx install --force "$spec"; then
    warn "Impossible d'installer $spec via pipx"
    return 1
  fi
}

ensure_local_bin_dir() {
  export PATH="$HOME/.local/bin:$PATH"
  if have pipx; then
    pipx ensurepath >/dev/null 2>&1 || true
  fi
}

ensure_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    log "Création du virtualenv Python"
    python3 -m venv "$VENV_DIR"
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  python -m pip install --upgrade pip >/dev/null
  python -m pip install -r "$SCRIPT_DIR/requirements.txt"
  if [[ "$INSTALL_AI" == "1" ]]; then
    python -m pip install anthropic
  fi
}

install_release_binary() {
  local bin_name="$1"
  local url="$2"
  local archive="$3"
  if have "$bin_name"; then
    good "$bin_name déjà présent"
    return 0
  fi
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  log "Téléchargement de $bin_name depuis ${url}"
  curl -fsSL "$url" -o "$tmpdir/$archive"
  case "$archive" in
    *.tar.gz|*.tgz) tar -xzf "$tmpdir/$archive" -C "$tmpdir" ;;
    *.zip) unzip -q "$tmpdir/$archive" -d "$tmpdir" ;;
    *) bad "Archive non supportée pour $bin_name: $archive"; return 1 ;;
  esac
  local found
  found="$(find "$tmpdir" -type f \( -name "$bin_name" -o -name "${bin_name}.exe" \) | head -1)"
  if [[ -z "$found" ]]; then
    bad "Impossible de trouver $bin_name dans l'archive"
    return 1
  fi
  run_priv install -m 0755 "$found" /usr/local/bin/$bin_name
  good "$bin_name installé dans /usr/local/bin"
}

main() {
  command -v python3 >/dev/null || { bad "python3 est requis"; exit 1; }
  command -v git >/dev/null || { bad "git est requis"; exit 1; }

  log "Mise à jour APT"
  run_priv apt-get update

  log "Installation des prérequis système"
  apt_install python3 python3-venv python3-pip pipx git curl unzip psmisc jq

  ensure_local_bin_dir
  ensure_venv

  if [[ ! -f "$SCRIPT_DIR/config.local.json" && -f "$SCRIPT_DIR/config.example.json" ]]; then
    cp "$SCRIPT_DIR/config.example.json" "$SCRIPT_DIR/config.local.json"
    good "config.local.json créé depuis config.example.json"
  fi

  if [[ "$SKIP_TOOLS" == "1" ]]; then
    good "Bootstrap Python terminé. Installation des outils offensifs ignorée (--skip-tools)."
    return 0
  fi

  log "Installation des outils système principaux"
  ensure_apt nmap nmap
  ensure_apt smbclient smbclient
  ensure_apt ldapsearch ldap-utils
  ensure_apt rpcclient samba-common-bin
  ensure_apt ntpdate ntpdate
  ensure_apt dig dnsutils
  ensure_apt curl curl
  ensure_apt jq jq
  ensure_apt whatweb whatweb
  ensure_apt nikto nikto
  ensure_apt ffuf ffuf
  ensure_apt wfuzz wfuzz
  ensure_apt hydra hydra
  ensure_apt socat socat
  ensure_apt sqlmap sqlmap
  ensure_apt smbmap smbmap
  ensure_apt wafw00f wafw00f
  ensure_apt wpscan wpscan
  ensure_apt feroxbuster feroxbuster
  ensure_apt gobuster gobuster
  ensure_apt showmount nfs-common
  ensure_apt redis-cli redis-tools
  ensure_apt psql postgresql-client
  ensure_apt mysql default-mysql-client
  ensure_apt responder responder
  ensure_apt chisel chisel
  ensure_apt evil-winrm evil-winrm
  ensure_apt rustscan rustscan
  ensure_apt masscan masscan
  ensure_apt nuclei nuclei
  ensure_apt mongosh mongodb-mongosh || true
  ensure_apt mongodump mongodb-database-tools || true
  ensure_apt sshpass sshpass
  ensure_apt onesixtyone onesixtyone || true
  ensure_apt snmpwalk snmp
  ensure_apt kerbrute kerbrute || true
  ensure_apt mono mono-utils || true
  ensure_apt strings binutils || true
  ensure_apt file file || true
  ensure_apt readelf binutils || true
  ensure_apt exiftool libimage-exiftool-perl || true
  ensure_apt binwalk binwalk || true
  ensure_apt foremost foremost || true
  ensure_apt checksec checksec || true
  ensure_apt nxc netexec || true
  ensure_apt crackmapexec crackmapexec || true
  ensure_apt impacket-GetNPUsers python3-impacket || true

  log "Installation des outils Python offensifs"
  ensure_pipx bloodhound-python bloodhound || true
  ensure_pipx ldapdomaindump git+https://github.com/dirkjanm/ldapdomaindump.git || true
  ensure_pipx enum4linux-ng git+https://github.com/cddmp/enum4linux-ng.git || true
  ensure_pipx certipy-ad git+https://github.com/ly4k/Certipy.git || true
  ensure_pipx bloodyAD git+https://github.com/CravateRouge/bloodyAD.git || true

  if ! have ligolo-proxy; then
    install_release_binary ligolo-proxy \
      https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz \
      ligolo-ng_proxy_linux_amd64.tar.gz || true
  fi

  chmod +x "$SCRIPT_DIR/htbtoolbox.sh" "$SCRIPT_DIR/start.sh"

  log "Complément via le moteur d'auto-install interne"
  mkdir -p "$BOOTSTRAP_OUTDIR"
  (
    export TARGET="127.0.0.1"
    export DOMAIN="bootstrap.local"
    export DC="dc01.bootstrap.local"
    export OUTDIR="$BOOTSTRAP_OUTDIR"
    export AUTO_INSTALL_TOOLS=1
    export DO_ASREP=1 KERBEROAST=1 MSSQL_ENUM=1 WINRM_CHECK=1 DNS_ENUM=1
    export KERB_USER_ENUM=1 ENUM4LINUX=1 NMAP_SCAN=1 NTP_SYNC=1 WEB_ENUM=1
    export BLOODHOUND=1 LDAPDOMAINDUMP=1 CERTIPY=1 BLOODYAD=1
    export SNMP_ENUM=1 FTP_ENUM=1 SMB_SIGNING=1 LDAPS_ENUM=1
    source "$SCRIPT_DIR/htbtoolbox.sh"
    htbtoolbox_init_tooling
  ) || true

  good "Installation terminée."
  echo
  echo "Ensuite :"
  echo "  cd $SCRIPT_DIR"
  echo "  ./start.sh --open"
}

main "$@"
