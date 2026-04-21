#!/usr/bin/env bash
# Installe les modules souvent absents : mongosh, mongodump, sshpass, rustscan, foremost, checksec, cargo
# Utilise les helpers de install.sh (ensure_rustscan, ensure_mongosh, ensure_mongodb_tools, install_deb_from_url)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '[*] %s\n' "$*"; }
good() { printf '[+] %s\n' "$*"; }
warn() { printf '[~] %s\n' "$*"; }
bad()  { printf '[!] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

run_priv() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    bad "sudo requis"
    exit 1
  fi
}

apt_install() {
  run_priv apt-get install -y "$@"
}

install_deb_from_url() {
  local bin_name="$1" url="$2"
  if have "$bin_name"; then good "$bin_name déjà présent"; return 0; fi
  local tmpfile
  tmpfile="$(mktemp --suffix=.deb)"
  log "Téléchargement .deb pour $bin_name : $url"
  if ! curl -fsSL "$url" -o "$tmpfile"; then
    warn "Téléchargement échoué pour $bin_name"
    rm -f "$tmpfile"; return 1
  fi
  run_priv dpkg -i "$tmpfile" 2>/dev/null || run_priv apt-get install -f -y
  rm -f "$tmpfile"
  have "$bin_name" && good "$bin_name installé" || { warn "$bin_name toujours absent"; return 1; }
}

run_priv apt-get update

# APT-available
for pair in "sshpass sshpass" "foremost foremost" "checksec checksec" "cargo cargo"; do
  bin="${pair% *}"; pkg="${pair#* }"
  if have "$bin"; then good "$bin déjà présent"; continue; fi
  log "apt install $pkg"
  apt_install "$pkg" || warn "$pkg : échec"
done

# rustscan : GitHub release
if have rustscan; then
  good "rustscan déjà présent"
else
  log "rustscan via GitHub release (bee-san/RustScan)"
  TAG="$(curl -fsSL https://api.github.com/repos/bee-san/RustScan/releases/latest 2>/dev/null | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)"
  [[ -z "$TAG" ]] && TAG="2.3.0"
  VER="${TAG#v}"
  install_deb_from_url rustscan "https://github.com/bee-san/RustScan/releases/download/${TAG}/rustscan_${VER}_amd64.deb" || \
    warn "rustscan : fallback cargo recommandé (cargo install rustscan)"
fi

# mongosh : MongoDB CDN
if have mongosh; then
  good "mongosh déjà présent"
else
  log "mongosh via MongoDB CDN"
  install_deb_from_url mongosh "https://downloads.mongodb.com/compass/mongodb-mongosh_2.3.2_amd64.deb" || \
    warn "mongosh : vérifie la dernière version sur https://www.mongodb.com/try/download/shell"
fi

# mongodump (mongodb-database-tools) : MongoDB CDN
if have mongodump; then
  good "mongodump déjà présent"
else
  log "mongodb-database-tools via MongoDB CDN"
  install_deb_from_url mongodump "https://fastdl.mongodb.org/tools/db/mongodb-database-tools-debian12-x86_64-100.10.0.deb" || \
    warn "mongodb-database-tools : vérifie la dernière version sur https://www.mongodb.com/try/download/database-tools"
fi

echo
good "Résumé :"
for b in sshpass foremost checksec cargo rustscan mongosh mongodump; do
  if have "$b"; then printf '  ok    %s\n' "$b"; else printf '  MANQUE %s\n' "$b"; fi
done
