#!/usr/bin/env bash
# Installe les modules souvent absents : mongosh, mongodump, sshpass, rustscan, foremost, checksec, cargo, PKINITtools
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

ensure_pkinittools() {
  local repo_dir="$SCRIPT_DIR/PKINITtools"
  if [[ -f "$repo_dir/gettgtpkinit.py" && -f "$repo_dir/getnthash.py" ]]; then
    good "PKINITtools déjà présent"
  else
    if ! have git; then
      log "apt install git"
      apt_install git || warn "git : échec"
    fi
    if have git; then
      log "PKINITtools via git clone"
      if [[ -d "$repo_dir/.git" ]]; then
        git -C "$repo_dir" pull --ff-only || warn "PKINITtools : mise à jour échouée"
      else
        git clone https://github.com/dirkjanm/PKINITtools.git "$repo_dir" || warn "PKINITtools : clone échoué"
      fi
    fi
  fi
  if [[ -f "$repo_dir/requirements.txt" ]]; then
    log "PKINITtools : installation des dépendances Python"
    python3 -m pip install -r "$repo_dir/requirements.txt" || warn "PKINITtools deps : échec"
  fi
}

run_priv apt-get update

# APT-available
for pair in "sshpass sshpass" "foremost foremost" "checksec checksec" "cargo cargo"; do
  bin="${pair% *}"; pkg="${pair#* }"
  if have "$bin"; then good "$bin déjà présent"; continue; fi
  log "apt install $pkg"
  apt_install "$pkg" || warn "$pkg : échec"
done

# rustscan : cargo
if have rustscan; then
  good "rustscan déjà présent"
else
  if ! have cargo; then
    log "apt install cargo"
    apt_install cargo || warn "cargo : échec"
  fi
  if have cargo; then
    log "rustscan via cargo install rustscan"
    cargo install rustscan || warn "rustscan via cargo : échec"
    hash -r 2>/dev/null || true
  fi
  if ! have rustscan && [[ -x "$HOME/.cargo/bin/rustscan" ]]; then
    good "rustscan installé dans $HOME/.cargo/bin/rustscan"
  elif ! have rustscan; then
    warn "rustscan toujours absent"
  fi
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

ensure_pkinittools

echo
good "Résumé :"
for b in sshpass foremost checksec cargo rustscan mongosh mongodump; do
  if have "$b"; then printf '  ok    %s\n' "$b"; else printf '  MANQUE %s\n' "$b"; fi
done
if [[ -f "$SCRIPT_DIR/PKINITtools/gettgtpkinit.py" && -f "$SCRIPT_DIR/PKINITtools/getnthash.py" ]]; then
  printf '  ok    %s\n' "PKINITtools"
else
  printf '  MANQUE %s\n' "PKINITtools"
fi
