#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# htbtoolbox.sh — utilitaires pré-flight pour HTB Toolbox
# ============================================================
# Historiquement, ce script hébergeait l'intégralité du moteur d'énumération
# AD/HTB. Le backend Python (server.py) est désormais la source unique de vérité
# pour l'exécution des phases. Ne restent ici que les utilitaires "pré-flight"
# réutilisés depuis Python ou install.sh :
#
#   setup_hosts              — met à jour /etc/hosts (TARGET + DOMAIN/DC)
#   htbtoolbox_init_tooling  — installe/vérifie les outils externes (apt/pipx)
#   htbtoolbox_fast_tooling_init — variante rapide (cache binaires)
#
# Usage depuis l'extérieur :
#   source ./htbtoolbox.sh && setup_hosts
#   source ./htbtoolbox.sh && htbtoolbox_init_tooling
#
# Exécuté directement, le script ne fait que lancer htbtoolbox_init_tooling.
# ============================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "[!] Ce script doit être exécuté avec bash, pas avec sh."
  exit 1
fi

umask 077

# ----------------------------
# Runtime configuration (valeurs par défaut)
# ----------------------------
TARGET="${TARGET:-}"
DOMAIN="${DOMAIN:-}"
DC="${DC:-}"
OUTDIR="${OUTDIR:-}"
AUTO_HOSTS="${AUTO_HOSTS:-0}"
AUTO_INSTALL_TOOLS="${AUTO_INSTALL_TOOLS:-1}"

# Flags pilotant htbtoolbox_init_tooling : quels outils optionnels installer.
DO_ASREP="${DO_ASREP:-1}"
KERBEROAST="${KERBEROAST:-1}"
MSSQL_ENUM="${MSSQL_ENUM:-1}"
ENUM4LINUX="${ENUM4LINUX:-1}"
NMAP_SCAN="${NMAP_SCAN:-1}"
NTP_SYNC="${NTP_SYNC:-1}"
WEB_ENUM="${WEB_ENUM:-1}"
BLOODHOUND="${BLOODHOUND:-1}"
LDAPDOMAINDUMP="${LDAPDOMAINDUMP:-1}"
CERTIPY="${CERTIPY:-1}"
BLOODYAD="${BLOODYAD:-1}"
DNS_ENUM="${DNS_ENUM:-1}"
KERB_USER_ENUM="${KERB_USER_ENUM:-1}"
WINRM_CHECK="${WINRM_CHECK:-1}"

# ----------------------------
# Colors / logging helpers
# ----------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "${YELLOW}[*] $*${NC}"; }
good()    { echo -e "${GREEN}[+] $*${NC}"; }
bad()     { echo -e "${RED}[!] $*${NC}"; }
section() { echo -e "\n${BOLD}${CYAN}==============================${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}==============================${NC}\n"; }

have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || { bad "Dépendance manquante : $1"; exit 1; }; }

PATH="$PATH:$HOME/.local/bin:/root/.local/bin"

# ----------------------------
# Privilèges (SUDO_PASS facultatif)
# ----------------------------
run_priv() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
    return
  fi
  if have sudo; then
    if [ -n "${SUDO_PASS:-}" ]; then
      printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"
      return
    fi
    sudo "$@"
    return
  fi
  return 1
}

# ----------------------------
# APT / pipx helpers + tooling summary
# ----------------------------
APT_UPDATED=0
INSTALL_ERRORS=0
TOOLING_SUMMARY=""

append_tooling_summary() {
  TOOLING_SUMMARY+="$1"$'\n'
}

tooling_summary_block() {
  [ -n "${TOOLING_SUMMARY:-}" ] && printf "%s" "$TOOLING_SUMMARY"
}

record_present_tool() {
  local label="$1" bin="$2"
  if have "$bin"; then
    append_tooling_summary "[OK]    ${label}|${bin}|present|$(command -v "$bin")"
  fi
}

apt_update_once() {
  [ "$APT_UPDATED" = "1" ] && return 0
  have apt-get || return 1
  log "Exécution de apt-get update..."
  if run_priv apt-get update; then
    APT_UPDATED=1
    return 0
  fi
  return 1
}

install_apt_pkg() {
  local pkg="$1"
  have apt-get || return 1
  apt_update_once || return 1
  log "Installation du paquet apt : $pkg"
  run_priv apt-get install -y "$pkg"
}

install_pipx_spec() {
  local spec="$1"
  if ! have pipx; then
    have apt-get && install_apt_pkg pipx || return 1
  fi
  log "Installation via pipx : $spec"
  pipx install --force "$spec"
}

ensure_tool() {
  local bin="$1" label="$2" apt_pkg="${3:-}" pipx_spec="${4:-}"

  if have "$bin"; then
    good "$label trouvé : $(command -v "$bin")"
    append_tooling_summary "[OK]    ${label}|${bin}|present|$(command -v "$bin")"
    return 0
  fi

  if [ "$AUTO_INSTALL_TOOLS" != "1" ]; then
    bad "$label manquant ($bin). AUTO_INSTALL_TOOLS=0, installation ignorée."
    append_tooling_summary "[MISS]  ${label}|${bin}|missing|auto-install disabled"
    INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
    return 1
  fi

  log "$label manquant -> tentative d'installation"

  if [ -n "$apt_pkg" ]; then
    install_apt_pkg "$apt_pkg" || true
    hash -r 2>/dev/null || true
    if have "$bin"; then
      good "$label installé via apt"
      append_tooling_summary "[INST]  ${label}|${bin}|installed|apt:${apt_pkg}"
      return 0
    fi
  fi

  if [ -n "$pipx_spec" ]; then
    install_pipx_spec "$pipx_spec" || true
    hash -r 2>/dev/null || true
    if have "$bin"; then
      good "$label installé via pipx/GitHub"
      append_tooling_summary "[INST]  ${label}|${bin}|installed|pipx:${pipx_spec}"
      return 0
    fi
  fi

  bad "Impossible d'installer automatiquement $label."
  append_tooling_summary "[FAIL]  ${label}|${bin}|failed|auto-install failed"
  INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
  return 1
}

# ----------------------------
# Dépendances (variante rapide via cache, puis complète)
# ----------------------------
GETNPUSERS_BIN=""
GETUSERSPNS_BIN=""
MSSQLCLIENT_BIN=""
SMB_ENUM_TOOL=""

htbtoolbox_fast_tooling_init() {
  GETNPUSERS_BIN=""
  GETUSERSPNS_BIN=""
  MSSQLCLIENT_BIN=""

  have impacket-GetNPUsers && GETNPUSERS_BIN="impacket-GetNPUsers"
  [ -z "$GETNPUSERS_BIN" ] && have impacket-getnpusers && GETNPUSERS_BIN="impacket-getnpusers"

  have impacket-GetUserSPNs && GETUSERSPNS_BIN="impacket-GetUserSPNs"
  [ -z "$GETUSERSPNS_BIN" ] && have impacket-getuserspns && GETUSERSPNS_BIN="impacket-getuserspns"

  have impacket-mssqlclient && MSSQLCLIENT_BIN="impacket-mssqlclient"
  [ -z "$MSSQLCLIENT_BIN" ] && have mssqlclient.py && MSSQLCLIENT_BIN="mssqlclient.py"

  if have nxc; then
    SMB_ENUM_TOOL="nxc"
  elif have crackmapexec; then
    SMB_ENUM_TOOL="crackmapexec"
  else
    return 1
  fi
  return 0
}

htbtoolbox_init_tooling() {
  local cache_file=""
  if [ -n "${OUTDIR:-}" ]; then
    cache_file="${OUTDIR}/.htbtoolbox_tooling_ok"
  fi

  if [ "${HTB_WEB_FAST_INIT:-0}" = "1" ] && [ -n "$cache_file" ] && [ -f "$cache_file" ]; then
    htbtoolbox_fast_tooling_init || return 1
    return 0
  fi

  section "Vérification des dépendances"
  ensure_tool tee "tee" coreutils
  ensure_tool grep "grep" grep
  ensure_tool awk "awk" gawk
  ensure_tool sed "sed" sed
  ensure_tool sort "sort" coreutils
  ensure_tool tr "tr" coreutils
  ensure_tool getent "getent" libc-bin
  ensure_tool smbclient "smbclient" smbclient
  ensure_tool ldapsearch "ldapsearch" ldap-utils
  ensure_tool rpcclient "rpcclient" samba-common-bin
  ensure_tool git "git" git

  GETNPUSERS_BIN=""
  GETUSERSPNS_BIN=""
  MSSQLCLIENT_BIN=""

  if [ "$DO_ASREP" = "1" ]; then
    if have impacket-GetNPUsers; then
      GETNPUSERS_BIN="impacket-GetNPUsers"
      record_present_tool "Impacket GetNPUsers" "impacket-GetNPUsers"
    elif have impacket-getnpusers; then
      GETNPUSERS_BIN="impacket-getnpusers"
      record_present_tool "Impacket GetNPUsers" "impacket-getnpusers"
    else
      ensure_tool impacket-getnpusers "Impacket GetNPUsers" python3-impacket "git+https://github.com/fortra/impacket.git" || true
      hash -r 2>/dev/null || true
      have impacket-GetNPUsers && GETNPUSERS_BIN="impacket-GetNPUsers"
      [ -z "$GETNPUSERS_BIN" ] && have impacket-getnpusers && GETNPUSERS_BIN="impacket-getnpusers"
    fi
  fi

  if [ "$KERBEROAST" = "1" ]; then
    if have impacket-GetUserSPNs; then
      GETUSERSPNS_BIN="impacket-GetUserSPNs"
      record_present_tool "Impacket GetUserSPNs" "impacket-GetUserSPNs"
    elif have impacket-getuserspns; then
      GETUSERSPNS_BIN="impacket-getuserspns"
      record_present_tool "Impacket GetUserSPNs" "impacket-getuserspns"
    else
      ensure_tool impacket-getuserspns "Impacket GetUserSPNs" python3-impacket "git+https://github.com/fortra/impacket.git" || true
      hash -r 2>/dev/null || true
      have impacket-GetUserSPNs && GETUSERSPNS_BIN="impacket-GetUserSPNs"
      [ -z "$GETUSERSPNS_BIN" ] && have impacket-getuserspns && GETUSERSPNS_BIN="impacket-getuserspns"
    fi
  fi

  if [ "$MSSQL_ENUM" = "1" ]; then
    if have impacket-mssqlclient; then
      MSSQLCLIENT_BIN="impacket-mssqlclient"
      record_present_tool "Impacket MSSQL client" "impacket-mssqlclient"
    elif have mssqlclient.py; then
      MSSQLCLIENT_BIN="mssqlclient.py"
      record_present_tool "Impacket MSSQL client" "mssqlclient.py"
    else
      ensure_tool impacket-mssqlclient "Impacket MSSQL client" python3-impacket "git+https://github.com/fortra/impacket.git" || true
      hash -r 2>/dev/null || true
      have impacket-mssqlclient && MSSQLCLIENT_BIN="impacket-mssqlclient"
      [ -z "$MSSQLCLIENT_BIN" ] && have mssqlclient.py && MSSQLCLIENT_BIN="mssqlclient.py"
    fi
  fi

  if have nxc; then
    SMB_ENUM_TOOL="nxc"
  elif have crackmapexec; then
    SMB_ENUM_TOOL="crackmapexec"
  else
    ensure_tool nxc "NetExec" netexec || true
    hash -r 2>/dev/null || true
    if have nxc; then
      SMB_ENUM_TOOL="nxc"
    elif have crackmapexec; then
      SMB_ENUM_TOOL="crackmapexec"
    else
      bad "Manquant : nxc (netexec) ou crackmapexec"
      return 1
    fi
  fi
  good "Outil d'énumération SMB : $SMB_ENUM_TOOL"

  [ "$ENUM4LINUX" = "1" ] && ! have jq && ensure_tool jq "jq" jq || true

  ensure_tool monodis "monodis" mono-utils || true
  ensure_tool strings "strings" binutils || true

  [ "$WINRM_CHECK" = "1" ] && ensure_tool curl "curl" curl || true
  if [ "$DNS_ENUM" = "1" ]; then
    ensure_tool dig "dig" dnsutils || true
    ensure_tool host "host" dnsutils || true
    ensure_tool nslookup "nslookup" dnsutils || true
  fi
  [ "$KERB_USER_ENUM" = "1" ] && ensure_tool kerbrute "kerbrute" kerbrute || true
  [ "$ENUM4LINUX" = "1" ] && ensure_tool enum4linux-ng "enum4linux-ng" enum4linux-ng "git+https://github.com/cddmp/enum4linux-ng.git" || true
  [ "$NMAP_SCAN" = "1" ] && ensure_tool nmap "nmap" nmap || true
  [ "$NTP_SYNC" = "1" ] && ensure_tool ntpdate "ntpdate" ntpdate || true
  if [ "$WEB_ENUM" = "1" ] && ! have feroxbuster && ! have gobuster && ! have dirb; then
    ensure_tool feroxbuster "feroxbuster" feroxbuster || true
    if ! have feroxbuster && ! have gobuster && ! have dirb; then
      ensure_tool gobuster "gobuster" gobuster || true
    fi
    if ! have feroxbuster && ! have gobuster && ! have dirb; then
      ensure_tool dirb "dirb" dirb || true
    fi
  fi
  [ "$BLOODHOUND" = "1" ] && ensure_tool bloodhound-python "bloodhound-python" "" bloodhound || true
  [ "$LDAPDOMAINDUMP" = "1" ] && ensure_tool ldapdomaindump "ldapdomaindump" "" "git+https://github.com/dirkjanm/ldapdomaindump.git" || true
  if [ "$CERTIPY" = "1" ]; then
    if have certipy-ad; then
      record_present_tool "certipy-ad" "certipy-ad"
    elif have certipy; then
      record_present_tool "certipy" "certipy"
    else
      ensure_tool certipy-ad "certipy-ad" "" "git+https://github.com/ly4k/Certipy.git" || true
    fi
  fi
  if [ "$BLOODYAD" = "1" ]; then
    if have bloodyAD; then
      record_present_tool "bloodyAD" "bloodyAD"
    elif have bloodyad; then
      record_present_tool "bloodyAD" "bloodyad"
    else
      ensure_tool bloodyAD "bloodyAD" "" "git+https://github.com/CravateRouge/bloodyAD.git" || true
    fi
  fi

  if [ "$INSTALL_ERRORS" -gt 0 ]; then
    log "L'installation automatique a rencontré ${INSTALL_ERRORS} échec(s). Le script continue quand c'est possible."
  fi

  if [ -n "$cache_file" ]; then
    : > "$cache_file" 2>/dev/null || true
  fi
}

# ----------------------------
# /etc/hosts (optional)
# ----------------------------
setup_hosts() {
  if [ "$AUTO_HOSTS" != "1" ]; then
    log "AUTO_HOSTS=0 -> /etc/hosts ignoré"
    return
  fi
  if [ -z "${TARGET:-}" ]; then
    log "TARGET vide -> /etc/hosts ignoré"
    return
  fi
  if [ -z "${DOMAIN:-}" ] && [ -z "${DC:-}" ]; then
    log "DOMAIN/DC non encore connus -> /etc/hosts différé"
    return
  fi
  need sudo

  log "Configuration de /etc/hosts..."
  local tag="# adv_enum_${TARGET}"
  local names=""
  [ -n "${DOMAIN:-}" ] && names="$names ${DOMAIN}"
  if [ -n "${DC:-}" ]; then
    names="$names ${DC}"
    [[ "$DC" == *.* ]] && names="$names ${DC%%.*}"
  fi
  names="$(printf '%s\n' "$names" | xargs -n1 2>/dev/null | awk 'NF && !seen[$0]++' | paste -sd' ' -)"
  if [ -z "$names" ]; then
    log "Aucun nom utile à écrire dans /etc/hosts"
    return
  fi
  local hosts_line="${TARGET} ${names} ${tag}"

  run_priv cp /etc/hosts /etc/hosts.bak_adv_enum 2>/dev/null || true
  run_priv sed -i "/${tag//\//\\/}/d" /etc/hosts || true
  run_priv sh -c 'printf "%s\n" "$1" >> /etc/hosts' sh "$hosts_line" || true
  good "Entrée mise à jour : $hosts_line"

  log "Test de résolution de nom..."
  local probe_name="${DC:-${DOMAIN:-}}"
  if [ -n "$probe_name" ] && getent hosts "$probe_name" >/dev/null 2>&1; then
    good "Résolution OK : $probe_name"
  else
    bad "Échec de résolution : ${probe_name:-inconnu} (vérifie /etc/hosts)"
  fi
}

# ----------------------------
# Exécution directe -> install outils uniquement
# ----------------------------
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  htbtoolbox_init_tooling
fi
