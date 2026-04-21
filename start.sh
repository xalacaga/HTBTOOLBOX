#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8765}"
OPEN_BROWSER=0
SKIP_BOOTSTRAP=0

usage() {
  cat <<'EOF'
Usage: ./start.sh [--host HOST] [--port PORT] [--open] [--skip-bootstrap]

Options:
  --host HOST         Bind host (default: 127.0.0.1)
  --port PORT         Bind port (default: 8765)
  --open              Open the UI in the default browser
  --skip-bootstrap    Do not auto-create/update the Python virtualenv
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --open) OPEN_BROWSER=1; shift ;;
    --skip-bootstrap) SKIP_BOOTSTRAP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[!] Option inconnue: $1"; usage; exit 1 ;;
  esac
done

echo
echo "  HTB Toolbox v2"
echo "  ══════════════"
echo

command -v python3 >/dev/null || { echo "[!] Python3 requis."; exit 1; }

ensure_impacket_launchers() {
  local examples_dir="/usr/share/doc/python3-impacket/examples"
  local system_python="/usr/bin/python3"
  local wrappers=(
    "impacket-GetNPUsers:GetNPUsers.py"
    "impacket-GetUserSPNs:GetUserSPNs.py"
    "impacket-getTGT:getTGT.py"
    "impacket-secretsdump:secretsdump.py"
    "impacket-psexec:psexec.py"
    "impacket-wmiexec:wmiexec.py"
    "impacket-ntlmrelayx:ntlmrelayx.py"
    "impacket-mssqlclient:mssqlclient.py"
    "impacket-rbcd:rbcd.py"
    "impacket-dacledit:dacledit.py"
    "impacket-owneredit:owneredit.py"
    "impacket-addcomputer:addcomputer.py"
    "impacket-getST:getST.py"
    "GetNPUsers.py:GetNPUsers.py"
    "GetUserSPNs.py:GetUserSPNs.py"
    "addcomputer.py:addcomputer.py"
    "dacledit.py:dacledit.py"
    "owneredit.py:owneredit.py"
    "rbcd.py:rbcd.py"
    "getST.py:getST.py"
    "ntlmrelayx.py:ntlmrelayx.py"
  )

  [[ -d "$VENV_DIR/bin" ]] || return 0

  for entry in "${wrappers[@]}"; do
    local name="${entry%%:*}"
    local example="${entry##*:}"
    local target="$VENV_DIR/bin/$name"
    if [[ -f "$examples_dir/$example" && -x "$system_python" ]]; then
      cat >"$target" <<EOF
#!/usr/bin/env bash
exec "$system_python" "$examples_dir/$example" "\$@"
EOF
    else
      continue
    fi
    chmod +x "$target"
  done
}

ensure_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    echo "[*] Création du virtualenv Python..."
    python3 -m venv "$VENV_DIR"
  fi

  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "[*] Installation des dépendances Python du projet..."
    python -m pip install --upgrade pip >/dev/null
    python -m pip install -r "$SCRIPT_DIR/requirements.txt"
  fi

  ensure_impacket_launchers
}

if [[ "$SKIP_BOOTSTRAP" != "1" ]]; then
  ensure_venv
else
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
fi

if [[ ! -f "$SCRIPT_DIR/config.local.json" && -f "$SCRIPT_DIR/config.example.json" ]]; then
  cp "$SCRIPT_DIR/config.example.json" "$SCRIPT_DIR/config.local.json"
fi

chmod +x "$SCRIPT_DIR/htbtoolbox.sh" "$SCRIPT_DIR/install.sh" 2>/dev/null || true

if [[ "$OPEN_BROWSER" == "1" ]]; then
  (sleep 1.5 && xdg-open "http://${HOST}:${PORT}" >/dev/null 2>&1) &
fi

if command -v fuser >/dev/null 2>&1 && fuser "${PORT}/tcp" &>/dev/null; then
  echo "[~] Port ${PORT} occupé — arrêt de l'instance précédente..."
  fuser -k "${PORT}/tcp" &>/dev/null || true
  sleep 1
fi

echo "[+] Démarrage → http://${HOST}:${PORT}"
echo "[+] Ctrl+C pour arrêter"
echo

HOST="$HOST" PORT="$PORT" python "$SCRIPT_DIR/server.py"
