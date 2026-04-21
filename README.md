# HTB Toolbox

> 🇫🇷 [Français](#-français) · 🇬🇧 [English](#-english)
> 📖 Guide utilisateur assisté : [GUIDE.md](GUIDE.md)

---

## 🇫🇷 Français

Interface web standalone qui pilote une boîte à outils de pentest **Windows / Linux / Web / Hybrid** depuis Kali Linux. Le projet est conçu pour être cloné et installé **from-scratch** sur une Kali récente en quelques commandes.

### Ce que fait l'outil

- **Un navigateur web = ta console opérateur** : sélectionne des outils, lance-les, regarde les sorties en temps réel, parcours le loot, analyse avec Claude.
- **91 outils catalogués** en 14 groupes : recon, SMB, LDAP, Kerberos, ADCS, BloodHound, post-auth, Linux privesc, Web, SQL, coercition NTLM, tunnel/pivot, plus des helpers de triage avancé.
- **Wizard guidé + Presets d'attaque** : chaînes prêtes à l'emploi pour `windows`, `linux`, `web` et `hybrid`.
- **Playbook opérateur** : recommandations adaptées au contexte détecté (type de cible × mode opératoire).
- **3 modes opératoires** : `safe` (discret), `htb` (agressif pour lab), `enterprise` (opsec serrée).
- **Détection auto** : après un scan, les modules pertinents se cochent tout seuls selon les ports ouverts.
- **Auto-complétion** : credentials extraits des sorties (NT hash, TGT, mots de passe) automatiquement proposés pour remplir la config.
- **Parallélisme contrôlé** : jusqu'à 3 outils en parallèle selon le contexte et le mode.
- **UI bilingue** : bascule `Français / English` directement dans l'interface, avec persistance dans la config locale.

### Installation from-scratch sur Kali

```bash
git clone <REPO_URL> HTBTOOLBOX
cd HTBTOOLBOX
chmod +x install.sh start.sh htbtoolbox.sh
./install.sh
./start.sh --open
```

L'interface est disponible sur `http://127.0.0.1:8765`.

#### Options install

```bash
./install.sh --with-ai      # ajoute le client Anthropic (analyse IA du loot)
./install.sh --skip-tools   # prépare seulement backend + UI (pas d'apt install)
```

#### Installation complémentaire

```bash
./install_missing.sh        # tente d'ajouter les outils souvent absents sur certaines Kali
```

Ce script complémentaire vise surtout `rustscan`, `mongosh`, `mongodump`, `sshpass`, `foremost`, `checksec` et `cargo`.

#### Options start

```bash
./start.sh                        # 127.0.0.1:8765
./start.sh --open                 # ouvre Firefox automatiquement
./start.sh --host 0.0.0.0         # accessible réseau (⚠ attention)
./start.sh --port 9000            # change le port
./start.sh --skip-bootstrap       # utilise .venv existant sans vérification
```

### Outils installés automatiquement

`install.sh` tente d'installer via apt/pipx/releases GitHub :

- Scan : `nmap`, `rustscan`, `masscan`
- AD : `netexec`/`nxc`, `crackmapexec`, `smbclient`, `rpcclient`, `ldap-utils`, `kerbrute`
- Impacket, `bloodhound-python`, `certipy-ad`, `bloodyAD`, `ldapdomaindump`, `enum4linux-ng`
- Web : `ffuf`, `wfuzz`, `feroxbuster`, `gobuster`, `nikto`, `nuclei`, `sqlmap`, `wpscan`, `wafw00f`, `whatweb`
- Linux : `hydra`, `sshpass`, `responder`, `chisel`, `ligolo-proxy`, `socat`
- SQL : `mysql`, `psql`, `redis-cli`, `mongosh`, `mongodump`
- Triage local / helpers : `file`, `readelf`, `strings`, `exiftool`, `binwalk`, `foremost`, `checksec`

> Best-effort : certains paquets varient selon la version de Kali. Ligolo-ng est téléchargé depuis sa release si absent.
> `cargo` est installé automatiquement. `rustup` n'est pas installé par défaut car il entre en conflit avec `cargo` sur Kali via APT.

### Structure du projet

```text
HTBTOOLBOX/
├── install.sh              ← bootstrap complet (apt + pipx + releases)
├── start.sh                ← lanceur (crée .venv, démarre uvicorn)
├── server.py               ← backend FastAPI + WebSocket (5000+ lignes)
├── index.html              ← SPA, zéro dépendance externe (5000+ lignes)
├── htbtoolbox.sh           ← script historique AD/HTB (toujours supporté)
├── catalog/
│   ├── modules.json        ← 91 outils catalogués + métadonnées FR/EN
│   └── profiles.json       ← profils de sélection FR/EN
├── config.example.json     ← template versionné
├── config.local.json       ← config locale (ignorée par Git)
├── requirements.txt        ← fastapi + uvicorn + websockets
└── loot/
    └── <domain>/           ← sorties triées par domaine cible
        ├── parsed/runs/    ← historique horodaté JSON
        ├── adcs/ kerberos/ bloodhound/ smb_shares/ …
        └── attack_checks/
```

### Sécurité & secrets

- Le backend écoute sur `127.0.0.1` par défaut.
- `config.local.json` contient tes secrets locaux — il est **ignoré par Git**.
- `config.example.json` est le template versionné (vide de secrets).
- Les mots de passe ne sont **jamais** persistés par `save_config`.
- Les mots de passe sont masqués dans l'output terminal.
- N'expose pas `--host 0.0.0.0` sur un réseau non maîtrisé.

### Commandes terminal intégrées

```text
TARGET=10.129.x.x       # changer la cible
DOMAIN=corp.htb         # changer le domaine
DC=DC01.corp.htb        # changer le DC
USER=john               # changer le user
PASS=P@ssw0rd           # changer le mot de passe
TYPE=linux              # windows | linux | web | hybrid
MODE=htb                # safe | htb | enterprise
run                     # lancer la sélection
stop                    # arrêter le run
profile=htb             # appliquer un profil de groupes
loot                    # vue loot
clear / help
```

### Raccourcis

| Touche | Action |
|--------|--------|
| `/` | Focus sur le terminal |
| `Ctrl+L` | Effacer le terminal |

### Pour aller plus loin

- 📖 **[GUIDE.md](GUIDE.md)** : guide utilisateur assisté, pas à pas
- 🧙 **Wizard** dans l'UI : sélecteur de type + preset en 3 clics
- 📚 **Playbook** : stratégie recommandée pour la box en cours

### Dépannage express

| Problème | Solution |
|----------|----------|
| `claude: command not found` | Claude Code CLI non installé (optionnel) |
| `rustscan` pas trouvé | Relancer `./install.sh` ou `./install_missing.sh` |
| Modules ne s'affichent pas | Le catalog JSON est invalide — `python3 -c "import json; json.load(open('catalog/modules.json'))"` |
| Backend injoignable | Vérifier que `./start.sh` tourne, port 8765 libre |
| WebSocket disconnects | Rechargement navigateur ou `Ctrl+C` puis `./start.sh` |
| `ModuleNotFoundError` sur un script Impacket | Utiliser les wrappers `impacket-*` ou forcer `/usr/bin/python3` |

---

## 🇬🇧 English

Standalone web interface driving a **Windows / Linux / Web / Hybrid** pentest toolbox from Kali Linux. The project is designed to be cloned and installed **from-scratch** on a recent Kali in a few commands.

### What it does

- **A web browser = your operator console**: pick tools, run them, watch live output, browse the loot, analyze with Claude.
- **91 catalogued tools** in 14 groups: recon, SMB, LDAP, Kerberos, ADCS, BloodHound, post-auth, Linux privesc, Web, SQL, NTLM coercion, tunneling/pivot, plus advanced local triage helpers.
- **Guided wizard + Attack presets**: ready-made chains for `windows`, `linux`, `web`, and `hybrid`.
- **Operator playbook**: context-aware recommendations (target type × operating mode).
- **3 operating modes**: `safe` (stealthy), `htb` (aggressive lab), `enterprise` (tight opsec).
- **Auto-detect**: after a scan, relevant modules are ticked automatically based on open ports.
- **Auto-fill**: credentials extracted from outputs (NT hash, TGT, passwords) are automatically suggested.
- **Controlled parallelism**: up to 3 tools in parallel depending on context and mode.
- **Bilingual UI**: switch `Français / English` directly in the interface, with persistence in local config.

### From-scratch install on Kali

```bash
git clone <REPO_URL> HTBTOOLBOX
cd HTBTOOLBOX
chmod +x install.sh start.sh htbtoolbox.sh
./install.sh
./start.sh --open
```

UI at `http://127.0.0.1:8765`.

#### Install flags

```bash
./install.sh --with-ai      # add Anthropic client (loot AI analysis)
./install.sh --skip-tools   # prepare only backend + UI (no apt install)
```

#### Supplemental install

```bash
./install_missing.sh        # tries to add tools commonly missing on some Kali builds
```

This helper mainly targets `rustscan`, `mongosh`, `mongodump`, `sshpass`, `foremost`, `checksec`, and `cargo`.

#### Start flags

```bash
./start.sh                        # 127.0.0.1:8765
./start.sh --open                 # auto-open Firefox
./start.sh --host 0.0.0.0         # expose on network (⚠ careful)
./start.sh --port 9000            # change port
./start.sh --skip-bootstrap       # reuse existing .venv without checks
```

### Auto-installed tooling

`install.sh` installs via apt/pipx/GitHub releases:

- Scan: `nmap`, `rustscan`, `masscan`
- AD: `netexec`/`nxc`, `crackmapexec`, `smbclient`, `rpcclient`, `ldap-utils`, `kerbrute`
- Impacket, `bloodhound-python`, `certipy-ad`, `bloodyAD`, `ldapdomaindump`, `enum4linux-ng`
- Web: `ffuf`, `wfuzz`, `feroxbuster`, `gobuster`, `nikto`, `nuclei`, `sqlmap`, `wpscan`, `wafw00f`, `whatweb`
- Linux: `hydra`, `sshpass`, `responder`, `chisel`, `ligolo-proxy`, `socat`
- SQL: `mysql`, `psql`, `redis-cli`, `mongosh`, `mongodump`
- Local triage / helpers: `file`, `readelf`, `strings`, `exiftool`, `binwalk`, `foremost`, `checksec`

> Best-effort: packages vary per Kali version. Ligolo-ng is downloaded from its release if missing.
> `cargo` is installed automatically. `rustup` is intentionally not installed by default because it conflicts with `cargo` through Kali APT.

### Project layout

```text
HTBTOOLBOX/
├── install.sh              ← full bootstrap (apt + pipx + releases)
├── start.sh                ← launcher (builds .venv, starts uvicorn)
├── server.py               ← FastAPI + WebSocket backend (5000+ lines)
├── index.html              ← SPA, zero external deps (5000+ lines)
├── htbtoolbox.sh           ← legacy AD/HTB script (still supported)
├── catalog/
│   ├── modules.json        ← 91 catalogued tools + FR/EN metadata
│   └── profiles.json       ← FR/EN selection profiles
├── config.example.json     ← versioned template
├── config.local.json       ← local config (Git-ignored)
├── requirements.txt        ← fastapi + uvicorn + websockets
└── loot/
    └── <domain>/           ← per-target outputs
        ├── parsed/runs/    ← timestamped JSON history
        ├── adcs/ kerberos/ bloodhound/ smb_shares/ …
        └── attack_checks/
```

### Security & secrets

- Backend binds `127.0.0.1` by default.
- `config.local.json` holds your local secrets — **Git-ignored**.
- `config.example.json` is the versioned template (no secrets).
- Passwords are **never** persisted by `save_config`.
- Passwords are masked in terminal output.
- Don't expose `--host 0.0.0.0` on untrusted networks.

### Built-in terminal commands

```text
TARGET=10.129.x.x       # change target
DOMAIN=corp.htb         # change domain
DC=DC01.corp.htb        # change DC
USER=john               # change user
PASS=P@ssw0rd           # change password
TYPE=linux              # windows | linux | web | hybrid
MODE=htb                # safe | htb | enterprise
run                     # run selection
stop                    # stop run
profile=htb             # apply group profile
loot                    # switch to loot view
clear / help
```

### Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus terminal |
| `Ctrl+L` | Clear terminal |

### Next steps

- 📖 **[GUIDE.md](GUIDE.md)**: assisted user guide, step-by-step
- 🧙 **Wizard** in the UI: target type + preset picker in 3 clicks
- 📚 **Playbook**: recommended strategy for your current box

### Quick troubleshooting

| Issue | Fix |
|-------|-----|
| `claude: command not found` | Claude Code CLI not installed (optional) |
| `rustscan` missing | Re-run `./install.sh` or `./install_missing.sh` |
| Modules don't show | Catalog JSON invalid — `python3 -c "import json; json.load(open('catalog/modules.json'))"` |
| Backend unreachable | Check `./start.sh` is running and port 8765 is free |
| WebSocket disconnects | Reload browser or `Ctrl+C` and `./start.sh` |
| `ModuleNotFoundError` from an Impacket script | Use the `impacket-*` wrappers or force `/usr/bin/python3` |
