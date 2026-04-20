# HTB Toolbox

Interface web standalone pour piloter une boîte à outils de pentest `Windows / Linux / Web / Hybrid` et un mode `HTB Challenge` depuis Kali Linux.

Le projet est maintenant pensé pour être cloné depuis GitHub et installé `from scratch` sur une Kali récente.

## Installation from scratch sur Kali

```bash
git clone <REPO_URL> HTBTOOLBOX
cd HTBTOOLBOX
chmod +x install.sh start.sh htbtoolbox.sh
./install.sh
./start.sh --open
```

L'interface sera disponible sur `http://127.0.0.1:8765`.

## Ce que fait `install.sh`

- installe les prérequis système: `python3`, `python3-venv`, `pipx`, `git`, `curl`, `jq`, `unzip`
- crée un virtualenv local `.venv/`
- installe les dépendances Python du backend via `requirements.txt`
- crée `config.local.json` à partir de `config.example.json`
- tente d'installer automatiquement les outils offensifs manquants
- complète l'installation avec le moteur d'auto-install interne de `htbtoolbox.sh`

## Outils installés automatiquement si absents

Le bootstrap essaie d'installer ou de préparer notamment:

- `nmap`, `rustscan`, `masscan`
- `netexec` / `nxc`, `crackmapexec`, `smbclient`, `rpcclient`, `ldapsearch`
- `impacket`, `bloodhound-python`, `certipy-ad`, `bloodyAD`, `ldapdomaindump`, `enum4linux-ng`
- `file`, `readelf`, `strings`, `exiftool`, `binwalk`, `foremost`, `checksec`
- `ffuf`, `wfuzz`, `feroxbuster`, `gobuster`, `nikto`, `nuclei`, `sqlmap`, `wpscan`, `wafw00f`, `whatweb`
- `hydra`, `responder`, `chisel`, `ligolo-proxy`, `socat`
- `kerbrute`, `ntpdate`, `snmpwalk`, `onesixtyone`
- `smbmap`, `evil-winrm`, `psql`, `mysql`, `redis-cli`, `mongosh`, `mongodump`

Important:
- l'installation est `best effort`: certains paquets peuvent varier selon la version de Kali
- les outils vraiment optionnels ou non packagés proprement peuvent nécessiter une installation manuelle complémentaire
- `ligolo-proxy` est téléchargé depuis sa release GitHub si absent

## Démarrage

```bash
./start.sh
./start.sh --open
./start.sh --host 0.0.0.0 --port 9000
```

Options:

```bash
./start.sh --skip-bootstrap   # utilise le .venv existant sans vérification
./install.sh --with-ai        # ajoute le client Anthropic
./install.sh --skip-tools     # prépare seulement le backend/UI
```

## Structure du projet

```text
HTBTOOLBOX/
├── install.sh
├── start.sh
├── server.py
├── htbtoolbox.sh
├── index.html
├── requirements.txt
├── config.example.json
├── config.local.json        # généré localement, ignoré par git
├── catalog/
│   ├── modules.json
│   └── profiles.json
└── loot/
```

## Configuration locale

Le projet versionne `config.example.json` et utilise `config.local.json` en local.

`config.local.json` est ignoré par Git pour éviter de publier:

- mots de passe
- `sudo_password`
- hash NT
- chemins de `ccache`
- infos de session locales

Le backend ne persiste plus les secrets lors du `save_config`.

## Développement / publication GitHub

Avant de pousser le dépôt:

```bash
rm -rf loot __pycache__ .venv
cp config.example.json config.local.json   # si besoin d'un squelette local propre
```

Fichiers ignorés par Git:

- `.venv/`
- `loot/`
- `timeline.json`
- `config.local.json`
- `__pycache__/`

## Modules et usage

L'interface couvre la recon, l'énumération et les chaînes d'attaque sur:

- Active Directory / Windows
- Linux
- Web
- SQL
- coercition / relay
- tunneling / pivot

Elle inclut aussi:

- presets d'attaque
- wizard
- playbook opérateur
- adaptation au contexte détecté
- mode opératoire `safe / htb / realiste entreprise`
- parallélisme contrôlé
- manifests de run
- historique et loot viewer
- mode `challenge` pour `web / pwn / reverse / crypto / forensics / osint / misc`

## Sécurité

- le backend écoute sur `127.0.0.1` par défaut
- les secrets ne sont pas sauvegardés dans la config persistée
- n'expose pas le service sur une interface publique sans cloisonnement
- certains outils lancés par l'UI sont bruyants: utilise le mode `safe` ou `realiste entreprise` si besoin
# HTBTOOLBOX
