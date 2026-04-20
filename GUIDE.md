# HTB Toolbox — Guide utilisateur / User Guide

> 🇫🇷 [Français](#-guide-français) · 🇬🇧 [English](#-english-guide)
> 📘 README principal : [README.md](README.md)

---

## 🇫🇷 Guide français

Ce guide t'accompagne **pas à pas** pour tirer le maximum de HTB Toolbox sur une machine HackTheBox. Il part du principe que tu débutes avec l'outil.

### 🎯 Table des matières

1. [Démarrage en 5 minutes](#1-démarrage-en-5-minutes)
2. [Comprendre l'interface](#2-comprendre-linterface)
3. [Les 3 modes opératoires](#3-les-3-modes-opératoires)
4. [Les 5 types de cible](#4-les-5-types-de-cible)
5. [Workflow recommandé sur HTB](#5-workflow-recommandé-sur-htb)
6. [Le Wizard : 3 clics pour démarrer](#6-le-wizard--3-clics-pour-démarrer)
7. [Les Presets d'attaque](#7-les-presets-dattaque)
8. [Le Playbook opérateur](#8-le-playbook-opérateur)
9. [Chaînage auto et auto-détection](#9-chaînage-auto-et-auto-détection)
10. [Gérer les credentials découverts](#10-gérer-les-credentials-découverts)
11. [Les daemons (Responder, chisel, ligolo…)](#11-les-daemons)
12. [Mode Challenge CTF](#12-mode-challenge-ctf)
13. [Analyse IA du loot avec Claude](#13-analyse-ia-du-loot-avec-claude)
14. [FAQ et pièges à éviter](#14-faq-et-pièges-à-éviter)

---

### 1. Démarrage en 5 minutes

```bash
cd ~/HTB/HTBTOOLBOX
./start.sh --open
```

Firefox s'ouvre sur `http://127.0.0.1:8765`. Tu vois :

- **Barre du haut** : état backend, horloge cible, boutons `🔑 Identifiants`, `🪄 Wizard`, `💾 Sauver`.
- **Sidebar gauche** : champs cible (IP, domaine, user, password), puis la liste des **groupes de modules**.
- **Panel central** : le **terminal** qui affiche les sorties en temps réel.
- **Panel droit** : `Résultats`, `Loot`, `Timeline`, `Credentials`, `Playbook`, `Analyse IA`.

**Premier lancement :**

1. Clique `🔑 Identifiants` → renseigne `IP cible`, `Domaine`, `DC (FQDN)`, `Utilisateur` si tu en as un.
2. Clique `🪄 Wizard` → choisis le type de box → sélectionne un preset → `Appliquer + Lancer`.
3. Regarde les outils s'enchaîner dans le terminal.
4. Dès qu'un hash ou un credential apparaît, une **toast** te propose de l'enregistrer.

---

### 2. Comprendre l'interface

#### Vue `Modules` (principale)

- Chaque **groupe** (SMB, LDAP, Kerberos…) est un bandeau pliable.
- Le **toggle ✓/✗** à droite du bandeau active/désactive le groupe.
- Les **outils** à l'intérieur se cochent individuellement.
- Les outils `[noisy]` sont bruyants → masqués en mode `safe`/`enterprise`.
- Les outils `[daemon]` (Responder, chisel…) occupent le slot d'exécution tant qu'on ne les stoppe pas.

#### Vue `Résultats`

Compteurs auto-extraits des sorties : **AS-REP roastables, Kerberoastables, SMB signing off, ADCS ESC**, etc.

#### Vue `Loot`

Navigateur de fichiers sur `loot/<domain>/` — tu peux lire les JSON parsés, les hashes, les rapports nmap.

#### Vue `Credentials`

Liste des users/passwords/hashes que tu as sauvegardés. Clique sur un user pour le **réinjecter dans la config active**.

#### Vue `Timeline`

Historique horodaté de tous les runs de la session.

#### Vue `Playbook`

**Recommandations adaptées** au contexte : type de cible détecté × mode opératoire. C'est le cerveau de l'outil.

---

### 3. Les 3 modes opératoires

Change le mode via le bouton dans la barre du haut ou `MODE=…` dans le terminal.

| Mode | Objectif | Bruit | Parallélisme typique |
|------|----------|-------|----------------------|
| `safe` | Recon discrète, pas de bruteforce | Faible | 1-2 |
| `htb` | Labo HTB, agressif, fuzzing permis | Moyen-haut | 2-3 |
| `enterprise` | Pentest réel avec opsec serrée | Très faible | 1-2 |

**En mode `enterprise`** certains outils sont **bloqués** : coercition NTLM, ffuf massif, sqlmap, nikto… Le but est de ressembler à un vrai attaquant discret.

---

### 4. Les 5 types de cible

| Type | Quand l'utiliser | Modules principaux |
|------|------------------|--------------------|
| `windows` | Active Directory, DC, serveur Windows | SMB, LDAP, Kerberos, ADCS, BloodHound |
| `linux` | Serveur Linux seul | SSH, NFS, HTTP fingerprint, privesc |
| `web` | Application web pure | TLS, dirs, vhosts, nuclei, sqlmap |
| `hybrid` | Box mixte (ex: AD + app web) | Tous les groupes pertinents |
| `challenge` | Challenges HTB Academy (pas une box) | Triage CTF (web/pwn/forensics) |

Le Wizard choisit automatiquement les bons groupes selon le type — pas besoin de tout sélectionner à la main.

---

### 5. Workflow recommandé sur HTB

Le flow optimal, chronométré sur une box HTB type :

```text
⏱ T+0        Démarrer l'UI + renseigner IP cible
⏱ T+30s      rustscan_fast (scan 65k ports en 30s)
⏱ T+1min     Auto-check des modules basé sur les ports
⏱ T+2min     nmap_targeted (-sC -sV sur les ports ouverts)
⏱ T+3min     hosts_autoconf (ajoute DC01.corp.htb à /etc/hosts)
⏱ T+4min     Preset « HTB AD quick win » : SMB/LDAP anonymes + AS-REP
⏱ T+10min    Si credentials trouvés → auto-chain (bloodhound, kerberoast)
⏱ T+20min    Analyse BloodHound + Playbook suggère les chemins
```

**Règle d'or** : ne commence pas par `nmap_baseline` (le -A). Il est **10× plus lent** que `rustscan_fast + nmap_targeted`.

---

### 6. Le Wizard : 3 clics pour démarrer

Bouton `🪄 Wizard` en haut.

**Étape 1** — Choisis le type de cible (windows / linux / web / hybrid / challenge).
**Étape 2** — Choisis un preset (voir section 7).
**Étape 3** — Options :

- `Appliquer` : coche les modules dans l'UI mais ne lance rien.
- `Appliquer + Lancer` : enchaîne immédiatement.

Le Wizard **analyse le contexte** (ports déjà détectés, credentials présents) et met en surbrillance le preset recommandé.

---

### 7. Les Presets d'attaque

| Preset | Pour quoi | Outils enchaînés |
|--------|-----------|------------------|
| **HTB AD quick win** | Box AD classique | rustscan → nmap → hosts → SMB anon → LDAP anon → AS-REP |
| **Foothold** | Box hybride, tu cherches l'entrée | rustscan → nmap → web + SMB + LDAP + SSH + WinRM |
| **Web focus** | Box 100% web | rustscan → web enum → TLS → robots → techno → ffuf dirs + vhost |
| **Linux focus** | Box Linux pure | rustscan → SSH → NFS → HTTP fingerprint → services |
| **Challenge triage** | CTF inconnu | file → archive → strings → exiftool → binwalk |
| **Challenge pwn** | ELF à reverse | file → checksec → readelf → strings |
| **Challenge forensics** | Fichier disque/image | file → exiftool → binwalk → foremost |
| **Challenge web** | URL CTF web | HTTP probe → whatweb → robots → dirs → params |

Tu peux **combiner plusieurs presets** : applique « HTB AD quick win » puis « Web focus » si le port 80 répond aussi.

---

### 8. Le Playbook opérateur

Vue `Playbook`. L'outil **te dit quoi faire** selon le contexte.

Exemple type sur une box Windows en mode `htb` :

- **Objectifs** : Monter la carte AD vite / déclencher les chemins auth utiles / chercher le foothold le plus court
- **Focus** : Preset « HTB AD quick win » / enum4linux-ng + LDAP + Kerberos / ADCS + BloodHound dès que des creds existent
- **Éviter** : Lancer tout le post-auth trop tôt

Le Playbook s'adapte à **chaque combinaison** (5 types × 3 modes = 15 configurations).

---

### 9. Chaînage auto et auto-détection

#### Auto-check des modules post-scan

Après `rustscan_fast` ou `nmap_targeted`, une toast apparaît avec les **modules suggérés** d'après les ports ouverts :

- Port 445 → SMB + BloodHound
- Port 389/636 → LDAP
- Port 88 → Kerberos
- Port 3306 → MySQL, etc.

Clique `Activer les modules` → tout est coché d'un coup.

#### Auto-hosts

L'outil `hosts_autoconf` lit la sortie nmap, extrait les FQDN (ex : `DC01.corp.htb`) et les ajoute à `/etc/hosts` via sudo. Évite les erreurs Kerberos dues à la résolution DNS.

#### Auto-chain credentials

Dès qu'un **hash NT** ou un **mot de passe** est détecté dans une sortie, une toast te le propose. Accepte → il est sauvegardé dans les credentials et peut être réinjecté en un clic dans la config active.

---

### 10. Gérer les credentials découverts

1. Vue `Credentials` → tu vois tous les comptes trouvés depuis le début de la session.
2. Chaque ligne affiche : `user`, `password/hash`, `source` (outil qui l'a trouvé), `note`.
3. Clique un compte → **réinjecte** dans la config active (user + password/nt_hash).
4. Relance les modules authentifiés → l'outil utilise ces credentials.

**Astuce** : sur HTB, dès qu'un user est trouvé, lance `getnpusers_asrep` et `getuserspns_kerberoast` — ce sont des gains gratuits.

---

### 11. Les daemons

Certains outils **tournent en continu** (Responder écoute, chisel maintient un tunnel). Dans l'UI ils sont marqués **[daemon]**.

- Quand un daemon tourne, la carte de l'outil affiche un **badge 🔴 actif** clignotant.
- Le bouton `▶` devient `■` (stop).
- Pendant qu'un daemon tourne, **un seul** daemon peut être actif à la fois.
- Les outils daemon disponibles : `responder_listen`, `ntlmrelayx_run`, `ntlmrelayx_relay`, `chisel_server`, `ligolo_server`, `socat_fwd`.

---

### 12. Mode Challenge CTF

Pour les challenges HTB Academy (pas des boxes) :

1. Type de cible = `challenge`
2. Catégorie (`web`, `pwn`, `reverse`, `crypto`, `forensics`, `osint`, `misc`)
3. `Fichier / dossier / URL` du challenge dans le champ dédié
4. Lance un preset `Challenge triage` → enchaîne les outils de triage
5. Selon le signal, bascule sur `Challenge pwn`, `Challenge forensics`, `Challenge web`…

Le loot est rangé dans `loot/output/challenge/`.

---

### 13. Analyse IA du loot avec Claude

1. Installe le client : `./install.sh --with-ai`
2. Vue `Analyse IA` → colle ta clé Anthropic (`sk-ant-api03-…`)
3. Sauvegarde : elle est stockée dans `config.local.json`
4. Choisis un sous-dossier (`adcs`, `kerberos`, `bloodhound`, etc. ou tout le loot)
5. Clique `✦ Analyser le loot` → Claude lit les fichiers et te propose un chemin d'attaque concret.

---

### 14. FAQ et pièges à éviter

**Q. L'outil ne trouve pas mon scan nmap pour l'auto-check.**
→ Lance `rustscan_fast` (ou `nmap_baseline` / `nmap_targeted`), attend qu'il termine, puis l'auto-check se déclenche tout seul.

**Q. Les modules LDAP/SMB/Kerberos sont grisés.**
→ Tu es sans credentials. Lance d'abord les modules `*_anon` ou `*_probe`. Une fois un credential trouvé, ils deviennent dispo.

**Q. Le terminal affiche `[!] sshpass manquant`.**
→ `sudo apt install sshpass`. C'est requis pour les outils Linux privesc qui passent par SSH.

**Q. `rustscan: command not found`.**
→ `cargo install rustscan` ou `apt install rustscan`. Fallback auto : nmap -F (top 100 ports).

**Q. Le wizard propose toujours le même preset.**
→ Le wizard suit le contexte détecté. Change manuellement le type de cible si nécessaire.

**Q. Comment relancer depuis zéro sur une nouvelle box ?**
→ Bouton `Reset session` dans la barre — efface le loot du domaine en cours + remet la config à zéro.

**Q. Le backend s'est arrêté sans prévenir.**
→ Regarde la sortie de `./start.sh` dans le terminal Kali. Exception Python la plupart du temps — copie-la si tu ouvres un ticket.

**Q. Mes secrets sont-ils dans Git ?**
→ Non. `config.local.json` est `.gitignore`. Seul `config.example.json` (vide) est versionné.

---

## 🇬🇧 English Guide

This guide walks you **step-by-step** through HTB Toolbox on a HackTheBox machine. It assumes you're new to the tool.

### 🎯 Table of Contents

1. [5-minute start](#1-5-minute-start)
2. [Understanding the UI](#2-understanding-the-ui)
3. [The 3 operating modes](#3-the-3-operating-modes)
4. [The 5 target types](#4-the-5-target-types)
5. [Recommended HTB workflow](#5-recommended-htb-workflow)
6. [The Wizard: 3 clicks to start](#6-the-wizard-3-clicks-to-start)
7. [Attack presets](#7-attack-presets)
8. [The operator Playbook](#8-the-operator-playbook)
9. [Auto-chain and auto-detect](#9-auto-chain-and-auto-detect)
10. [Managing discovered credentials](#10-managing-discovered-credentials)
11. [Daemons (Responder, chisel, ligolo…)](#11-daemons)
12. [Challenge CTF mode](#12-challenge-ctf-mode)
13. [Claude AI loot analysis](#13-claude-ai-loot-analysis)
14. [FAQ and common pitfalls](#14-faq-and-common-pitfalls)

---

### 1. 5-minute start

```bash
cd ~/HTB/HTBTOOLBOX
./start.sh --open
```

Firefox opens `http://127.0.0.1:8765`. You see:

- **Top bar**: backend status, target clock, `🔑 Credentials`, `🪄 Wizard`, `💾 Save` buttons.
- **Left sidebar**: target fields (IP, domain, user, password), then the **module groups** list.
- **Center panel**: the live **terminal** with real-time output.
- **Right panel**: `Results`, `Loot`, `Timeline`, `Credentials`, `Playbook`, `AI Analysis`.

**First run:**

1. Click `🔑 Credentials` → fill `target IP`, `domain`, `DC (FQDN)`, `user` if you have one.
2. Click `🪄 Wizard` → pick box type → pick a preset → `Apply + Run`.
3. Watch tools chain in the terminal.
4. When a hash or credential shows up, a **toast** suggests saving it.

---

### 2. Understanding the UI

#### `Modules` view (main)

- Each **group** (SMB, LDAP, Kerberos…) is a collapsible panel.
- The **✓/✗ toggle** on the right enables/disables the group.
- **Tools** are ticked individually.
- `[noisy]` tools are suppressed in `safe`/`enterprise` mode.
- `[daemon]` tools (Responder, chisel…) occupy the execution slot until stopped.

#### `Results` view

Auto-extracted counters: **AS-REP roastable, Kerberoastable, SMB signing off, ADCS ESC**, etc.

#### `Loot` view

File browser over `loot/<domain>/` — read parsed JSON, hashes, nmap reports.

#### `Credentials` view

Saved users/passwords/hashes. Click a user to **reinject into the active config**.

#### `Timeline` view

Timestamped history of all session runs.

#### `Playbook` view

**Context-aware recommendations**: detected target type × operating mode. This is the brain of the tool.

---

### 3. The 3 operating modes

Change via the top-bar button or `MODE=…` in the terminal.

| Mode | Goal | Noise | Typical parallelism |
|------|------|-------|---------------------|
| `safe` | Stealthy recon, no bruteforce | Low | 1-2 |
| `htb` | HTB lab, aggressive, fuzzing allowed | Medium-high | 2-3 |
| `enterprise` | Real engagement, tight opsec | Very low | 1-2 |

In `enterprise` mode, some tools are **blocked**: NTLM coercion, massive ffuf, sqlmap, nikto… Stays close to a stealthy real-world attacker.

---

### 4. The 5 target types

| Type | When to use | Main modules |
|------|-------------|--------------|
| `windows` | Active Directory, DC, Windows server | SMB, LDAP, Kerberos, ADCS, BloodHound |
| `linux` | Standalone Linux server | SSH, NFS, HTTP fingerprint, privesc |
| `web` | Pure web app | TLS, dirs, vhosts, nuclei, sqlmap |
| `hybrid` | Mixed box (e.g. AD + web app) | All relevant groups |
| `challenge` | HTB Academy challenges (not a box) | CTF triage (web/pwn/forensics) |

The Wizard auto-selects matching groups — no manual hunting.

---

### 5. Recommended HTB workflow

Optimal flow, clocked on a typical HTB box:

```text
⏱ T+0        Start UI + set target IP
⏱ T+30s      rustscan_fast (65k-port scan in 30s)
⏱ T+1min     Auto-check modules based on open ports
⏱ T+2min     nmap_targeted (-sC -sV on open ports only)
⏱ T+3min     hosts_autoconf (adds DC01.corp.htb to /etc/hosts)
⏱ T+4min     Preset "HTB AD quick win": anon SMB/LDAP + AS-REP
⏱ T+10min    If creds found → auto-chain (bloodhound, kerberoast)
⏱ T+20min    BloodHound analysis + Playbook suggests paths
```

**Golden rule**: don't start with `nmap_baseline` (-A). It's **10× slower** than `rustscan_fast + nmap_targeted`.

---

### 6. The Wizard: 3 clicks to start

`🪄 Wizard` button at the top.

**Step 1** — Pick target type (windows / linux / web / hybrid / challenge).
**Step 2** — Pick a preset (see section 7).
**Step 3** — Options:

- `Apply`: tick the modules in the UI but don't run.
- `Apply + Run`: immediately chain them.

The Wizard **analyzes context** (already detected ports, existing credentials) and highlights the recommended preset.

---

### 7. Attack presets

| Preset | For | Chained tools |
|--------|-----|---------------|
| **HTB AD quick win** | Classic AD box | rustscan → nmap → hosts → SMB anon → LDAP anon → AS-REP |
| **Foothold** | Hybrid box, hunting entry | rustscan → nmap → web + SMB + LDAP + SSH + WinRM |
| **Web focus** | Pure web box | rustscan → web enum → TLS → robots → tech → ffuf dirs + vhost |
| **Linux focus** | Pure Linux box | rustscan → SSH → NFS → HTTP fingerprint → services |
| **Challenge triage** | Unknown CTF | file → archive → strings → exiftool → binwalk |
| **Challenge pwn** | ELF to reverse | file → checksec → readelf → strings |
| **Challenge forensics** | Disk/image file | file → exiftool → binwalk → foremost |
| **Challenge web** | CTF web URL | HTTP probe → whatweb → robots → dirs → params |

You can **combine presets**: apply "HTB AD quick win" then "Web focus" if port 80 is also up.

---

### 8. The operator Playbook

`Playbook` view. The tool **tells you what to do** based on context.

Sample output on a Windows box in `htb` mode:

- **Objectives**: Map the AD fast / trigger useful auth paths early / find the shortest foothold
- **Focus**: Preset "HTB AD quick win" / enum4linux-ng + LDAP + Kerberos / ADCS + BloodHound as soon as creds exist
- **Avoid**: Firing all post-auth too early

The Playbook adapts to **each combination** (5 types × 3 modes = 15 configurations).

---

### 9. Auto-chain and auto-detect

#### Auto-check post-scan

After `rustscan_fast` or `nmap_targeted`, a toast shows **suggested modules** based on open ports:

- Port 445 → SMB + BloodHound
- Port 389/636 → LDAP
- Port 88 → Kerberos
- Port 3306 → MySQL, etc.

Click `Activate modules` → everything gets ticked.

#### Auto-hosts

The `hosts_autoconf` tool reads nmap output, extracts FQDNs (e.g. `DC01.corp.htb`) and adds them to `/etc/hosts` via sudo. Prevents Kerberos failures caused by DNS resolution.

#### Credential auto-chain

When a **NT hash** or **password** is detected in output, a toast suggests it. Accept → saved to credentials, reinjectable in one click into the active config.

---

### 10. Managing discovered credentials

1. `Credentials` view → all accounts found since session start.
2. Each line: `user`, `password/hash`, `source` (discovering tool), `note`.
3. Click a row → **reinjects** into active config (user + password/nt_hash).
4. Re-run authenticated modules → they use these credentials.

**Tip**: on HTB, as soon as a user is found, run `getnpusers_asrep` and `getuserspns_kerberoast` — free wins.

---

### 11. Daemons

Some tools **run continuously** (Responder listens, chisel holds a tunnel). Marked **[daemon]** in the UI.

- When a daemon runs, its card shows a blinking **🔴 active** badge.
- The `▶` button becomes `■` (stop).
- While a daemon runs, **only one** daemon can be active at a time.
- Available daemon tools: `responder_listen`, `ntlmrelayx_run`, `ntlmrelayx_relay`, `chisel_server`, `ligolo_server`, `socat_fwd`.

---

### 12. Challenge CTF mode

For HTB Academy challenges (not boxes):

1. Target type = `challenge`
2. Category (`web`, `pwn`, `reverse`, `crypto`, `forensics`, `osint`, `misc`)
3. `File / folder / URL` of the challenge in the dedicated field
4. Run a `Challenge triage` preset → chains triage tools
5. Depending on signal, switch to `Challenge pwn`, `Challenge forensics`, `Challenge web`…

Loot is stored in `loot/output/challenge/`.

---

### 13. Claude AI loot analysis

1. Install client: `./install.sh --with-ai`
2. `AI Analysis` view → paste your Anthropic key (`sk-ant-api03-…`)
3. Save: stored in `config.local.json`
4. Pick a subfolder (`adcs`, `kerberos`, `bloodhound`, etc. or full loot)
5. Click `✦ Analyze loot` → Claude reads files and suggests a concrete attack path.

---

### 14. FAQ and common pitfalls

**Q. The tool can't find my nmap scan for auto-check.**
→ Run `rustscan_fast` (or `nmap_baseline` / `nmap_targeted`), wait for it to finish, auto-check fires on its own.

**Q. LDAP/SMB/Kerberos modules are greyed out.**
→ No credentials. Start with `*_anon` / `*_probe` modules. Once a credential is found, the rest unlock.

**Q. Terminal shows `[!] sshpass missing`.**
→ `sudo apt install sshpass`. Required for Linux privesc tools that use SSH.

**Q. `rustscan: command not found`.**
→ `cargo install rustscan` or `apt install rustscan`. Auto fallback: nmap -F (top 100 ports).

**Q. The wizard always proposes the same preset.**
→ The wizard follows detected context. Change target type manually if needed.

**Q. How do I reset for a new box?**
→ `Reset session` button in the top bar — clears the current domain's loot and resets config.

**Q. Backend crashed silently.**
→ Check `./start.sh` output in the Kali terminal. Usually a Python exception — copy it if you open a ticket.

**Q. Are my secrets in Git?**
→ No. `config.local.json` is `.gitignore`d. Only `config.example.json` (empty) is versioned.
