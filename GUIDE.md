# HTB Toolbox — Guide utilisateur / User Guide

> 🇫🇷 [Français](#-guide-français) · 🇬🇧 [English](#-english-guide)
> 📘 README principal : [README.md](README.md)

---

## 🇫🇷 Guide français

Ce guide t'accompagne **pas à pas** pour tirer le maximum de HTB Toolbox sur une machine HackTheBox. Il part du principe que tu débutes avec l'outil.

### 🎯 Table des matières

1. [Démarrage en 5 minutes](#1-démarrage-en-5-minutes)
2. [Comprendre l'interface](#2-comprendre-linterface)
3. [Choisir la langue de l'interface](#3-choisir-la-langue-de-linterface)
4. [Les 3 modes opératoires](#4-les-3-modes-opératoires)
5. [Les 4 types de cible](#5-les-4-types-de-cible)
6. [Workflow recommandé sur HTB](#6-workflow-recommandé-sur-htb)
7. [Le Wizard : 3 clics pour démarrer](#7-le-wizard--3-clics-pour-démarrer)
8. [Les Presets d'attaque](#8-les-presets-dattaque)
9. [Comprendre les outils et leurs résultats utiles](#9-comprendre-les-outils-et-leurs-résultats-utiles)
10. [Le Playbook opérateur](#10-le-playbook-opérateur)
11. [Chaînage auto et auto-détection](#11-chaînage-auto-et-auto-détection)
12. [Gérer les credentials découverts](#12-gérer-les-credentials-découverts)
13. [Les daemons (Responder, chisel, ligolo…)](#13-les-daemons)
14. [Analyse IA du loot avec Claude](#14-analyse-ia-du-loot-avec-claude)
14bis. [Prévisualiser avant de lancer](#14bis-prévisualiser-avant-de-lancer)
14ter. [Notes par box](#14ter-notes-par-box)
15. [FAQ et pièges à éviter](#15-faq-et-pièges-à-éviter)

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
- **Panel droit** : `Résultats`, `Loot`, `Timeline`, `Credentials`, `Playbook`, `Analyse IA`, `📝 Notes` (par box).

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

### 3. Choisir la langue de l'interface

Le sélecteur `Français / English` est en haut de l'interface.

- La langue choisie est **sauvegardée** dans `config.local.json`.
- Les libellés UI, les vues, les toasts et le catalogue des outils suivent ce choix.
- Le backend ne change pas de comportement selon la langue, seule la présentation change.

---

### 4. Les 3 modes opératoires

Change le mode via le bouton dans la barre du haut ou `MODE=…` dans le terminal.

| Mode | Objectif | Bruit | Parallélisme typique |
|------|----------|-------|----------------------|
| `safe` | Recon discrète, pas de bruteforce | Faible | 1-2 |
| `htb` | Labo HTB, agressif, fuzzing permis | Moyen-haut | 2-3 |
| `enterprise` | Pentest réel avec opsec serrée | Très faible | 1-2 |

**En mode `enterprise`** certains outils sont **bloqués** : coercition NTLM, ffuf massif, sqlmap, nikto… Le but est de ressembler à un vrai attaquant discret.

---

### 5. Les 4 types de cible

| Type | Quand l'utiliser | Modules principaux |
|------|------------------|--------------------|
| `windows` | Active Directory, DC, serveur Windows | SMB, LDAP, Kerberos, ADCS, BloodHound |
| `linux` | Serveur Linux seul | SSH, NFS, HTTP fingerprint, privesc |
| `web` | Application web pure | TLS, dirs, vhosts, nuclei, sqlmap |
| `hybrid` | Box mixte (ex: AD + app web) | Tous les groupes pertinents |

Le Wizard choisit automatiquement les bons groupes selon le type — pas besoin de tout sélectionner à la main.

---

### 6. Workflow recommandé sur HTB

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

### 7. Le Wizard : 3 clics pour démarrer

Bouton `🪄 Wizard` en haut.

**Étape 1** — Choisis le type de cible (windows / linux / web / hybrid).
**Étape 2** — Choisis un preset (voir section 7).
**Étape 3** — Options :

- `Appliquer` : coche les modules dans l'UI mais ne lance rien.
- `Appliquer + Lancer` : enchaîne immédiatement.

Le Wizard **analyse le contexte** (ports déjà détectés, credentials présents) et met en surbrillance le preset recommandé.

---

### 8. Les Presets d'attaque

| Preset | Pour quoi | Outils enchaînés |
|--------|-----------|------------------|
| **HTB AD quick win** | Box AD classique | rustscan → nmap → hosts → SMB anon → LDAP anon → AS-REP |
| **Foothold** | Box hybride, tu cherches l'entrée | rustscan → nmap → web + SMB + LDAP + SSH + WinRM |
| **Web focus** | Box 100% web | rustscan → web enum → TLS → robots → techno → ffuf dirs + vhost |
| **Linux focus** | Box Linux pure | rustscan → SSH → NFS → HTTP fingerprint → services |

Tu peux **combiner plusieurs presets** : applique « HTB AD quick win » puis « Web focus » si le port 80 répond aussi.

---

### 9. Comprendre les outils et leurs résultats utiles

Le but n'est pas seulement de lancer des commandes, mais de savoir **ce que chaque outil peut t'apporter**. Voici la lecture opérateur des plus importants.

| Outil | À quoi il sert | Ce qui est réellement utile |
|------|-----------------|-----------------------------|
| `rustscan_fast` | Trouver vite les ports ouverts | Les ports ouverts eux-mêmes. Ils te disent **quoi lancer ensuite** : 88 = Kerberos, 389 = LDAP, 445 = SMB, 5985 = WinRM, 80/443 = Web. |
| `nmap_targeted` | Identifier précisément les services sur les ports ouverts | Le **nom du service**, la **version**, le **hostname/FQDN**, les scripts NSE intéressants. C'est souvent lui qui te révèle `DC01.corp.htb`, ADCS, WinRM, MSSQL ou un virtual host. |
| `hosts_autoconf` | Corriger la résolution DNS locale | Le renseignement utile est le **FQDN du DC ou du serveur**. Sans lui, Kerberos et parfois LDAP cassent. |
| `nxc smb` / `smbclient` | Lire l'exposition SMB | Ce qui compte : **nom de machine**, **domaine**, **OS**, **partages accessibles**, et surtout présence de `SYSVOL`, `NETLOGON` ou d'un share en lecture/écriture. |
| `ldap_anon_base` / `ldap_users_auth` | Lire l'annuaire AD | Les infos qui aident vraiment : **noms d'utilisateurs**, **groupes**, **description**, **OU**, **noms de machines**, et parfois des champs oubliés avec des passwords ou indices. |
| `GetNPUsers` / `ldap_asrep_candidates` | Trouver des users sans pré-auth Kerberos | Le vrai gain est la **liste des comptes AS-REP roastables** puis les **hashes** récupérables hors authentification. Très forte valeur sur HTB. |
| `GetUserSPNs` / `ldap_kerberoastable` | Sortir des hashes TGS crackables | Le résultat utile est le **hash Kerberoast** et le **service account** associé. Priorité aux comptes `sql`, `svc`, `backup`, `web` et similaires. |
| `kerbrute_userenum` | Valider l'existence d'utilisateurs AD | Ce qui t'intéresse est la **liste des usernames valides**. C'est utile pour AS-REP, password spray, Kerberoast et BloodHound. |
| `bloodhound-python` | Cartographier les chemins d'attaque AD | Les renseignements vraiment utiles sont les **edges exploitables** : `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AddMember`, `CanPSRemote`, `AdminTo`, `AllowedToAct`, chemins vers `Domain Admins`. |
| `enum4linux-ng` | Faire un résumé SMB/RPC lisible | Très utile pour récupérer vite **users**, **shares**, **policy**, **RID enum**, **machine/domain names** sans tout relire à la main. |
| `certipy find` | Identifier des faiblesses ADCS | Les résultats à guetter : **ESC1/ESC2/ESC3/ESC4...**, templates enrollables, SAN contrôlable, EKU client auth, droits d'inscription. |
| `winrm_checks` | Vérifier un accès shell Windows | Le point clé est : **WinRM accessible + credentials valides**. Si oui, tu tiens souvent un foothold immédiat via `evil-winrm`. |
| `whatweb` / `web_tech_detect` | Comprendre la stack web | Cherche le **framework**, le **CMS**, les **versions**, un **WAF**, des **headers** révélateurs, et les technos qui orientent tes wordlists et exploits. |
| `ffuf_dir_fast` / `ffuf_vhost` | Trouver des endpoints ou vhosts cachés | Les vrais gains sont les **hits anormaux** : `/admin`, `/backup`, `.git`, `.env`, API internes, `.bak`, `.old`, ou un **nouveau hostname**. |
| `nikto` / `nuclei` | Attraper rapidement des expositions connues | Garde surtout les **résultats actionnables** : fichiers sensibles, endpoints d'admin, CVE crédibles, méthodes HTTP dangereuses, mauvaises configs. |
| `linpeas` / checks privesc Linux | Chercher une escalade locale | Les résultats les plus précieux : **sudo sans mot de passe**, **SUID inhabituel**, **capabilities dangereuses**, **cron writable**, **credentials**, **docker group**. |

**Règle simple** : pour chaque outil, pose-toi toujours 3 questions.

1. Est-ce qu'il me donne un **nouvel accès** ?
2. Est-ce qu'il me donne un **nouvel identifiant** ou un **hash crackable** ?
3. Est-ce qu'il me donne un **nouveau chemin d'attaque** crédible ?

Si la réponse est non aux trois, la sortie est souvent secondaire.

---

### 10. Le Playbook opérateur

Vue `Playbook`. L'outil **te dit quoi faire** selon le contexte.

Exemple type sur une box Windows en mode `htb` :

- **Objectifs** : Monter la carte AD vite / déclencher les chemins auth utiles / chercher le foothold le plus court
- **Focus** : Preset « HTB AD quick win » / enum4linux-ng + LDAP + Kerberos / ADCS + BloodHound dès que des creds existent
- **Éviter** : Lancer tout le post-auth trop tôt

Le Playbook s'adapte à **chaque combinaison** (4 types × 3 modes = 12 configurations principales dans l'UI).

---

### 11. Chaînage auto et auto-détection

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

### 12. Gérer les credentials découverts

1. Vue `Credentials` → tu vois tous les comptes trouvés depuis le début de la session.
2. Chaque ligne affiche : `user`, `password/hash`, `source` (outil qui l'a trouvé), `note`.
3. Clique un compte → **réinjecte** dans la config active (user + password/nt_hash).
4. Relance les modules authentifiés → l'outil utilise ces credentials.

**Astuce** : sur HTB, dès qu'un user est trouvé, lance `getnpusers_asrep` et `getuserspns_kerberoast` — ce sont des gains gratuits.

**Dépannage Impacket** : si un script d'exemple Impacket renvoie `ModuleNotFoundError: No module named 'pyasn1'` ou `No module named 'impacket'`, tu es probablement dans le `.venv` du projet, alors que les scripts `/usr/share/doc/python3-impacket/examples/*.py` utilisent les dépendances du Python système. La bonne habitude est d'utiliser d'abord les wrappers Kali `impacket-*`, par exemple :

```bash
impacket-GetNPUsers -h
impacket-addcomputer -h
```

Si tu veux exécuter directement un exemple `.py`, force le Python système :

```bash
/usr/bin/python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -h
/usr/bin/python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -h
```

`install.sh` et `start.sh` créent maintenant aussi des wrappers dans `.venv/bin` pour éviter ce conflit quand le venv est actif.

**Conseil installation** : si `rustscan`, `mongosh`, `mongodump`, `foremost`, `checksec` ou `sshpass` manquent encore après l'installation principale, lance :

```bash
./install_missing.sh
```

---

### 13. Les daemons

Certains outils **tournent en continu** (Responder écoute, chisel maintient un tunnel). Dans l'UI ils sont marqués **[daemon]**.

- Quand un daemon tourne, la carte de l'outil affiche un **badge 🔴 actif** clignotant.
- Le bouton `▶` devient `■` (stop).
- Pendant qu'un daemon tourne, **un seul** daemon peut être actif à la fois.
- Les outils daemon disponibles : `responder_listen`, `ntlmrelayx_run`, `ntlmrelayx_relay`, `chisel_server`, `ligolo_server`, `socat_fwd`.

---

### 14. Analyse IA du loot avec Claude

1. Installe le client : `./install.sh --with-ai`
2. Vue `Analyse IA` → colle ta clé Anthropic (`sk-ant-api03-…`)
3. Sauvegarde : elle est stockée dans `config.local.json`
4. Choisis un sous-dossier (`adcs`, `kerberos`, `bloodhound`, etc. ou tout le loot)
5. Clique `✦ Analyser le loot` → Claude lit les fichiers et te propose un chemin d'attaque concret.

---

### 14bis. Prévisualiser avant de lancer

Le bouton `👁 Prévisualiser` dans la barre d'actions construit la commande réelle pour chaque outil coché, **sans l'exécuter**. La commande est affichée dans le terminal avec les secrets masqués (password, NT hash, sudo password).

Utile pour :

- Vérifier que l'auth choisie (ccache / hash / password) est bien celle qui sera utilisée.
- Valider les flags, le port web/SSH, le chemin de sortie.
- Adapter la commande à la main puis la copier-coller dans un autre terminal si besoin.

Les outils bloqués par le mode opératoire ou les prérequis (ports fermés, auth manquante) apparaissent en `[skip]` avec la raison.

---

### 14ter. Notes par box

Vue `📝 Notes` dans la nav. Une note **par domaine** (`cfg.domain`), stockée dans `loot/<domain>/notes.md`. Les notes voyagent donc avec le loot (backup, partage, export).

- **Éditeur markdown** avec auto-save (1,2 s après inactivité) + sauvegarde au blur.
- **Aperçu rendu** via le bouton `👁 Aperçu` : titres, code, listes formatés.
- **Rechargement automatique** quand tu changes de domaine dans la barre du haut.
- **Badge** sur la nav quand la box a des notes non vides.

Idéal pour noter les credentials glanés, les pistes à tester, une checklist, ou un writeup en construction pendant que tu progresses.

---

### 15. FAQ et pièges à éviter

**Q. L'outil ne trouve pas mon scan nmap pour l'auto-check.**
→ Lance `rustscan_fast` (ou `nmap_baseline` / `nmap_targeted`), attend qu'il termine, puis l'auto-check se déclenche tout seul.

**Q. Les modules LDAP/SMB/Kerberos sont grisés.**
→ Tu es sans credentials. Lance d'abord les modules `*_anon` ou `*_probe`. Une fois un credential trouvé, ils deviennent dispo.

**Q. Le terminal affiche `[!] sshpass manquant`.**
→ `sudo apt install sshpass`. C'est requis pour les outils Linux privesc qui passent par SSH.

**Q. `rustscan: command not found`.**
→ Relance `./install.sh` ou `./install_missing.sh`. Le script tente `apt`, puis fallback release GitHub si nécessaire.

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
3. [Choosing the interface language](#3-choosing-the-interface-language)
4. [The 3 operating modes](#4-the-3-operating-modes)
5. [The 4 target types](#5-the-4-target-types)
6. [Recommended HTB workflow](#6-recommended-htb-workflow)
7. [The Wizard: 3 clicks to start](#7-the-wizard-3-clicks-to-start)
8. [Attack presets](#8-attack-presets)
9. [Understanding tools and useful results](#9-understanding-tools-and-useful-results)
10. [The operator Playbook](#10-the-operator-playbook)
11. [Auto-chain and auto-detect](#11-auto-chain-and-auto-detect)
12. [Managing discovered credentials](#12-managing-discovered-credentials)
13. [Daemons (Responder, chisel, ligolo…)](#13-daemons)
14. [Claude AI loot analysis](#14-claude-ai-loot-analysis)
14bis. [Preview before running](#14bis-preview-before-running)
14ter. [Per-box notes](#14ter-per-box-notes)
15. [FAQ and common pitfalls](#15-faq-and-common-pitfalls)

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
- **Right panel**: `Results`, `Loot`, `Timeline`, `Credentials`, `Playbook`, `AI Analysis`, `📝 Notes` (per box).

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

### 3. Choosing the interface language

The `Français / English` selector is available at the top of the interface.

- The chosen language is **saved** in `config.local.json`.
- UI labels, views, toasts, and the tool catalog follow this choice.
- The backend behavior does not change with the language, only presentation does.

---

### 4. The 3 operating modes

Change via the top-bar button or `MODE=…` in the terminal.

| Mode | Goal | Noise | Typical parallelism |
|------|------|-------|---------------------|
| `safe` | Stealthy recon, no bruteforce | Low | 1-2 |
| `htb` | HTB lab, aggressive, fuzzing allowed | Medium-high | 2-3 |
| `enterprise` | Real engagement, tight opsec | Very low | 1-2 |

In `enterprise` mode, some tools are **blocked**: NTLM coercion, massive ffuf, sqlmap, nikto… Stays close to a stealthy real-world attacker.

---

### 5. The 4 target types

| Type | When to use | Main modules |
|------|-------------|--------------|
| `windows` | Active Directory, DC, Windows server | SMB, LDAP, Kerberos, ADCS, BloodHound |
| `linux` | Standalone Linux server | SSH, NFS, HTTP fingerprint, privesc |
| `web` | Pure web app | TLS, dirs, vhosts, nuclei, sqlmap |
| `hybrid` | Mixed box (e.g. AD + web app) | All relevant groups |

The Wizard auto-selects matching groups — no manual hunting.

---

### 6. Recommended HTB workflow

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

### 7. The Wizard: 3 clicks to start

`🪄 Wizard` button at the top.

**Step 1** — Pick target type (windows / linux / web / hybrid).
**Step 2** — Pick a preset (see section 7).
**Step 3** — Options:

- `Apply`: tick the modules in the UI but don't run.
- `Apply + Run`: immediately chain them.

The Wizard **analyzes context** (already detected ports, existing credentials) and highlights the recommended preset.

---

### 8. Attack presets

| Preset | For | Chained tools |
|--------|-----|---------------|
| **HTB AD quick win** | Classic AD box | rustscan → nmap → hosts → SMB anon → LDAP anon → AS-REP |
| **Foothold** | Hybrid box, hunting entry | rustscan → nmap → web + SMB + LDAP + SSH + WinRM |
| **Web focus** | Pure web box | rustscan → web enum → TLS → robots → tech → ffuf dirs + vhost |
| **Linux focus** | Pure Linux box | rustscan → SSH → NFS → HTTP fingerprint → services |

You can **combine presets**: apply "HTB AD quick win" then "Web focus" if port 80 is also up.

---

### 9. Understanding tools and useful results

The goal is not just to launch commands, but to understand **what each tool can actually give you**. Here's the operator view of the most useful ones.

| Tool | What it does | What is genuinely useful in the output |
|------|---------------|----------------------------------------|
| `rustscan_fast` | Finds open ports quickly | The **open ports** themselves. They tell you **what to run next**: 88 = Kerberos, 389 = LDAP, 445 = SMB, 5985 = WinRM, 80/443 = Web. |
| `nmap_targeted` | Precisely identifies services on open ports | The **service name**, **version**, **hostname/FQDN**, and useful NSE findings. This is often what reveals `DC01.corp.htb`, ADCS, WinRM, MSSQL, or a hidden virtual host. |
| `hosts_autoconf` | Fixes local DNS resolution | The useful information is the **DC/server FQDN**. Without it, Kerberos and sometimes LDAP will fail. |
| `nxc smb` / `smbclient` | Reads SMB exposure | What matters: **machine name**, **domain**, **OS**, **accessible shares**, and especially `SYSVOL`, `NETLOGON`, or any read/write share. |
| `ldap_anon_base` / `ldap_users_auth` | Reads the AD directory | Truly useful data: **usernames**, **groups**, **descriptions**, **OUs**, **computer names**, and sometimes forgotten fields containing passwords or hints. |
| `GetNPUsers` / `ldap_asrep_candidates` | Finds users with no Kerberos pre-auth | The real win is the **list of AS-REP roastable accounts** and then the **hashes** you can obtain without authentication. Very high value on HTB. |
| `GetUserSPNs` / `ldap_kerberoastable` | Extracts crackable TGS hashes | The useful result is the **Kerberoast hash** and the related **service account**. Prioritize accounts named `sql`, `svc`, `backup`, `web`, and similar. |
| `kerbrute_userenum` | Validates AD usernames | What matters is the **list of valid usernames**. Useful for AS-REP, password spray, Kerberoast, and BloodHound. |
| `bloodhound-python` | Maps AD attack paths | The really useful findings are **actionable edges**: `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AddMember`, `CanPSRemote`, `AdminTo`, `AllowedToAct`, and paths to `Domain Admins`. |
| `enum4linux-ng` | Gives a readable SMB/RPC summary | Very useful for quickly collecting **users**, **shares**, **policy**, **RID enum**, and **machine/domain names** without manually reading everything. |
| `certipy find` | Identifies ADCS weaknesses | Watch for **ESC1/ESC2/ESC3/ESC4...**, enrollable templates, controllable SAN, client auth EKU, and enrollment rights. |
| `winrm_checks` | Verifies a Windows shell path | The key point is: **WinRM reachable + valid credentials**. If yes, you often have an immediate foothold through `evil-winrm`. |
| `whatweb` / `web_tech_detect` | Understands the web stack | Look for the **framework**, **CMS**, **versions**, a **WAF**, revealing **headers**, and technologies that guide your wordlists and exploits. |
| `ffuf_dir_fast` / `ffuf_vhost` | Finds hidden endpoints or virtual hosts | The real wins are **unusual hits**: `/admin`, `/backup`, `.git`, `.env`, internal APIs, `.bak`, `.old`, or a **new hostname**. |
| `nikto` / `nuclei` | Quickly catches known exposures | Keep the **actionable results**: sensitive files, admin endpoints, credible CVEs, dangerous HTTP methods, bad configs. |
| `linpeas` / Linux privesc checks | Searches for local escalation | The most valuable findings are **passwordless sudo**, **unusual SUID**, **dangerous capabilities**, **writable cron**, **credentials**, **docker group**. |

**Simple rule**: for each tool, always ask yourself 3 questions.

1. Does it give me **new access**?
2. Does it give me a **new credential** or a **crackable hash**?
3. Does it give me a **new credible attack path**?

If the answer is no to all three, the output is often secondary.

---

### 10. The operator Playbook

`Playbook` view. The tool **tells you what to do** based on context.

Sample output on a Windows box in `htb` mode:

- **Objectives**: Map the AD fast / trigger useful auth paths early / find the shortest foothold
- **Focus**: Preset "HTB AD quick win" / enum4linux-ng + LDAP + Kerberos / ADCS + BloodHound as soon as creds exist
- **Avoid**: Firing all post-auth too early

The Playbook adapts to **each combination** (4 types × 3 modes = 12 main UI configurations).

---

### 11. Auto-chain and auto-detect

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

### 12. Managing discovered credentials

1. `Credentials` view → all accounts found since session start.
2. Each line: `user`, `password/hash`, `source` (discovering tool), `note`.
3. Click a row → **reinjects** into active config (user + password/nt_hash).
4. Re-run authenticated modules → they use these credentials.

**Tip**: on HTB, as soon as a user is found, run `getnpusers_asrep` and `getuserspns_kerberoast` — free wins.

**Impacket troubleshooting**: if an Impacket example script throws `ModuleNotFoundError: No module named 'pyasn1'` or `No module named 'impacket'`, you are likely inside the project's `.venv` while `/usr/share/doc/python3-impacket/examples/*.py` expects system Python dependencies. The best habit is to use Kali's `impacket-*` wrappers first, for example:

```bash
impacket-GetNPUsers -h
impacket-addcomputer -h
```

If you want to run an example `.py` directly, force system Python:

```bash
/usr/bin/python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -h
/usr/bin/python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -h
```

`install.sh` and `start.sh` now also create wrappers in `.venv/bin` to avoid this conflict while the venv is active.

**Install tip**: if `rustscan`, `mongosh`, `mongodump`, `foremost`, `checksec`, or `sshpass` are still missing after the main install, run:

```bash
./install_missing.sh
```

---

### 13. Daemons

Some tools **run continuously** (Responder listens, chisel holds a tunnel). Marked **[daemon]** in the UI.

- When a daemon runs, its card shows a blinking **🔴 active** badge.
- The `▶` button becomes `■` (stop).
- While a daemon runs, **only one** daemon can be active at a time.
- Available daemon tools: `responder_listen`, `ntlmrelayx_run`, `ntlmrelayx_relay`, `chisel_server`, `ligolo_server`, `socat_fwd`.

---

### 14. Claude AI loot analysis

1. Install client: `./install.sh --with-ai`
2. `AI Analysis` view → paste your Anthropic key (`sk-ant-api03-…`)
3. Save: stored in `config.local.json`
4. Pick a subfolder (`adcs`, `kerberos`, `bloodhound`, etc. or full loot)
5. Click `✦ Analyze loot` → Claude reads files and suggests a concrete attack path.

---

### 14bis. Preview before running

The `👁 Preview` button in the action bar builds the real command for each ticked tool **without executing it**. The command is echoed into the terminal with secrets masked (password, NT hash, sudo password).

Useful for:

- Confirming the auth chosen (ccache / hash / password) is the one that will actually be used.
- Validating flags, web/SSH port, output path.
- Tweaking the command manually and pasting it into another terminal if needed.

Tools blocked by the operating mode or prerequisites (closed ports, missing auth) show up as `[skip]` with the reason.

---

### 14ter. Per-box notes

`📝 Notes` view in the nav. One note **per domain** (`cfg.domain`), stored in `loot/<domain>/notes.md`. Notes therefore travel with the loot (backup, share, export).

- **Markdown editor** with auto-save (1.2s after idle) + save-on-blur.
- **Rendered preview** via the `👁 Preview` button: headings, code, lists.
- **Auto-reload** when you change the domain in the top bar.
- **Nav badge** when the current box has non-empty notes.

Great for writing down gleaned credentials, leads to test, a checklist, or a writeup-in-progress as you move forward.

---

### 15. FAQ and common pitfalls

**Q. The tool can't find my nmap scan for auto-check.**
→ Run `rustscan_fast` (or `nmap_baseline` / `nmap_targeted`), wait for it to finish, auto-check fires on its own.

**Q. LDAP/SMB/Kerberos modules are greyed out.**
→ No credentials. Start with `*_anon` / `*_probe` modules. Once a credential is found, the rest unlock.

**Q. Terminal shows `[!] sshpass missing`.**
→ `sudo apt install sshpass`. Required for Linux privesc tools that use SSH.

**Q. `rustscan: command not found`.**
→ Re-run `./install.sh` or `./install_missing.sh`. The script tries `apt` first, then a GitHub release fallback if needed.

**Q. The wizard always proposes the same preset.**
→ The wizard follows detected context. Change target type manually if needed.

**Q. How do I reset for a new box?**
→ `Reset session` button in the top bar — clears the current domain's loot and resets config.

**Q. Backend crashed silently.**
→ Check `./start.sh` output in the Kali terminal. Usually a Python exception — copy it if you open a ticket.

**Q. Are my secrets in Git?**
→ No. `config.local.json` is `.gitignore`d. Only `config.example.json` (empty) is versioned.
