# HTB Toolbox — Practical Lab Guide

> A short, concrete, easy-to-follow guide for running labs properly from HTB Toolbox.

## 1. Before you start

Goal: start cleanly, avoid basic mistakes, and not get lost in the output.

Checklist:

1. Start the tool:

```bash
cd ~/HTB/HTBTOOLBOX
./start.sh --open
```

2. Make sure you have:
- `target` = the box IP
- `domain` = the domain if this is a Windows/AD box
- `dc` = the DC FQDN if you already know it
- the UI language you prefer

3. Do not fill every field randomly.

Simple rule:
- if you have no access yet, start as close to anonymous as possible
- if you find a user/password, add it to `Creds Tracker`
- if you find a `ccache`, paste it into the dedicated field

4. Open the `Notes` view right away.

At minimum, write down:
- what you found
- what you tested
- what failed
- what looks promising

## 2. The right workflow

Do not launch “many tools” without a purpose. Work in this order:

1. Understand the attack surface
2. Identify possible access paths
3. Turn information into access
4. Turn access into privilege
5. Clean up and summarize

At every step, ask yourself:

1. Does this give me new access?
2. Does this give me a credential or a hash?
3. Does this give me a credible attack path?

If the answer is no to all three, do not overcommit time to it.

Realistic pentest rule:
- a hypothesis is not a fact
- an interesting line is not yet a pivot
- a discovered credential only matters if you test it properly
- partial access often matters more than a complicated theory

Always work like this:
1. observe
2. form a hypothesis
3. choose the cheapest test that can validate it
4. read the proof
5. decide whether to continue, pivot, or drop that line of effort

## 3. Universal starting routine

On almost every box:

1. Pick the correct type:
- `windows`
- `linux`
- `web`
- `hybrid`

2. Use the `Wizard`

The easiest flow:
- click `Wizard`
- choose the type
- apply a preset

If you are on a `windows / AD` box, you can also use the **interactive path up to WinRM** directly inside the wizard. It follows a realistic order:
- recon
- read loot / logs
- apply a credential
- `krb5_setup` then `getTGT`
- confirm the BloodHound / ACL path
- run `shadowcred_pkinit_chain`
- test WinRM and then open `evil-winrm`

Good defaults:
- `windows` → `HTB AD quick win`
- `linux` → `Linux focus`
- `web` → `Web focus`
- `hybrid` → `Foothold`

3. Let the first steps happen:
- `rustscan_fast`
- `nmap_targeted`
- module auto-check

Do not start with the loudest tools before you even understand the target.

## 4. The real step-by-step box flow

If you want the simplest practical version, follow this chain in order.

### Step 1 — start from the IP

Fill:
- `target`
- `domain` if you already know it
- `dc` if you already know it

Then run:
- `rustscan_fast`
- `nmap_targeted`

You only want to answer this question:
- which services are actually present on the target?

At this stage, do not chase “the exploit” yet.
You only want to establish:
- what is actually listening
- what responds consistently
- what deserves deeper validation

### Step 2 — understand what kind of box this is

From the ports and early results:
- if you see `88`, `389`, `445`, `5985`, think `Windows / AD`
- if you see `80`, `443`, `8080`, also think `Web`
- if you see `22`, `111`, `2049`, think `Linux`

Then follow the correct routine:
- `Windows / AD`
- `Web`
- `Linux`
- or `Hybrid` if several surfaces overlap

Important:
- port `80` does not automatically mean “this is a web box”
- port `445` does not automatically mean “SMB will be exploitable”
- port `5985` does not automatically mean “WinRM is usable”

The right reflex is:
- identify
- confirm
- only then go deeper

### Step 3 — extract the first useful clues

If this is a Windows / AD box, start with:
- `hosts_autoconf`
- `nxc_anon_probe`
- `smbclient_list`
- `ldap_anon_base`
- `getnpusers_asrep`

If this is a Web box, start with:
- `tls_probe`
- `web_robots`
- `web_tech_detect`
- `ffuf_dir_fast`
- `ffuf_vhost`

If this is a Linux box, start with:
- `ssh_banner`
- `ssh_auth_methods`
- `nfs_probe`
- `linux_http_fingerprint`
- `linux_services_enum`

Goal:
- surface a first credible pivot
- not “test everything” yet

In a realistic lab workflow, a “first credible pivot” can be:
- a confirmed domain
- an identified DC
- a readable SMB share
- an AS-REP roastable account
- a hidden vhost
- an admin endpoint
- a recovered config file
- a plausible SSH path

### Step 4 — read the results before clicking everywhere

Go to:
- `Results`
- `Loot`
- `Playbook`

Read first:
- `Anomalies & weaknesses`
- `proofs`
- `interesting hosts`
- highlighted log or config files

Important rule:
- one opened proof is worth more than ten skimmed summaries

Realistic reading priority:
1. anything that gives direct access
2. anything that gives a credential or hash
3. anything that gives a short attack path
4. anything that only adds context

Example:
- `WinRM auth ok` > very strong
- `weak password policy` > useful, but less urgent
- `interesting LDAP descriptions` > good context, not access by itself

### Step 5 — turn a clue into credentials or access

As soon as you find:
- a `user/password`
- an `NT hash`
- a `ccache`
- a service account

Always do:
1. add it to `Creds Tracker`
2. click `Use + retest`
3. reread `Results`
4. reread `Playbook`

If your immediate goal is Kerberos:
- click `Use for getTGT`
- check that the auth bar badge switches to `Kerberos ready`
- then run `gettgt`

Typical modules to rerun at that point:
- `nxc_smb_auth_test`
- `ldap_users_auth`
- `ldapdomaindump`
- `bloodhound_collect`
- `gettgt`
- `winrm_checks`

Recommended realistic order after a new credential:
1. fast validity test
2. direct access test
3. structured collection
4. post-auth only after access is confirmed

So in practice:
1. `nxc_smb_auth_test`
2. `winrm_checks`
3. `ldap_users_auth`
4. `gettgt`
5. `ldapdomaindump`
6. `bloodhound_collect`

What to avoid:
- immediately launching the whole auth catalog
- jumping into post-auth without confirming the account works
- concluding too quickly that a credential is bad when only SMB is blocked

### Step 6 — when a file drops, it becomes a new source

When `smbmap`, `Loot`, or another module brings back a file:
1. open the proof
2. read the file
3. click `Reanalyze loot`
4. add what you found to `Creds Tracker`

What to look for in a file:
- usernames
- passwords
- tokens
- hosts
- UNC paths
- internal URLs
- service names

What makes a file high-priority:
- its name suggests identity, sync, backup, config, admin, hr, db, task, audit
- its content contains `pass`, `token`, `bind`, `ldap`, `sql`, `svc`, `admin`
- it names a machine or service you have not seen elsewhere
- it explains how a service account is actually used

### Step 7 — if SMB is limited, switch to Kerberos

If an account looks valid but SMB fails:
- `krb5_setup`
- `gettgt`
- paste the `ccache`
- rerun Kerberos / LDAP / BloodHound tools

Goal:
- do not abandon a valid credential just because SMB is restricted

Keep in mind:
- `STATUS_ACCOUNT_RESTRICTION` does not mean “bad password”
- `invalid credentials` in one tool does not mean the account is dead everywhere
- some accounts are meant for LDAP, Kerberos, SQL, or services, not interactive SMB
- `krb5_setup` prepares Kerberos but does not create the ticket
- `gettgt` still needs `user + password` or `user + NT hash`
- the `Kerberos ready` / `ccache only` / `getTGT: missing secret` badge helps avoid confusion

### Step 8 — turn access into privilege or endgame

Once you have useful access, prioritize:
- `winrm_checks`
- `bloodyad_acls`
- `certipy_find`
- `gpo_parse`
- `shadowcred_pkinit_chain`
- `secretsdump`

On Linux after foothold:
- `sudo_enum`
- `suid_sgid_find`
- `linux_caps_check`
- `linux_cron_check`
- `linux_docker_check`
- `linux_privesc_check`

Goal:
- turn access into a final pivot, hash, certificate, admin shell, or root

Again, stay realistic:
- prefer short and verifiable abuses
- read the proofs before building a complicated attack story
- if direct `WinRM` or `SSH` is available, test that before an exotic chain

## 5. How to read the results

In `Results`, focus on:

- `Anomalies & weaknesses`
- `interesting hosts`
- `proofs`
- `WinRM`
- `SMB signing`
- `AS-REP`
- `Kerberoast`
- `ADCS`

When a line is clickable, open the proof.

Practical rule:
- do not trust a summary without opening at least one proof
- if an important clue comes from a log or loot file, read the source file

## 6. Windows / AD routine

### Phase 1 — understanding

Start with:
- `rustscan_fast`
- `nmap_targeted`
- `hosts_autoconf`
- `nxc_anon_probe`
- `smbclient_list`
- `ldap_anon_base`
- `getnpusers_asrep`

What you want to know quickly:
- is there a domain?
- is there a DC?
- does SMB respond?
- does LDAP respond?
- does WinRM respond?
- are there AS-REP roastable accounts?

### Phase 2 — first credentials

As soon as you find a user/password or hash:

1. add it to `Creds Tracker`
2. click `Use + retest`
3. reread `Results`

Very useful modules after a first access:
- `nxc_smb_auth_test`
- `ldap_users_auth`
- `ldapdomaindump`
- `bloodhound_collect`
- `getuserspns_kerberoast`
- `gettgt`
- `winrm_checks`

### Phase 3 — when SMB is restricted

Common case:
- password is valid
- SMB is not usable
- `STATUS_ACCOUNT_RESTRICTION`

Then the correct chain is:

1. `krb5_setup`
2. `gettgt`
3. paste the `ccache`
4. rerun Kerberos / LDAP / BloodHound tools

### Phase 4 — post-auth

When you have interesting access, look at:
- `bloodyad_acls`
- `certipy_find`
- `gpo_parse`
- `shadowcred_pkinit_chain`
- `secretsdump`

Use `target account` whenever the module needs a specific target.

## 7. Web routine

Start with:
- `tls_probe`
- `web_robots`
- `web_tech_detect`
- `ffuf_dir_fast`
- `ffuf_vhost`

What you are looking for:
- admin pages
- backups
- `.git`
- `.env`
- hidden vhosts
- framework / CMS / stack
- injectable parameters

Only after that:
- `nikto_scan`
- `web_nuclei_safe`
- `sqlmap_basic`
- `wfuzz_params`

Do not jump into `sqlmap` too early if you have no promising parameter.

## 8. Linux routine

Start with:
- `ssh_banner`
- `ssh_auth_methods`
- `nfs_probe`
- `linux_http_fingerprint`
- `linux_services_enum`

If you get access:
- `sudo_enum`
- `suid_sgid_find`
- `linux_caps_check`
- `linux_cron_check`
- `linux_docker_check`
- `linux_privesc_check`

What you want to find:
- `sudo -l`
- unusual SUID
- dangerous capabilities
- writable cron
- cleartext credentials
- docker group

## 9. How to exploit loot properly

When files appear in `Loot`:

1. run `Reanalyze loot`
2. read the highlighted files
3. open proofs from `Results`
4. add credentials to `Creds Tracker`

High-priority loot:
- logs
- config files
- LDAP exports
- `SYSVOL`
- files downloaded through SMB
- archives and backups

Inside logs, focus on:
- usernames
- passwords
- tokens
- hosts
- FQDNs
- UNC paths
- service names

## 10. When a new credential appears

Recommended routine:

1. `Creds Tracker`
2. `Use + retest`
3. reread `Results`
4. reread `Playbook`
5. prioritize direct access paths:
- `winrm_checks`
- `gettgt`
- `bloodhound_collect`
- `ldapdomaindump`
- `nxc smb`

Do not relaunch the whole toolbox for every new password.
The goal is to test what has the highest chance of turning that credential into access or privilege.

## 11. How to read the Playbook

The `Playbook` is not absolute truth.
It is a prioritization aid.

Focus on:
- `Priorities`
- `Likely paths`
- `Next commands`
- `active credential`

Proper usage:
- it helps you choose the next action
- it does not replace reading the proofs

## 12. When to slow down

Pause and reread before continuing if:

- you launched many tools but none produced a pivot
- you keep accumulating output without taking notes
- you found several credentials but did not test the simplest ones first
- you jumped into complex post-auth while a direct `WinRM` or `SSH` path may already exist

## 13. Common mistakes to avoid

Avoid:

- launching too many noisy tools too early
- ignoring proofs and only reading summaries
- forgetting `krb5_setup` before Kerberos
- forgetting `Reanalyze loot` after a new file appears
- forgetting to fill `target account` for targeted abuse modules
- not taking notes
- not reusing discovered credentials

## 14. Simple end-of-lab routine

Before you stop:

1. reread `Results`
2. reread `Creds Tracker`
3. write down:
- obtained access
- found credentials
- confirmed attack paths
- important proofs

4. update `Notes`

You should be able to summarize the box in 4 points:

1. entry point
2. initial credential
3. main pivot
4. privesc or final access

## 15. Ultra-short checklist

If you only want the shortest version:

1. `Wizard`
2. `rustscan_fast`
3. `nmap_targeted`
4. read `Results`
5. open proofs
6. add creds to `Creds Tracker`
7. `Use + retest`
8. follow `Playbook`
9. `Reanalyze loot`
10. write notes

## 16. The right mindset

A good lab run is not:
- the highest number of launched tools

It is:
- the highest number of useful outputs you actually understood
- the highest number of pivots you successfully turned into access
- the least amount of pointless noise

HTB Toolbox is here to help you:
- move faster
- forget fewer things
- chain better

But you are still the one driving the lab.
