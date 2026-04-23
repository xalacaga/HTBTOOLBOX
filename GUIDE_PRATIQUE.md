# HTB Toolbox — Guide Pratique Lab

> Guide court, concret et facile à suivre pour conduire un lab proprement depuis HTB Toolbox.

## 1. Avant de commencer

Objectif : partir proprement, éviter les erreurs de base, ne pas te perdre dans les sorties.

Checklist :

1. Lance l'outil :

```bash
cd ~/HTB/HTBTOOLBOX
./start.sh --open
```

2. Vérifie que tu as bien :
- `target` = l'IP de la box
- `domain` = le domaine si c'est une box Windows/AD
- `dc` = le FQDN du DC si tu l'as déjà
- la langue UI qui te convient

3. Ne remplis pas tout “au hasard”.

Règle simple :
- si tu n'as aucun accès, commence en quasi anonyme
- si tu trouves un user/password, ajoute-le dans `Creds Tracker`
- si tu trouves un `ccache`, colle-le dans le champ dédié

4. Ouvre tout de suite la vue `Notes`.

Note au minimum :
- ce que tu as trouvé
- ce que tu as testé
- ce qui a échoué
- ce qui semble prometteur

## 2. La bonne logique de travail

Ne lance pas “plein d’outils” sans but. Travaille dans cet ordre :

1. Comprendre la surface d’attaque
2. Identifier les accès possibles
3. Transformer une info en accès
4. Transformer un accès en privilège
5. Nettoyer et résumer

À chaque étape, pose-toi toujours :

1. Est-ce que ça me donne un nouvel accès ?
2. Est-ce que ça me donne un credential ou un hash ?
3. Est-ce que ça me donne un chemin d’attaque crédible ?

Si la réponse est non aux trois, ne t’acharne pas trop longtemps.

Règle réaliste de pentest :
- une hypothèse n’est pas un fait
- une ligne intéressante n’est pas encore un pivot
- un credential trouvé n’est utile que s’il est testé proprement
- un accès partiel vaut souvent plus qu’une grosse théorie

Travaille toujours comme ça :
1. tu observes
2. tu formules une hypothèse
3. tu choisis le test le moins coûteux pour la valider
4. tu lis la preuve
5. tu décides si tu continues, si tu pivotes, ou si tu abandonnes cette piste

## 3. Routine universelle de départ

Sur presque toutes les boxes :

1. Choisis le bon type :
- `windows`
- `linux`
- `web`
- `hybrid`

2. Utilise le `Wizard`

Le plus simple :
- clique `Wizard`
- choisis le type
- applique un preset

Si tu es sur une box `windows / AD`, tu peux aussi suivre le **chemin interactif jusqu'à WinRM** directement dans le wizard. Il te guide dans l'ordre réaliste :
- recon
- lecture du loot / logs
- application d'un credential
- `krb5_setup` puis `getTGT`
- confirmation BloodHound / ACL
- chaîne `shadowcred_pkinit_chain`
- test WinRM puis ouverture `evil-winrm`

Bon réflexe :
- `windows` → `HTB AD quick win`
- `linux` → `Linux focus`
- `web` → `Web focus`
- `hybrid` → `Foothold`

3. Laisse d’abord faire :
- `rustscan_fast`
- `nmap_targeted`
- auto-check des modules

Ne commence pas par les gros outils bruyants si tu n’as encore rien compris à la cible.

## 4. Le vrai pas à pas de la box

Si tu veux une version très simple, suis cette chaîne dans l’ordre.

### Étape 1 — partir de l’IP

Tu remplis :
- `target`
- `domain` si tu l’as déjà
- `dc` si tu l’as déjà

Puis tu lances :
- `rustscan_fast`
- `nmap_targeted`

Tu veux juste répondre à cette question :
- quels services existent vraiment sur cette cible ?

À ce stade, ne cherche pas encore “l’exploit”.
Tu veux seulement établir :
- ce qui écoute vraiment
- ce qui répond de façon cohérente
- ce qui mérite une vérification de deuxième niveau

### Étape 2 — comprendre le type de box

À partir des ports et premiers résultats :
- si tu vois `88`, `389`, `445`, `5985`, pense `Windows / AD`
- si tu vois `80`, `443`, `8080`, pense aussi `Web`
- si tu vois `22`, `111`, `2049`, pense `Linux`

Ensuite tu suis la bonne routine :
- `Windows / AD`
- `Web`
- `Linux`
- ou `Hybrid` si plusieurs surfaces se mélangent

Important :
- un port `80` ne veut pas dire “la box est web”
- un port `445` ne veut pas dire “SMB sera exploitable”
- un port `5985` ne veut pas dire “WinRM utilisable”

Le bon réflexe est :
- repérer
- confirmer
- seulement ensuite approfondir

### Étape 3 — tirer les premiers éléments utiles

Si c’est une box Windows / AD, commence par :
- `hosts_autoconf`
- `nxc_anon_probe`
- `smbclient_list`
- `ldap_anon_base`
- `getnpusers_asrep`

Si c’est une box Web, commence par :
- `tls_probe`
- `web_robots`
- `web_tech_detect`
- `ffuf_dir_fast`
- `ffuf_vhost`

Si c’est une box Linux, commence par :
- `ssh_banner`
- `ssh_auth_methods`
- `nfs_probe`
- `linux_http_fingerprint`
- `linux_services_enum`

Objectif :
- faire remonter un premier pivot crédible
- pas encore “tout tester”

Un “premier pivot crédible”, dans la vraie vie du lab, c’est par exemple :
- un domaine confirmé
- un DC identifié
- un partage SMB lisible
- un compte AS-REP roastable
- un vhost caché
- un endpoint admin
- un fichier de config récupéré
- un accès SSH potentiellement atteignable

### Étape 4 — lire les résultats avant de cliquer partout

Va dans :
- `Résultats`
- `Loot`
- `Playbook`

Lis en priorité :
- `Anomalies & faiblesses`
- `preuves`
- `hosts intéressants`
- fichiers de log ou de config mis en avant

Règle importante :
- une preuve ouverte vaut mieux que dix résumés survolés

Hiérarchie réaliste de lecture :
1. ce qui donne un accès direct
2. ce qui donne un credential ou un hash
3. ce qui donne un chemin d’attaque court
4. ce qui donne seulement du contexte

Exemple :
- `WinRM auth ok` > très fort
- `password policy faible` > utile, mais moins prioritaire
- `descriptions LDAP intéressantes` > bon contexte, pas un accès en soi

### Étape 5 — transformer un élément en credential ou en accès

Dès que tu trouves :
- un `user/password`
- un `NT hash`
- un `ccache`
- un compte de service

Tu fais toujours :
1. ajoute dans `Creds Tracker`
2. clique `Use + retest`
3. relis `Résultats`
4. relis `Playbook`

Si ton but immédiat est Kerberos :
- clique `Use for getTGT`
- vérifie que le badge de la barre d’auth passe sur `Kerberos prêt`
- puis lance `gettgt`

Modules typiques à relancer à ce moment :
- `nxc_smb_auth_test`
- `ldap_users_auth`
- `ldapdomaindump`
- `bloodhound_collect`
- `gettgt`
- `winrm_checks`

Ordre réaliste recommandé après un nouveau credential :
1. test rapide de validité
2. test d’accès direct
3. collecte structurée
4. post-auth seulement si l’accès est confirmé

Donc, en pratique :
1. `nxc_smb_auth_test`
2. `winrm_checks`
3. `ldap_users_auth`
4. `gettgt`
5. `ldapdomaindump`
6. `bloodhound_collect`

Ce qu’il faut éviter :
- lancer immédiatement tout le catalogue auth
- sauter sur le post-auth sans savoir si le compte marche vraiment
- conclure trop vite qu’un credential est mauvais alors que seul SMB est bloqué

### Étape 6 — si un fichier tombe, il devient une nouvelle source

Quand `smbmap`, `Loot` ou un autre module ramène un fichier :
1. ouvre la preuve
2. lis le fichier
3. clique `Réanalyser le loot`
4. ajoute ce qui est trouvé dans `Creds Tracker`

Ce que tu cherches dans un fichier :
- usernames
- mots de passe
- tokens
- hosts
- chemins UNC
- URL internes
- noms de services

Ce qui fait qu’un fichier devient prioritaire :
- son nom suggère identité, sync, backup, config, admin, hr, db, task, audit
- son contenu contient `pass`, `token`, `bind`, `ldap`, `sql`, `svc`, `admin`
- il cite une machine ou un service jamais vus ailleurs
- il explique l’usage réel d’un compte de service

### Étape 7 — si SMB est limité, bascule sur Kerberos

Si un compte semble valide mais que SMB échoue :
- `krb5_setup`
- `gettgt`
- colle le `ccache`
- relance les outils Kerberos / LDAP / BloodHound

Objectif :
- ne pas abandonner un bon credential juste parce que SMB est restreint

À retenir :
- `STATUS_ACCOUNT_RESTRICTION` ne veut pas dire “mauvais password”
- `invalid credentials` sur un outil ne veut pas dire que le compte est mort partout
- certains comptes servent à LDAP, Kerberos, SQL ou services, mais pas à SMB interactif
- `krb5_setup` prépare Kerberos mais ne crée pas le ticket
- `gettgt` demande encore `user + password` ou `user + NT hash`
- le badge `Kerberos prêt` / `ccache seul` / `getTGT: secret manquant` aide à ne pas se tromper

### Étape 8 — transformer l’accès en privilège ou en fin de box

Quand tu as un accès exploitable, priorise :
- `winrm_checks`
- `bloodyad_acls`
- `certipy_find`
- `gpo_parse`
- `shadowcred_pkinit_chain`
- `secretsdump`

Sur Linux après foothold :
- `sudo_enum`
- `suid_sgid_find`
- `linux_caps_check`
- `linux_cron_check`
- `linux_docker_check`
- `linux_privesc_check`

Objectif :
- transformer un accès en pivot final, hash, certificat, shell admin ou root

Là encore, reste réaliste :
- privilégie les abus courts et vérifiables
- lis les preuves avant d’écrire une histoire d’attaque trop complexe
- si un accès direct `WinRM` ou `SSH` existe, teste-le avant une chaîne exotique

## 5. Lecture correcte des résultats

Dans `Résultats`, concentre-toi sur :

- `Anomalies & faiblesses`
- `hosts intéressants`
- `preuves`
- `WinRM`
- `SMB signing`
- `AS-REP`
- `Kerberoast`
- `ADCS`

Quand une ligne est cliquable, ouvre la preuve.

Règle pratique :
- ne fais pas confiance à un résumé sans ouvrir au moins une preuve
- si une info importante vient d’un log ou d’un loot, lis le fichier source

## 6. Routine Windows / AD

### Phase 1 — compréhension

Commence par :
- `rustscan_fast`
- `nmap_targeted`
- `hosts_autoconf`
- `nxc_anon_probe`
- `smbclient_list`
- `ldap_anon_base`
- `getnpusers_asrep`

Ce que tu veux savoir vite :
- y a-t-il un domaine ?
- y a-t-il un DC ?
- SMB répond-il ?
- LDAP répond-il ?
- WinRM répond-il ?
- y a-t-il des comptes AS-REP roastables ?

Ce que tu ne dois pas faire trop tôt :
- lancer `bloodhound_collect` avant de savoir que les creds marchent
- partir sur ADCS sans preuve d’ADCS
- lancer des abus ACL ciblés sans avoir identifié la cible et le droit utile

### Phase 2 — premiers credentials

Dès que tu trouves un user/password ou hash :

1. ajoute-le dans `Creds Tracker`
2. clique `Use + retest`
3. relis `Résultats`

Modules très utiles après un premier accès :
- `nxc_smb_auth_test`
- `ldap_users_auth`
- `ldapdomaindump`
- `bloodhound_collect`
- `getuserspns_kerberoast`
- `gettgt`
- `winrm_checks`

Ordre conseillé :
1. `nxc_smb_auth_test` pour valider vite
2. `winrm_checks` si `5985/5986` répond
3. `ldap_users_auth`
4. `gettgt`
5. `ldapdomaindump`
6. `bloodhound_collect`
7. `getuserspns_kerberoast`

### Phase 3 — si SMB est restreint

Cas classique :
- mot de passe bon
- SMB pas utilisable
- `STATUS_ACCOUNT_RESTRICTION`

Alors la bonne chaîne est :

1. `krb5_setup`
2. `gettgt`
3. colle le `ccache`
4. relance les outils Kerberos / LDAP / BloodHound

### Phase 4 — post-auth

Quand tu as un accès intéressant, regarde :
- `bloodyad_acls`
- `certipy_find`
- `gpo_parse`
- `shadowcred_pkinit_chain`
- `secretsdump`

Utilise `target account` quand le module en a besoin.

Très bon réflexe :
- si `bloodhound_collect` ou `bloodyad_acls` te donnent un abus simple et court, priorise-le
- si tu as déjà un accès shell, vérifie d’abord ce qu’il te donne vraiment avant d’ouvrir trois nouvelles chaînes

## 7. Routine Web

Commence par :
- `tls_probe`
- `web_robots`
- `web_tech_detect`
- `ffuf_dir_fast`
- `ffuf_vhost`

Ce que tu cherches :
- pages d’admin
- backups
- `.git`
- `.env`
- vhosts cachés
- techno/framework/CMS
- paramètres injectables

Ordre réaliste :
1. identifier la surface
2. comprendre l’application
3. confirmer une faiblesse
4. seulement ensuite lancer les outils plus lourds

Ensuite seulement :
- `nikto_scan`
- `web_nuclei_safe`
- `sqlmap_basic`
- `wfuzz_params`

Ne pars pas trop tôt sur `sqlmap` si tu n’as aucun paramètre prometteur.

En pratique :
- `ffuf` sert à découvrir
- `whatweb` ou `web_tech_detect` sert à orienter
- `sqlmap` sert à confirmer et exploiter, pas à remplacer l’analyse

## 8. Routine Linux

Commence par :
- `ssh_banner`
- `ssh_auth_methods`
- `nfs_probe`
- `linux_http_fingerprint`
- `linux_services_enum`

Si tu obtiens un accès :
- `sudo_enum`
- `suid_sgid_find`
- `linux_caps_check`
- `linux_cron_check`
- `linux_docker_check`
- `linux_privesc_check`

Ce que tu veux trouver :
- `sudo -l`
- SUID anormal
- capabilities dangereuses
- cron modifiable
- credentials en clair
- docker group

Ordre réaliste après foothold :
1. comprendre quel utilisateur tu es
2. lire `sudo -l`
3. chercher les chemins courts vers root
4. garder les checks plus larges pour après

## 9. Comment exploiter le loot correctement

Quand des fichiers arrivent dans `Loot` :

1. relance `Réanalyser le loot`
2. lis les fichiers mis en avant
3. ouvre les preuves depuis `Résultats`
4. ajoute les credentials dans `Creds Tracker`

Priorité haute pour :
- logs
- fichiers config
- exports LDAP
- `SYSVOL`
- fichiers téléchargés via SMB
- archives et backups

Priorité encore plus haute si le fichier :
- contient un couple user/password
- documente un workflow métier réel
- montre comment un service se connecte à LDAP, SQL ou à un autre hôte
- révèle un nom de machine ou de compte réutilisable

Dans un log, cherche surtout :
- usernames
- passwords
- tokens
- hosts
- FQDN
- chemins UNC
- noms de services

## 10. Quand un nouveau credential tombe

Routine recommandée :

1. `Creds Tracker`
2. `Use + retest`
3. relis `Résultats`
4. relis `Playbook`
5. priorise les accès directs :
- `winrm_checks`
- `gettgt`
- `bloodhound_collect`
- `ldapdomaindump`
- `nxc smb`

Ne lance pas toute la boîte à outils à chaque nouveau mot de passe.
L’idée est de tester ce qui a le plus de chances de transformer ce credential en accès ou privilège.

Pense en “valeur attendue” :
- un test WinRM direct peut valoir plus qu’un gros dump LDAP
- un getTGT rapide peut valoir plus qu’un scan SMB complet
- un accès SQL ou LDAP réutilisable peut être plus rentable qu’un shell non privilégié

## 11. Comment lire le Playbook

Le `Playbook` n’est pas une vérité absolue.
C’est une aide de tri.

Lis surtout :
- `Priorités`
- `Chemins probables`
- `Commandes suivantes`
- `credential actif`

Utilisation correcte :
- il t’aide à choisir la prochaine action
- il ne remplace pas la lecture des preuves

## 12. Les cas où il faut ralentir

Fais une pause et relis avant de continuer si :

- tu as lancé beaucoup d’outils mais rien n’a produit de pivot
- tu accumules des sorties sans ajouter de notes
- tu trouves plusieurs credentials mais tu ne testes pas les plus simples d’abord
- tu pars en post-auth complexe alors qu’un accès direct `WinRM` ou `SSH` est peut-être déjà là
- tu confonds “énumération riche” et “avancée réelle”
- tu n’arrives plus à dire quelle hypothèse tu essaies de valider

## 13. Les erreurs classiques à éviter

À éviter :

- lancer trop d’outils bruyants trop tôt
- ignorer les preuves et ne lire que les résumés
- oublier `krb5_setup` avant Kerberos
- oublier `Réanalyser le loot` après un nouveau fichier
- ne pas remplir `target account` pour les modules d’abus ciblé
- ne pas garder de notes
- oublier de réutiliser les credentials trouvés
- tirer des conclusions trop vite à partir d’un seul outil
- ne pas recouper un indice avec une deuxième preuve
- garder un credential “dans le tracker” sans jamais le tester proprement

## 14. Routine simple de fin de lab

Avant de quitter :

1. relis `Résultats`
2. relis `Creds Tracker`
3. exporte mentalement ou note :
- accès obtenus
- credentials trouvés
- chemins d’attaque confirmés
- preuves importantes

4. mets à jour `Notes`

Tu dois pouvoir résumer en 4 points :

1. point d’entrée
2. credential initial
3. pivot principal
4. privesc ou accès final

## 15. Mini checklist ultra-courte

Si tu veux juste la version la plus simple :

1. `Wizard`
2. `rustscan_fast`
3. `nmap_targeted`
4. lire `Résultats`
5. ouvrir les preuves
6. ajouter les creds dans `Creds Tracker`
7. `Use + retest`
8. suivre `Playbook`
9. `Réanalyser le loot`
10. noter ce que tu fais

## 16. Le bon état d’esprit

Un bon run de lab, ce n’est pas :
- le plus d’outils lancés

C’est :
- le plus de sorties utiles comprises
- le plus de pivots transformés
- le moins de bruit inutile

Le rôle de HTB Toolbox est de t’aider à :
- aller plus vite
- oublier moins de choses
- mieux enchaîner

Mais c’est toujours toi qui pilotes le lab.
