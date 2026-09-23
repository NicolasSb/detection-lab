# Compte rendu semaine 2 — partie Linux (auditd + Neo23x0)

## Vérification des clés auditd sur le scénario rejoué

Scénario : `auditd-scenario.sh` copié dans `lab-auditd` puis exécuté avec
`auid=1001` (labuser) forcé via `/proc/self/loginuid`. Six actions dans le
script : exécution d'un binaire caché, `sudo whoami`, `sudo useradd`,
modification de `sshd_config`, `chmod 777`, lecture refusée de
`/etc/shadow`.

**`docker exec lab-auditd ausearch -k process_creation -ts recent`**
nous donne tous les `execve` de la machine hôte capturés par cette clé,
pas seulement ceux du scénario — la clé n'a pas de filtre `auid`, donc
elle voit passer n'importe quel process lancé sur l'hôte pendant la
fenêtre de temps, y compris des processus totalement étrangers au conteneur
(ex : `docker`, `runc`, des outils lancés sur la machine hôte elle-même).
Le champ qui prouve que le binaire caché du scénario a bien été exécuté :
`comm="tail"`/`comm="docker"` dans le bruit, mais aussi, en filtrant sur
`auid=1001`, on retrouve nos propres actions au milieu — la clé est donc
fonctionnelle, juste très bruyante par construction.

**`docker exec lab-auditd ausearch -k etcpasswd -ts recent`**
nous donne les écritures sur les fichiers de la base compte/groupe
(`/etc/passwd`, `/etc/subuid`, `/etc/subgid`...). Sur le run propre,
`ausearch` remonte plusieurs lignes `comm="useradd" exe="/usr/sbin/useradd"
auid=1001 uid=0 key="etcpasswd"` — la commande `sudo useradd -m
backdoor_user` du scénario est bien capturée. Le champ qui le prouve :
`comm="useradd"` associé à `key="etcpasswd"`, avec `auid=1001` (labuser)
mais `uid=0` (root, via sudo) — la distinction auid/uid déjà repérée en
semaine 1/2 se confirme ici en pratique.

**`docker exec lab-auditd ausearch -k sshd -ts recent`**
nous donne les écritures sur `/etc/ssh/`. Une ligne capturée :
`comm="bash" exe="/usr/bin/bash" auid=1001 key="sshd"`, qui correspond à
`sudo bash -c "echo PermitRootLogin yes >> /etc/ssh/sshd_config"` du
scénario. Le champ `comm="bash"` (pas `sshd` lui-même) est un point à
noter : la clé surveille le FICHIER modifié, pas un programme en particulier
— n'importe quel processus qui touche à `/etc/ssh/` déclenche cette clé,
qu'il s'appelle bash, vim, ou un outil de déploiement.

**`docker exec lab-auditd ausearch -k perm_mod -ts recent`**
nous donne les appels `chmod`/`chown`/`fchmod`... Plusieurs lignes
capturées : deux liées à `useradd` en interne (`comm="useradd"`, la
commande modifie des permissions pendant la création du compte, pas
seulement les fichiers passwd), et une explicite avec `comm="chmod"
exe="/usr/bin/chmod"`, qui correspond à notre `chmod 777
/tmp/.hidden_payload` du scénario. Le champ qui prouve l'action volontaire
du scénario (par opposition aux effets de bord d'useradd) :
`comm="chmod"` avec `auid=1001 uid=1001` (pas de sudo cette fois, chmod
tourne en tant que labuser directement).

**`docker exec lab-auditd ausearch -k unauthedfileaccess -ts recent`**
nous donne les tentatives d'accès **refusées** à `/etc`, `/bin`, `/sbin`...
(la règle filtre explicitement sur `success=0`). Ligne capturée :
`comm="cat" exe="/usr/bin/cat" success=no exit=-13 key="unauthedfileaccess"`
— `exit=-13` est le code d'erreur `EACCES` (permission refusée), qui
correspond exactement à notre `cat /etc/shadow` du scénario, qui a échoué
parce que `labuser` n'a pas les droits de lecture sur ce fichier. Point
important à retenir : cette clé n'aurait RIEN capturé si on avait lu le
fichier avec succès (en root, par exemple) — elle détecte le tâtonnement,
pas l'exfiltration réussie.

## Le volume de `process_creation`, chiffré

**`docker exec lab-auditd ausearch -k process_creation -ts today | grep -c type=SYSCALL`**
nous donne le nombre total d'événements capturés par cette clé depuis le
début de la journée : **939**. À comparer aux 6 actions réellement
pertinentes du scénario qu'on cherchait à observer. L'écart énorme
(939 contre 6) s'explique par l'absence de filtre `auid` sur cette clé
précise du ruleset Neo23x0 — contrairement à `etcpasswd`, `sshd`,
`perm_mod` et `unauthedfileaccess` qui ciblent des fichiers/appels précis,
`process_creation` capture tout `execve` de la machine, sans distinction
entre une session utilisateur et n'importe quel autre processus qui
démarre sur l'hôte.

[à continuer : partie Windows/EVTX, puis le livrable "politique de
journalisation"]
