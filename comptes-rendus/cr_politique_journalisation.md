# Politique de journalisation, parc Windows/Linux

## Préambule : d'où vient cette priorisation

Dans le cadre de l'exercice, l'analyse de risque n'est pas fournie.
L'étude se base sur deux éléments :
- la prévalence documentée de certaines techniques à l'échelle du
  secteur (vol de credentials, mouvement latéral par abus de service,
  persistance) ;
- le contexte de déploiement du plan de révision (site isolé, bande
  passante limitée vers un centre de supervision, client étatique,
  maintien en condition de sécurité sur plusieurs décennies).

À réviser avec un modèle de menace réel : Threat Intel propre à
l'organisation, inventaire d'actifs, résultats Redteam.

## Ce qu'on collecte, et pourquoi

Principe d'arbitrage : pas de redondance entre deux sources qui verraient
la même chose, et priorité à la source qui porte le signal de la façon la
plus directement exploitable en un seul événement (moins de corrélation
manuelle nécessaire).

**Windows - Sysmon**

| EventID | Ce qu'il couvre | Technique visée |
|---|---|---|
| 1 (process creation) | Chaîne d'exécution complète (`Image`/`ParentImage`/`CommandLine`) | Base de toute détection d'exécution, LOLBAS/LOLBIN, persistance |
| 8 (CreateRemoteThread) | Injection de code dans un process distant | T1055 |
| 10 (process access) | Accès mémoire à un process, notamment LSASS | T1003.001 (dump credentials) |
| 11 (file creation) | Écriture de fichier, croisée avec 1 pour les chaînes de persistance | T1053.005 (tâche planifiée) |
| 12/13 (registre) | Création/modification de clé, notamment la base SAM | T1136 (compte local), T1098 (groupe admin) |

**Windows - logs natifs Security**, non redondants avec Sysmon :

| EventID | Ce qu'il couvre | Technique visée |
|---|---|---|
| 7045 | Service Control Manager, installation de service | T1543.003 (mouvement latéral façon PsExec) |
| 4662 | Directory Service Access, droits étendus AD | T1003.006 (DCSync), aucun équivalent Sysmon |
| 5145 | Vérification d'accès à un partage réseau | T1135/reconnaissance, aucun équivalent Sysmon |

**Windows - PowerShell**

| EventID | Ce qu'il couvre |
|---|---|
| 4104 (Script Block Logging) | Seule source PowerShell utile en détection. Le reste de l'espace d'ID PowerShell (cycle de vie du moteur, événements 40000+) est du bruit de fonctionnement générique, écarté par défaut. |

**Linux - auditd (Neo23x0)**, correspondance technique par technique avec
le choix Windows, pas symétrie systématique :

| Clé | Ce qu'elle couvre | Équivalent Windows |
|---|---|---|
| `etcpasswd` | Écritures sur la base compte/groupe | Sysmon 12/13 (création de compte local) |
| `process_vm` | Syscalls d'accès mémoire à un autre process (ptrace, process_vm_readv/writev) | Sysmon 8/10 (injection, accès mémoire) |
| `cron` | Tâches planifiées | Sysmon 1+11 (persistance par tâche planifiée) |
| `systemd` | Création/modification de service | Security 7045 (abus de service) |

Deux techniques Windows n'ont pas d'équivalent Linux propre, assumé
plutôt que forcé : DCSync (spécifique au protocole de réplication AD,
aucun sens sur une machine qui n'est pas contrôleur de domaine) et la
reconnaissance de partage administratif C$ (un partage Windows n'a pas
d'équivalent direct côté Linux).

## Ce qu'on ne collecte pas, et pourquoi

- **Sysmon 3 (network connection), 7 (image load), 22 (DNS query)** :
  aucune technique de la liste ci-dessus n'en dépend directement pour être
  détectée. Volume significatif (7 en particulier) pour une valeur
  ajoutée hors contexte d'investigation ciblée. À reconsidérer si une
  technique de type C2/exfiltration entre dans le périmètre.
- **Le reste de l'espace d'ID PowerShell** (40000+, cycle de vie du
  moteur) : sans valeur de détection sur un exemple réel
  (`Powershell_4104_MiniDumpWriteDump_Lsass.xml`, EventID
  40961/40962/53504 présents sur toute session, malveillante ou non).
- **`unauthedfileaccess` (auditd) au-delà du périmètre par défaut du
  ruleset** : cette clé ne capture que les tentatives d'accès échouées
  (`success=0`), son volume reste contenu par nature, pas besoin
  d'extension à des chemins applicatifs custom sans justification par
  service.
- **Contenu complet des paquets réseau en continu** : hors de portée avec
  la contrainte de bande passante vers un centre de supervision distant.
  Remplacé par des métadonnées de flux et une capture ciblée déclenchée
  sur alerte plutôt qu'en continu.

## Comment on tranche bruit vs signal

Exemple concret, sur la détection de lecture mémoire
LSASS (`EventID 4663`, `AccessMask=0x00000010`) : la règle inclut un
filtre d'exclusion sur `ProcessName|contains: 'C:\Program Files'`, parce
qu'un agent EDR/AV légitime peut lire la mémoire de LSASS dans le cadre
d'un scan. Le filtre est volontairement scopé à `Program Files`
(emplacement d'installation standard des logiciels professionnels, droits
admin requis pour y écrire) et pas à `C:\` seul, qui aurait exclu la
quasi-totalité des process de la machine, légitimes et malveillants
confondus, y compris un payload posé dans `Downloads` ou `Temp`.

Deuxième exemple, sur le volume plutôt que sur un filtre d'exclusion :
la clé auditd `process_creation` a capturé 939 événements en une seule
journée de test sur une machine quasi inactive, faute de filtre `auid`.
Une clé qui ne trie rien à la source déplace le travail de tri vers la
couche de détection ou vers la capacité de stockage/traitement en aval.
Gardée telle quelle ici : c'est la source la plus dense pour la
détection d'exécution.

## Limites d'auditd et pourquoi eBPF prend le relais

Testé directement : auditd n'est pas conteneurisable
proprement. Le sous-système audit du noyau n'est pas namespacé, un seul
listener par noyau (`pid: host` obligatoire même dans un lab Docker). Sur
un parc avec des workloads conteneurisés, cette limite structurelle pose
un vrai problème d'attribution : un audit exécuté depuis l'hôte voit
tout, sans distinguer facilement de quel conteneur vient l'activité sans
corrélation PID/cgroup manuelle.

Coût CPU non négligeable sous forte charge syscall, chaque appel
intercepté passe par le sous-système audit avant d'être autorisé.
Contournement documenté : un attaquant avec les privilèges suffisants
peut désactiver auditd (`-D` charge une politique vide) ou tuer le
processus. À surveiller via les clés `auditconfig`/`auditlog`
elles-mêmes.

eBPF (Falco, Tetragon, ou l'instrumentation native de la plupart des EDR
modernes) répond à une partie de ces limites : filtrage en kernel-space
avant remontée, et surtout awareness native des conteneurs
(cgroups/namespaces), ce qu'auditd n'a jamais eu nativement. Ne remplace
pas complètement auditd à court terme (maturité opérationnelle encore
inégale selon les distributions/kernels supportés), mais c'est la
direction du marché sur les déploiements récents.
