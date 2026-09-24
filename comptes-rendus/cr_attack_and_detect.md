# Attaquer et détecter la même technique : retour d'expérience Active Directory

> À visée pédagogique. Les techniques offensives sont décrites contre un lab
> personnel et autorisé, dans le seul but de construire et justifier leur
> détection. Les séquences d'attaque sont volontairement incomplètes : l'outil et
> le principe sont cités, la ligne de commande directement exploitable est
> retirée. Le contenu de détection (EventID, champs, règles) est complet.

Sept techniques d'attaque Active Directory (Kerberoasting, AS-REP Roasting,
Pass-the-Hash, DCSync, extraction NTDS, abus de GPO, délégation contrainte) sur
le principe attaque plus détection : rejouer la technique, identifier la
télémétrie qui la trahit, écrire la règle, mesurer ce qui peut l'être.

## Préambule : le contrôleur de domaine est un Samba AD, pas un Windows

Vu les ressources système, le DC du lab est un Samba AD (Samba 4.15.13, domaine
LAB.LOCAL) plutôt qu'un Windows Server : un système similaire dans les mécanismes
(mêmes protocoles LDAP, Kerberos, NTLM, SMB, réplication DRSUAPI) mais différent
dans les séquences et la détection. Certaines attaques se rejouent telles quelles,
d'autres sont refusées par le KDC Samba ou par impacket, jamais conçu contre une
cible Samba. Ces refus sont des résultats, attribués à leur cause et à la
référence upstream.

Deux plans tenus séparés. L'exécution, en partie live contre le Samba, en partie
bloquée. La détection, dont les règles ciblent le journal Security Windows (4768,
4769, 4662, 5136, 4624), ce qu'un DC Windows de production émet. On distingue donc
ce qui est mesuré (rejoué et observé) de ce qui est raisonné (déduit de la
technique et de la télémétrie de référence).

## Vue d'ensemble

Tout ce qui reste sur LDAP, NTLM et SMB fonctionne contre Samba. Les blocages se
concentrent sur la surface Kerberos (la demande de ticket), là où le KDC Samba et
impacket ne s'accordent pas.

| Technique | Exécution contre le Samba AD | Cause du blocage |
|---|---|---|
| Reconnaissance SPN / UAC (LDAP) | Mesurée | - |
| Pass-the-Hash (NTLM/SMB) | Mesurée | - |
| Abus de GPO | Mesurée | - |
| Configuration de délégation | Mesurée | - |
| Kerberoasting (extraction TGS) | Bloquée | impacket #2211 (checksum TGS_REQ) |
| Délégation contrainte (S4U) | Bloquée | impacket #2211 (même cause) |
| AS-REP Roasting | Bloquée | KDC Samba : préauth exigée malgré le flag |
| DCSync (DRSUAPI) | Bloquée | impacket #991 (DRSUAPI non supporté vs Samba) |
| Extraction NTDS.dit | Sans objet | pas de ntds.dit (backend sam.ldb) |

Un lab Samba enseigne fidèlement les protocoles et la surface d'attaque LDAP/NTLM,
mais ne remplace pas un Windows sur la surface de forge de tickets Kerberos.

## Détection : rien ne se déclenche sur ce lab, et pourquoi

Aucune règle ne peut être vue se déclencher sur le Samba, pour deux raisons
cumulées :

1. Les règles ciblent le journal Security Windows. Samba n'émet pas d'EVTX
   Windows, ces events n'existent pas ici.
2. Samba a son propre audit (auth_audit JSON), mais l'image `nowsci/samba-domain`
   régénère `smb.conf` au démarrage et n'expose pas l'audit du KDC sans
   reconfiguration lourde.

Observer la détection ici signifie inspecter la requête que la règle compile
(`sigma convert`) et la relier champ par champ à l'action. Les règles sont
validées par `sigma check` et `sigma convert`, sur un échantillon réel quand il
existe (4662 pour DCSync), raisonnées sur la forme de l'event sinon. Voir une
vraie télémétrie demande un DC Windows.

## Kerberoasting (T1558.003)

Un compte de service porteur d'un SPN a un ticket de service chiffré avec la clé
dérivée de son mot de passe. Tout compte du domaine peut le demander, puis le
casser hors ligne.

**Reconnaissance (mesurée).** En s'authentifiant comme un utilisateur lambda du
domaine, `GetUserSPNs.py` (impacket) énumère les comptes porteurs d'un SPN via
LDAP, sans privilège particulier. Retourne `MSSQLSvc/dc1.lab.local:1433` porté par
`svc_sql`.

**Extraction (bloquée).** La même commande avec l'option `-request` (récupération
du ticket crackable) échoue :

```
[-] Principal: lab.local\svc_sql - Kerberos SessionError:
    KRB_AP_ERR_INAPP_CKSUM(Inappropriate type of checksum in message)
```

Le KDC Samba exige un checksum du KDC_REQ_BODY dans l'authenticator de l'AP_REQ du
TGS_REQ ; impacket 0.13.1 ne l'envoie pas, le KDC refuse. Bug upstream ouvert,
[fortra/impacket#2211](https://github.com/fortra/impacket/pull/2211). Contre un DC
Windows la requête aboutit et rend le ticket.

**Détection.** Event 4769 (demande de ticket de service). Requête compilée :

```
Channel:Security AND ((EventID:4769 AND TicketOptions:0x40810000
    AND TicketEncryptionType:0x17) AND (NOT ServiceName:*$))
```

- `TicketEncryptionType:0x17` : RC4 demandé par l'outil pour le crackage hors
  ligne. Signal principal.
- `NOT ServiceName:*$` : exclusion des comptes machine, dont les tickets RC4 sont
  légitimes. `svc_sql` n'est pas un compte machine.

Faux positif : comptes de service sur systèmes anciens négociant encore RC4
(NetApp, legacy), ou domaine à niveau fonctionnel bas.

## AS-REP Roasting (T1558.004)

Un compte dont la pré-authentification Kerberos est désactivée laisse le KDC
renvoyer un AS-REP chiffré avec la clé dérivée de son mot de passe, sans preuve
d'identité préalable, crackable hors ligne. Différence avec le Kerberoasting :
aucun compte du domaine n'est nécessaire, il suffit du nom d'un compte vulnérable.

**Attaque (bloquée par le KDC).** `asrep_test` a la pré-authentification désactivée
(userAccountControl 4194816, bit `0x400000`, vérifié via `samba-tool user show` et
`ldbsearch`). La demande d'AS-REP sur une liste de comptes candidats
(`GetNPUsers.py`, impacket, `-no-pass`) donne pour `asrep_test` :

```
[-] User asrep_test doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Un rejeu manuel de l'AS-REQ confirme que le refus vient du KDC, pas de l'outil : le
KDC répond `KRB_ERROR` code 25 (`KDC_ERR_PREAUTH_REQUIRED`). Ce build de Samba
impose la pré-authentification même quand le bit `DONT_REQ_PREAUTH` est positionné.

Blocage opposé à celui du Kerberoasting : là c'est l'outil offensif qui refuse
(checksum absent), ici c'est la cible (le KDC Samba n'honore pas le flag). Le
premier marcherait contre un DC Windows, le second est une propriété du KDC visé.

**Détection.** Event 4768 (demande de TGT). Requête compilée :

```
Channel:Security AND (EventID:4768 AND ServiceName:krbtgt
    AND PreAuthType:0 AND TicketEncryptionType:0x17)
```

- `PreAuthType:0` : aucune pré-authentification, la condition qui rend le compte
  roastable. Signal principal.
- `ServiceName:krbtgt`, `TicketEncryptionType:0x17` : demande de TGT, ticket RC4
  crackable.

Faux positif : comptes legacy sans pré-authentification pour un besoin
d'interopérabilité.

## Pass-the-Hash (T1550.002)

Une authentification NTLM prouve la connaissance du hash NT, pas du mot de passe
en clair. Qui possède le hash s'authentifie sans connaître le mot de passe.
Première technique de la liste qui se rejoue entièrement contre le Samba, parce
qu'elle reste sur NTLM et SMB, hors de la surface Kerberos.

**Prérequis, le hash.** Pass-the-Hash suppose un hash déjà obtenu en amont (dump
LSASS, DCSync). DCSync étant bloqué contre Samba (voir plus bas), le hash est ici
extrait côté DC (`samba-tool user getpassword`, attribut `unicodePwd` en base64 à
décoder en hex), ce qui tient lieu de cette étape amont.

**Attaque (mesurée).** `smbclient.py` (impacket) avec l'option `-hashes` (format
`LMHASH:NTHASH`, LM vide, seul le NT compte) ouvre une session SMB authentifiée
sur le DC (partages `sysvol`, `netlogon`) avec le seul hash NT, sans que le mot de
passe n'ait transité. Le mécanisme est une propriété de NTLM, pas une faille de
Samba.

**Détection.** Event 4624 (ouverture de session), branche NTLM réseau. Requête
compilée :

```
Channel:Security AND ((EventID:4624 AND LogonType:3 AND LogonProcessName:NtLmSsp
    AND KeyLength:0 AND SubjectUserSid:S-1-0-0)
    AND (NOT TargetUserName:"ANONYMOUS LOGON"))
```

- `LogonType:3` + `LogonProcessName:NtLmSsp` + `KeyLength:0` : session réseau via
  NTLM, pas Kerberos. Signature du hash rejoué.
- `SubjectUserSid:S-1-0-0` : SID sujet nul, propre à ce logon NTLM.

Règle plus bruyante que les précédentes : le NTLM légitime existe (hôtes non
intégrés à Kerberos, applications anciennes). Le vrai signal n'est pas le NTLM en
soi mais un compte censé utiliser Kerberos qui apparaît en NTLM réseau, ce qui
exige une baseline des couples compte/hôte normaux.

## DCSync (T1003.006)

Le protocole de réplication AD (DRSUAPI) sert aux DC à se synchroniser. Un compte
disposant des droits de réplication peut le rejouer pour demander au DC les
secrets d'un compte, sans toucher au disque du DC. Ces droits ne sont normalement
portés que par les DC et les administrateurs du domaine.

**Attaque (bloquée).** Depuis le conteneur attaquant, en administrateur du
domaine, `secretsdump.py` (impacket, `-just-dc-user`, méthode DRSUAPI) échoue :

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] byte indices must be integers or slices, not str
[*] Something went wrong with the DRSUAPI approach.
```

Le chemin DRSUAPI d'impacket n'a jamais été développé ni testé contre Samba,
confirmé par le mainteneur sur
[fortra/impacket#991](https://github.com/fortra/impacket/issues/991). Contre un DC
Windows la technique rend les hash. L'option `-use-vss` suggérée ne change rien :
VSS est une méthode de dump local sur DC Windows, pas applicable ici.

**Détection (mesurée sur échantillon réel).** Seule technique du document dont la
télémétrie a été observée en réel, sur un échantillon EVTX du dépôt public
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(`CA_DCSync_4662.xml`) : un event 4662 authentique portant deux GUID de droits de
réplication. Rapport inversé par rapport aux autres sections, l'attaque n'est pas
mesurée mais la détection l'est. Requête compilée :

```
Channel:Security AND ((EventID:4662 AND (Properties:(
    *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR
    *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* OR
    *9923a32a-3607-11d2-b9be-0000f87a36b2*)))
    AND (NOT SubjectUserName:*$)
    AND (NOT (SubjectUserName:(NT\ AUT* OR MSOL_*))))
```

- GUID `1131f6aa...` (DS-Replication-Get-Changes) et `1131f6ad...`
  (DS-Replication-Get-Changes-All) : l'usage des droits de réplication. Les deux
  sur un même acteur est la signature.
- `NOT SubjectUserName:*$` et `NT AUT*` / `MSOL_*` : exclusion des comptes machine,
  système et de synchronisation d'annuaire, qui répliquent légitimement.

Faux positif : comptes de synchronisation d'annuaire (`MSOL_`, type Entra
Connect), exclus explicitement.

## Extraction NTDS.dit (T1003.003)

L'autre voie vers les secrets que DCSync : copier à froid le fichier de base
d'annuaire du DC via un snapshot `ntdsutil` ou un cliché VSS. Elle suppose une
exécution locale sur le DC, pas un accès réseau.

**Sans objet contre Samba.** La base d'annuaire de Samba est un ensemble de
fichiers LDB (`/var/lib/samba/private/sam.ldb`), il n'y a pas de `ntds.dit`.
`ntdsutil` et le cliché VSS sont des outils Windows. Technique de DC Windows, sans
équivalent à rejouer ici.

**Détection (raisonnée).** Création de processus (Sysmon 1 ou 4688). Requête
compilée :

```
(CommandLine:*ntdsutil* AND CommandLine:*create* AND CommandLine:*ifm*)
    OR CommandLine:*ntds.dit*
    OR (Image:*\vssadmin.exe AND (CommandLine:*create* AND CommandLine:*shadow*))
```

- `ntdsutil ... create ... ifm` : création d'un média d'installation embarquant
  une copie de NTDS.dit.
- `ntds.dit` en ligne de commande, ou `vssadmin ... create shadow` pour copier la
  base contournée du verrou en écriture.

Distincte de DCSync : copie à froid depuis le DC, pas le protocole de réplication.

Faux positif : sauvegarde légitime de l'AD par l'outillage de backup, à traiter
par allowlist de comptes et d'hôtes.

## Abus de GPO (T1484.001)

Une GPO liée à une OU s'applique à toutes ses machines. Modifier une GPO liée à
une OU sensible déploie une tâche planifiée ou un script de logon à grande
échelle, vecteur d'exécution et de persistance.

**Attaque (mesurée).** La gestion des GPO passe par `samba-tool gpo` (avec une
cible LDAP explicite `-H`), qui liste les deux GPO par défaut. Sans `-H`,
`samba-tool gpo` échoue avec `Could not find a DC for domain`, un défaut de
résolution DNS/SPN du DC unique conteneurisé, contourné par la cible explicite.
Création et modification accessibles par la même voie.

**Détection (raisonnée).** Event 5136 (modification d'objet annuaire). Requête
compilée :

```
Channel:Security AND (EventID:5136 AND ObjectClass:groupPolicyContainer
    AND (AttributeLDAPDisplayName:(gPCMachineExtensionNames
    OR gPCUserExtensionNames OR versionNumber)))
```

- `ObjectClass:groupPolicyContainer` : la modification porte sur un objet GPO.
- `gPCMachineExtensionNames` / `gPCUserExtensionNames` : attributs modifiés quand
  on ajoute une extension (tâche, script). `versionNumber` : incrémenté à chaque
  modification.

À corréler avec l'écriture de fichier correspondante dans SYSVOL, où réside le
contenu réel de la GPO.

Faux positif : administration légitime des GPO par l'équipe AD, à réduire par
allowlist des comptes délégués.

## Délégation contrainte (T1098)

La délégation contrainte autorise un compte à obtenir des tickets en usurpant un
autre utilisateur vers un service donné (S4U). Attribuée à un compte contrôlé,
elle permet de se faire passer pour un administrateur vers ce service.

**Configuration (mesurée), abus S4U (bloqué).** L'attribut a été posé sur un
compte machine et vérifié (`samba-tool computer show` :
`msDS-AllowedToDelegateTo: HTTP/dc1.lab.local`, `userAccountControl: 4096`).
L'abus S4U (`getST.py`, impacket, option `-impersonate`) échoue :

```
[*] Requesting S4U2self
[-] Kerberos SessionError: KRB_AP_ERR_INAPP_CKSUM
```

Même cause que le Kerberoasting : S4U passe par un TGS_REQ, donc le défaut de
checksum d'impacket #2211. La configuration est mesurée, l'exploitation bloquée à
la cause déjà identifiée.

**Détection (raisonnée).** Event 5136 sur les attributs de délégation. Requête
compilée :

```
Channel:Security AND (EventID:5136
    AND (AttributeLDAPDisplayName:(msDS-AllowedToDelegateTo
    OR msDS-AllowedToActOnBehalfOfOtherIdentity)))
```

- `msDS-AllowedToDelegateTo` : délégation contrainte, l'attribut posé sur
  `svc_web01$`. `msDS-AllowedToActOnBehalfOfOtherIdentity` : délégation basée sur
  les ressources, même famille.

Détecter l'attribution du droit vaut mieux que son usage : l'attribut change
rarement, alors que l'usage S4U ressemble à du trafic Kerberos normal. Détection
left of boom, en amont de l'exploitation.

Faux positif : configuration légitime d'une délégation par l'équipe AD, rare et à
tracer nominativement.

## Discussion : fiabilité des détections et portée du lab

Les sept techniques ne se valent pas en fiabilité de détection :

| Détection | Fiabilité | Raison |
|---|---|---|
| DCSync (4662, GUID de réplication) | Élevée | droit rare, signature précise, mesurée sur échantillon réel |
| Délégation (5136, attribut posé) | Élevée | attribut rarement modifié, détection en amont de l'usage |
| Kerberoasting (4769, RC4) | Moyenne | RC4 légitime résiduel sur systèmes anciens |
| AS-REP Roasting (4768, PreAuthType 0) | Moyenne | comptes legacy sans préauth existants |
| Extraction NTDS (process ntdsutil/VSS) | Moyenne | outillage de backup légitime |
| Abus de GPO (5136 sur GPO) | Moyenne | administration GPO légitime fréquente |
| Pass-the-Hash (4624 NTLM) | Faible seule | NTLM légitime répandu, exige une baseline |

La ligne de partage est le taux d'activité légitime qui ressemble à l'attaque. Une
détection est fiable quand l'action détectée n'a presque pas de raison d'exister
légitimement (réplication accordée à un compte utilisateur, attribut de délégation
modifié), bruyante quand l'action a un jumeau légitime courant (NTLM, RC4,
administration GPO). Les détections bruyantes exigent une baseline ou une allowlist
documentée pour séparer le jumeau légitime de l'attaque.

Deux limites de portée. Les blocages d'exécution viennent de l'interopérabilité
Samba/impacket, pas d'une défense du SI cible : contre un DC Windows, Kerberoasting,
AS-REP Roasting, DCSync et l'abus S4U s'exécutent. Et les faux positifs cités sont
qualitatifs, une mesure réelle demanderait une fenêtre de trafic normal sur un AD
de production.

### Ce que le lab apporte, attaques bloquées comprises

L'ingénierie de détection ne dépend pas de l'exécution de l'exploit sur le lab.
Pour chaque technique, la télémétrie qui la trahit (EventID, champs), la règle et
son analyse de faux positifs tiennent, que l'attaque ait tourné ici ou non. Pour
les techniques bloquées, la détection est raisonnée et validée par `sigma check` /
`sigma convert`, mesurée sur échantillon réel dans le seul cas de DCSync. Aucun
signal n'est prétendu observé là où il ne l'est pas.

Les attaques bloquées apportent autant que les réussites, parfois plus. Expliquer
pourquoi DCSync échoue impose de comprendre DRSUAPI, pourquoi le Kerberoasting
échoue impose de comprendre le checksum du TGS_REQ et la pré-authentification.
Diagnostiquer un blocage force à comprendre le protocole en profondeur, là où un
exploit qui aboutit du premier coup n'apprend que la mécanique de l'outil.

Le lab a servi à transposer une connaissance Wazuh vers Sigma, monter une infra
de test reproductible, écrire et valider des règles et une politique de détection,
et mesurer les signaux réels côté auditd et NIDS. Sur la partie AD, l'apport est
la connaissance de la télémétrie et la capacité à caractériser honnêtement les
limites de l'expérimentation, ce qui est mesuré et ce qui est raisonné.

## Conclusion

Quatre des sept techniques se rejouent contre le Samba (reconnaissance LDAP,
Pass-the-Hash, abus de GPO, configuration de délégation), trois sont bloquées sur
la surface Kerberos (deux par impacket, une par le KDC Samba), une est sans objet
faute de NTDS.dit. Les sept règles ciblent la télémétrie Windows de référence,
validées par `sigma check` et `sigma convert`, dont une (DCSync) sur un échantillon
réel. La valeur transférable en poste n'est pas d'avoir tout rejoué, mais de savoir
pour chaque technique quelle télémétrie la trahit, à quel point la détection est
fiable, pourquoi elle se comporte différemment sur Samba et sur Windows, et
pourquoi un blocage contre ce lab ne vaut jamais preuve de défense.
