# Conversion Wazuh -> Sigma : méthode et retour d'expérience

Les 21 règles de `rules/` viennent du ruleset par défaut de Wazuh (dépôt
officiel `wazuh/wazuh`, dossier `ruleset/rules/`), converties une par une
en Sigma. Ce document décrit le procédé suivi et les difficultés réelles
rencontrées en le faisant, pas une théorie a priori.

## Procédé suivi pour chaque règle

**1. Identifier la source du log, pas le contenu de la description.**
Une règle Wazuh ne dit pas toujours explicitement quel type de log elle
regarde - il faut remonter à la règle parente (`if_sid`, `if_group`) ou au
décodeur (`decoded_as`) pour le savoir. Par exemple `5701` (sonde de
protocole SSH) référence `<if_sid>5700</if_sid>`, et c'est la règle 5700
elle-même qui porte `<decoded_as>sshd</decoded_as>` - l'indice n'est pas
sur la règle qu'on convertit, mais sur son parent.

**2. Choisir le `logsource` Sigma en fonction du champ observé, pas de l'OS visé.**
Le nom du champ que la règle Wazuh interroge dit directement quelle
combinaison `category`/`product`/`service` utiliser côté Sigma - voir la
table plus bas. La règle pratique retenue : `service` + `product` quand la
source est un démon précis lié à un seul OS (sshd, auditd, le journal
Windows Security natif), `category` seule quand la source est une famille
de log indépendante du logiciel exact qui l'a produite (un serveur web,
quel qu'il soit), et `category` + `product` ensemble quand la famille de
log est elle-même spécifique à un OS (Sysmon, qui n'existe que sous
Windows).

**3. Traduire la syntaxe de correspondance, pas juste copier le texte.**
Wazuh utilise très souvent des regex PCRE2 (`type="pcre2"`), avec ou sans
ancres (`^...$`). Sigma préfère des valeurs littérales combinées à des
modificateurs (`|contains`, `|endswith`, `|startswith`) plutôt que de la
regex - une valeur Wazuh ancrée (`^lsass\.exe$`) devient une égalité ou un
`|endswith` simple, une valeur non ancrée devient un `|contains`. Copier le
texte de la regex tel quel dans une valeur Sigma ne fonctionne presque
jamais (voir la section pièges plus bas).

**4. Mapper le tag `<mitre>` vers les tactiques réelles, pas une seule au choix.**
Le tag `<mitre><id>Txxxx</id></mitre>` fourni nativement par Wazuh donne la
technique. La ou les tactiques associées ne se devinent pas : elles se
vérifient avec la donnée que l'outil de validation utilise lui-même :

```python
from sigma.data import mitre_attack as m
m.mitre_attack_techniques_tactics_mapping.get('T1055')
# ['stealth', 'privilege-escalation']
```

Certaines techniques n'ont qu'une tactique, d'autres plusieurs - dans ce
cas les règles SigmaHQ réelles les mettent toutes, pas une seule choisie
arbitrairement (vérifié en comparant avec des règles publiées du dépôt
`SigmaHQ/sigma` sur des techniques proches de celles converties ici).

**5. Séparer règle atomique et règle de corrélation.**
Les règles Wazuh avec `frequency`/`timeframe`/`same_source_ip`
(ex: `5703`, seuil de tentatives de connexion) ne sont pas des détections
sur un seul événement, ce sont des agrégats sur une fenêtre de temps. Sigma
les représente avec un type de règle séparé (`correlation:`), qui référence
une règle atomique classique par son `id` plutôt que de dupliquer sa
condition. Les deux vivent dans des fichiers distincts (`002a`/`002b`).

**6. Valider avec l'outil, pas à l'œil.**
Chaque règle passe par `sigma check` puis `sigma convert` vers au moins un
backend avant d'être considérée terminée. Plusieurs erreurs décrites plus
bas ne sont visibles qu'à la conversion, jamais au `check`.

## Table de correspondance des logsources

| Indice dans la règle Wazuh | `logsource` Sigma | Champs Wazuh -> Sigma |
|---|---|---|
| `<decoded_as>sshd</decoded_as>` sur la règle parente | `product: linux`, `service: sshd` | texte libre -> `message` |
| `<field name="audit.type">` | `product: linux`, `service: auditd` | `audit.type` -> `type` |
| `<url>` (log web décodé, Apache/Nginx) | `category: webserver` | `<url>` -> `cs-uri-query` |
| `<field name="win.system.eventID">` | `product: windows`, `service: security` | `win.system.eventID` -> `EventID` |
| `win.eventdata.*`, Sysmon event 1 | `category: process_creation`, `product: windows` | `.image` -> `Image`, `.parentImage` -> `ParentImage`, `.commandLine` -> `CommandLine`, `.originalFileName` -> `OriginalFileName`, `.parentCommandLine` -> `ParentCommandLine` |
| `win.eventdata.*`, Sysmon event 3 | `category: network_connection`, `product: windows` | `.destinationPort` -> `DestinationPort`, `.destinationIp` -> `DestinationIp`, `.sourceIp` -> `SourceIp`, `.protocol` -> `Protocol` |
| `win.eventdata.*`, Sysmon event 8 (`if_group>sysmon_event8`) | `category: create_remote_thread`, `product: windows` | `.targetImage` -> `TargetImage`, `.sourceImage` -> `SourceImage` |
| `win.eventdata.*`, Sysmon event 10 (`if_group>sysmon_event_10`) | `category: process_access`, `product: windows` | `.targetImage` -> `TargetImage`, `.sourceImage` -> `SourceImage`, `.grantedAccess` -> `GrantedAccess` |
| canal PowerShell/Operational, event 4104 | `category: ps_script`, `product: windows` | `.scriptBlockText` -> `ScriptBlockText` |

Règle générale pour retrouver un nom de champ Sigma sans cette table sous
les yeux : c'est quasiment toujours le nom de champ Sysmon natif tel qu'il
apparaît dans l'event XML brut, en PascalCase - Wazuh le transforme en
camelCase et le préfixe par `win.eventdata.`. Retirer le préfixe, remettre
la première lettre en majuscule.

## Difficultés rencontrées

### Bugs du framework, pas des erreurs de conversion

**`pyparsing >= 3.3.3` casse toute condition `X and not Y`.** Symptôme :
`sigma check`/`sigma convert` plantent avec une trace Python se terminant
par `TypeError: 'str' object is not callable`, sur n'importe quelle règle
combinant deux identifiants avec `and not` - un pattern pourtant très
courant pour exclure des faux positifs connus (`selection and not filter`).
Reproduit en isolant un cas minimal (deux sélections triviales), confirmé
comme régression connue sur le dépôt de pySigma
([SigmaHQ/pySigma#548](https://github.com/SigmaHQ/pySigma/issues/548)).
Contournement : épingler `pyparsing<3.3.3` (déjà fait dans
`requirements.txt`).

**Le pipeline `windows-logsources` plante sur `category: ps_script`.** Même
signature d'erreur que ci-dessus, mais cause différente : isolé en testant
les pipelines un par un, le problème n'apparaît qu'avec
`-p windows-logsources` sur une règle de cette catégorie précise (`sysmon`
seul, ou aucun pipeline, fonctionnent). Contournement : ne jamais chaîner
les deux, `sysmon` seul suffit puisque le nom de champ `ScriptBlockText`
est déjà correct sans transformation.

### Pièges YAML invisibles pour `sigma check`

YAML est parsé avant que Sigma n'intervienne : une perte de données à ce
niveau est structurellement invisible pour l'outil de validation, qui ne
voit que ce qui a survécu au parsing.

- **Clé dupliquée dans une mapping** (un nom de champ répété plusieurs
  fois, ou un nom de bloc de détection répété) : YAML garde silencieusement
  la dernière occurrence et écarte les précédentes, sans erreur ni
  avertissement. `sigma check` remonte alors 0 issue sur une règle qui a
  perdu une partie de sa logique. La bonne syntaxe pour combiner plusieurs
  valeurs sur un même champ est une liste sous une clé unique, pas
  plusieurs clés identiques.
- **Valeur hexadécimale non quotée interprétée comme un entier.** YAML
  reconnaît nativement la notation `0x...` comme un entier et la convertit
  (`0x40` devient `64`). Un champ censé contenir le texte `"0x40"` finit
  comparé à un nombre décimal, qui ne matchera jamais un vrai log. Toujours
  quoter les valeurs qui ressemblent à des identifiants hexadécimaux.
- **Wildcard manuel en plus d'un modificateur.** Les modificateurs Sigma
  (`|contains`, `|endswith`, `|startswith`) ajoutent déjà les wildcards
  nécessaires à la conversion - en ajouter un à la main dans la valeur
  produit un avertissement de l'outil (`WildcardInsteadOfEndswithIssue`)
  dont la suggestion de correction n'est pas toujours la bonne, à évaluer
  au cas par cas plutôt qu'à suivre aveuglément.

### Zones sans mapping propre

Certains champs Wazuh n'ont pas d'équivalent direct et standardisé côté
Sigma :

- Les types `audit.type` issus du détecteur d'anomalies natif d'auditd
  (`ANOM_ADD_ACCT`, `ANOM_ROOT_TRANS`...) n'ont pas de taxonomie
  communément admise dans SigmaHQ, qui cible surtout les traces syscall
  (`type: EXECVE`). Le choix `service: auditd` + champ `type` est
  pragmatique, pas un standard.
- Le champ `cs-uri-query` utilisé pour les logs web est une convention
  issue du format W3C/IIS, reprise par une partie de la communauté même
  pour de l'Apache/Nginx - sa portabilité réelle dépend de l'existence d'un
  pipeline de normalisation vers ce nom de champ sur la plateforme cible.
- Il n'existe pas de backend pySigma "Wazuh" officiel sur PyPI. Le Wazuh
  indexer en 4.x étant un OpenSearch, `opensearch_lucene` est le backend le
  plus proche pour vérifier une conversion.

### Tagging ATT&CK

Le validateur `sigma check` utilise une taxonomie de tactiques tirée en
direct d'un jeu de données STIX dont certains noms courts diffèrent de la
convention utilisée dans le reste de la documentation ATT&CK (`stealth`
plutôt que `defense-evasion` par exemple, alors que c'est bien le nom
utilisé côté SigmaHQ en pratique - vérifié par comparaison directe avec le
dépôt officiel). Par ailleurs, le mapping ATT&CK fourni nativement par une
règle Wazuh n'est pas toujours strictement fidèle à la définition officielle
de la technique (`60144`, sur l'ajout à un groupe de sécurité local, est
tagué T1484 - Domain Policy Modification - une technique qui, dans son
usage réel documenté, concerne la modification de GPO de domaine plutôt que
l'appartenance à un groupe local). Le tag Wazuh est conservé tel quel dans
la conversion pour rester traçable à la source, sans être présenté comme
une vérité ATT&CK absolue.
