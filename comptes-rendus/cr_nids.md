# Détection réseau : exfiltration DNS et battement C2 (Suricata, Zeek)

Détection de deux techniques réseau, l'exfiltration DNS et le battement C2, avec
Suricata et Zeek, plus la position de capture sous bande passante contrainte.
Chaque règle est validée deux fois : elle doit alerter sur le trafic d'attaque
(pas de faux négatif) et rester silencieuse sur du trafic normal (pas de faux
positif).

## Approche de test

Pas de vrai malware. Le trafic de test est synthétique et bénin, forgé paquet par
paquet avec scapy (aucune émission réseau, aucune charge), reproduisant la
structure des deux techniques : requêtes DNS à label gauche encodé long pour
l'exfil, connexions TCP périodiques vers un hôte fixe pour le battement. Un
générateur à graine fixe rend les captures reproductibles. Connaître la structure
exacte du trafic permet de mesurer faux négatifs (rejeu contre le pcap d'attaque)
et faux positifs (rejeu contre un pcap de trafic normal) de façon déterministe.

## Exfiltration DNS (Suricata)

L'exfil encode la donnée dans le sous-domaine du nom demandé : le résolveur
transmet la requête au serveur autoritaire du domaine, contrôlé par l'attaquant,
qui décode le label. Un label gauche long et à haute entropie est donc la donnée
elle-même.

Règle de forme sur le buffer `dns.query` :

```
dns.query; pcre:"/^[a-z2-7]{40,}\./"
```

Un label de 40 caractères ou plus dans le jeu base32. Elle cible la forme, pas un
domaine connu, donc résiste au changement de domaine C2. Sur le pcap d'attaque,
20 alertes sur 20 requêtes, 0 sur le trafic normal.

Limites, à assumer : elle rate un attaquant qui découpe en labels courts pour
passer sous le seuil, et lève des FP sur des services cloud à sous-domaines longs
(clés d'objets S3/Azure). Une règle de forme se double d'un second critère et
d'une allowlist.

La détection par volume voudrait compter les requêtes vers un même domaine
parent. Suricata ne sait pas : son `threshold` ne tracke que par IP
(`track by_src` / `by_dst`), pas par domaine. `by_dst` vise le résolveur, le même
pour tous les domaines, donc il compte tout le DNS confondu. Le regroupement par
champ applicatif (un `group-by` sur le nom demandé, comme un `event_count` Sigma)
n'est pas exprimable en Suricata. En Suricata la règle de volume est donc
spécifique à un domaine connu, réactive. La détection générique par diversité de
sous-domaines revient à Zeek ou au SIEM.

## Heartbeat C2 (Zeek)

La signature d'un battement (heartbeat) n'est pas le contenu (souvent chiffré) mais la
régularité temporelle : l'implant recontacte son serveur à intervalle quasi
constant. Un script Zeek accumule les horodatages de connexion par couple
(source, dest) via l'événement `connection_state_remove`, puis, à la fin, calcule
le coefficient de variation des intervalles (écart-type / moyenne). CV bas =
régulier = battement.

Sur le pcap d'attaque : 30 connexions vers la même destination, intervalle moyen
59.9s, écart-type 0.99s, CV 0.017. Le jitter que l'attaquant ajoute pour paraître
moins robotique (intervalles de 59 à 61s) est absorbé par le CV, là où une
égalité stricte d'intervalle raterait.

Piège rencontré : `connection_state_remove` ne livre pas les horodatages dans
l'ordre chronologique. Sans tri avant le calcul, le CV d'un battement régulier
ressort à 1.71 au lieu de 0.017 (faux négatif). Un `sort()` avant le calcul le
corrige.

Faux positifs : le trafic périodique légitime existe (DNS, NTP, keepalives,
sondes de supervision). Sur la seule régularité il ressemble à un battement (le
résolveur DNS ressortait à CV 0.000). Deux leviers, complémentaires : un seuil de
connexions assez haut (un vrai battement tourne longtemps, pas 5 connexions) et
une allowlist des destinations légitimes connues. La périodicité seule n'est pas
un détecteur.

## Suricata et Zeek : deux limites, une cause

Pour l'exfil DNS, Suricata attrape la forme mais pas le volume par domaine. Pour
le battement, il attrape le volume de connexions mais pas la régularité. Même
cause : Suricata fait du match par paquet et du seuil par IP, il n'agrège pas
avec état sur un champ applicatif (le domaine DNS, la périodicité d'un flux).
L'agrégation stateful va à Zeek (calcul sur une fenêtre, regroupement par champ)
ou au SIEM (corrélation Sigma). Suricata reste le bon outil pour la détection de
forme à la sonde.

Corollaire pour la chasse : Suricata n'alerte que sur ce qui matche une
signature, Zeek décrit tout le trafic en logs structurés. Une menace sans
signature préexistante reste visible par corrélation dans `conn.log`. Partir des
logs et corréler bat souvent l'attente d'une alerte qui n'existera pas.

## Suricata, Zeek et Sigma : sondes puis SIEM

Suricata et Zeek sont des sondes réseau, de la couche IP à la couche applicative.
Sigma est un langage de règles sur les logs parsés, au repos dans le SIEM.

Les trois forment un pipeline. Les sondes matchent le trafic et émettent logs et
alertes. Ces logs rejoignent les logs hôte dans le SIEM. Sigma corrèle au-dessus,
logs réseau compris (logsources `product: zeek`, `category: dns`). Là se fait la
corrélation cross-source : un battement Zeek vers une IP, croisé avec un process
hôte suspect qui parle à cette IP.

## Position : capture en bande passante contrainte

Sur un site isolé à liaison limitée vers le centre de supervision, la capture
complète ne remonte pas en continu. Trois niveaux, alignés sur ce qui précède :

- À la sonde, détection de forme (Suricata), sans état, en première ligne.
- En local, agrégation avec état (Zeek calcule un verdict sur une fenêtre sans
  remonter les paquets bruts).
- Au central, corrélation sur les logs structurés et les alertes, pas les
  paquets.

La capture complète reste en tampon local (ring buffer) sur la sonde. Une alerte
remonte, et seulement alors on va chercher le pcap correspondant. Déclenchée par
l'alerte, pas l'inverse. La bande passante consommée suit le signal, pas le
volume.
