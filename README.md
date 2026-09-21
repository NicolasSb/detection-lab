Labo pour montée en compétence sur Sigma, adapté à ma machine (4 coeurs,
~62 Go de disque libre). Que du Docker + un venv Python, pas d'ISO Security Onion ni
de GOAD complet.

Identifiants générés : voir CREDENTIALS.md (pas commité).

Sigma, pas de conteneur nécessaire :

    cd sigma
    ./.venv/bin/sigma check rules/example_suspicious_powershell.yml
    ./.venv/bin/sigma convert -t lucene -p sysmon rules/example_suspicious_powershell.yml

Backends installés : lucene/eql/esql (Elastic), opensearch_lucene, splunk. Il n'existe
pas de backend pySigma "Wazuh" officiel sur PyPI, le Wazuh indexer en 4.x est un
OpenSearch donc opensearch_lucene est ce qui s'en approche le plus pour vérifier une
règle. Pour les vieilles règles Wazuh en XML, pas de conversion automatique possible,
juste une réécriture à la main en se raccrochant à la technique ATT&CK correspondante.

AD minimal + attaque :

    docker compose --profile ad up -d
    docker compose --profile caldera up -d

Attention, ce n'est pas GOAD : un seul DC, pas de forêt, rien de pré-cassé (délégations,
ACL, GPO piégées). Bon pour comprendre auditd/Sysmon côté AD et Kerberos, pas
suffisant pour rejouer Kerberoasting/DCSync sans configurer des comptes vulnérables à
la main d'abord.

Semaine 4, NIDS sur pcap (pas de capture live) :

    docker compose --profile nids up -d
    docker exec lab-suricata suricata-update -o /etc/suricata/rules --no-test
    docker exec lab-suricata suricata -r /pcaps/<fichier>.pcap -S /etc/suricata/rules/suricata.rules -l /var/log/suricata --runmode=single -k none
    docker exec lab-zeek zeek -r /pcaps/<fichier>.pcap Log::default_logdir=/zeek-logs LogAscii::use_json=T

Il y a déjà un pcap de test dans nids/pcaps (trafic DNS+HTTP+HTTPS réel), déjà validé
avec les deux moteurs. Pour d'autres scénarios (exfiltration DNS, Atomic Red Team...)
il faut capturer depuis ailleurs et déposer le fichier ici, pas de capture live prévue.

EDR + IOC :

    docker compose --profile velociraptor up -d
    cd misp && docker compose up -d

Velociraptor : https://localhost:8889/ - MISP : https://localhost:8443/

Pour tout arrêter et garder les données :

    docker compose --profile velociraptor --profile ad --profile nids --profile caldera down
    (cd misp && docker compose down)

Ajouter -v aux deux commandes pour repartir de zéro (supprime aussi les données).

Ce qui manque par rapport au plan d'origine : pas de Security Onion (remplacé par
Suricata+Zeek en conteneur sur pcap, pas de stack Elastic ni de capture continue, la
place disque manque). Pas de GOAD (DC Samba minimal à la place, à configurer à la
main pour les scénarios avancés). Pas de backend Sigma->Wazuh natif (voir plus haut).
Atomic Red Team pas installé, plus logique de le lancer direct sur un hôte du labo
que dans un conteneur isolé, à faire quand j'en serai là.
