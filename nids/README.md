pcaps/ : fichiers à analyser. sample_traffic.pcap déjà dedans (DNS+HTTP+HTTPS,
capturé avec tcpdump via un conteneur netshoot, permissions raw socket obligent).

rules/ : suricata.rules généré par suricata-update (ET Open), pas versionné, se
retélécharge avec la commande dans le README du dossier lab.

suricata-logs/ et zeek-logs/ : sorties des runs, à vider de temps en temps
(eve.json prend vite de la place avec le ruleset complet).
