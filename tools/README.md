# evtx_to_xml.py

Rend lisibles les échantillons `.evtx` cités dans `comptes-rendus/cr_telemetrie.md`,
issus du dépôt public [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
Ces échantillons ne sont pas inclus dans ce dépôt, à télécharger depuis la
source.

```bash
python3 -m venv .venv && .venv/bin/pip install python-evtx
.venv/bin/python evtx_to_xml.py CA_DCSync_4662.evtx > CA_DCSync_4662.xml
```

Testé sur `python-evtx` tel que publié sur PyPI en septembre 2026 : les
scripts console du paquet (`evtx_dump`, `evtx_dump_json`) sont cassés
(`ModuleNotFoundError: No module named 'scripts'`), d'où l'appel direct à
l'API dans ce script.
