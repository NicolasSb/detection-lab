venv Python avec sigma-cli + pySigma. requirements.txt pour réinstaller si besoin.

rules/example_suspicious_powershell.yml : juste pour vérifier que la chaîne
check -> convert marche, à remplacer par mes vraies conversions Wazuh.

    ./.venv/bin/sigma plugin list --plugin-type pipeline   # pipelines dispo (sysmon, windows, ...)
    ./.venv/bin/sigma plugin list --plugin-type backend    # backends dispo
