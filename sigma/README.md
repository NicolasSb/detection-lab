venv Python avec sigma-cli + pySigma. requirements.txt pour réinstaller si
besoin (pin pyparsing<3.3.3 obligatoire, voir plus bas).

rules/example_suspicious_powershell.yml : juste pour vérifier que la chaîne
check -> convert marche, à remplacer par mes vraies conversions Wazuh au fur
et à mesure.

METHODOLOGIE.md : comment je convertis une règle Wazuh en Sigma (repérer la
source du log, choisir le bon logsource, traduire la syntaxe de match), la
table de correspondance des champs, et le détail des bugs/pièges rencontrés
en le faisant.

    ./.venv/bin/sigma plugin list --plugin-type pipeline   # pipelines dispo (sysmon, windows, ...)
    ./.venv/bin/sigma plugin list --plugin-type backend    # backends dispo

../tp/semaine1/ : énoncé + corrigé du TP de conversion Wazuh->Sigma, avec 21
vraies règles du ruleset officiel Wazuh. Pas dans git (voir ../.gitignore),
c'est du matériel de révision, pas mon travail.

Bug à connaître si sigma check/convert plante avec "TypeError: 'str' object
is not callable" : pyparsing 3.3.3+ casse le parsing de toute condition avec
"and not" (SigmaHQ/pySigma#548, pas encore corrigé). requirements.txt pin déjà
pyparsing<3.3.3, mais si le venv a été créé avant ce pin il faut réinstaller :
./.venv/bin/pip install "pyparsing<3.3.3"

La CI GitHub Actions (../.github/workflows/sigma-ci.yml) fait tourner
sigma check sur rules/ à chaque push.
