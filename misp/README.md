docker-compose.yml et template.env viennent du repo officiel MISP/misp-docker (branche
master), pas touchés sauf ssl/ et .env ajoutés à côté.

.env : copié depuis template.env, rempli : ADMIN_EMAIL/ADMIN_ORG/ADMIN_PASSWORD
et changé les ports nginx (8080/8443 au lieu de 80/443 pour pas rentrer en conflit).

ssl/ : cert auto-signé perso (openssl req), généré une fois, à refaire si expiré dans
un an. Le key.pem doit être en 644 sinon le conteneur nginx n'a pas le droit de le lire.

Pour remonter tout ça : docker compose up -d depuis ce dossier.
