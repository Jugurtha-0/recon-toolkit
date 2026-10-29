# 🎯 Recon Toolkit (Red Team — reconnaissance)

Boîte à outils de **reconnaissance passive/active** : scanner de ports TCP multithread avec
banner grabbing, et audit des en-têtes de sécurité HTTP. C'est la première étape de toute
mission de pentest (phase *reconnaissance* de la kill chain).

## ⚠️ Usage légal uniquement
À utiliser **uniquement** sur :
- vos propres machines / votre propre lab (VM locale, conteneurs),
- des cibles explicitement prévues pour l'entraînement (ex. `scanme.nmap.org`, autorisé par Nmap pour les tests),
- un système pour lequel vous avez une **autorisation écrite**.

Scanner un système sans autorisation est **illégal** dans la plupart des juridictions
(en France : article 323-1 du Code pénal). Les deux scripts exigent le flag `--yes` pour
rappeler explicitement cette règle avant toute exécution.

## Fonctionnalités
| Outil | Rôle |
|---|---|
| `port_scanner.py` | Scan TCP connect multithread + récupération de bannière (service, version) |
| `header_scanner.py` | Audit passif des en-têtes de sécurité HTTP (CSP, HSTS, X-Frame-Options...) et détection des fuites de version |
| `recon.py` | Enchaîne les deux : scan de ports puis audit HTTP si 80/443 est ouvert |

## Utilisation
```bash
# Scan de ports (sur votre propre machine, par ex.)
python3 port_scanner.py 127.0.0.1 --ports 1-1024 --yes

# Audit des en-têtes HTTP d'un site
python3 header_scanner.py https://example.com

# Recon complète
python3 recon.py scanme.nmap.org --ports 1-1024 --yes

python3 -m pytest tests/ -v
```

## Choix de conception
- **Scan TCP connect**, pas de paquets bruts (SYN) : aucun privilège root nécessaire, et c'est
  plus facile à détecter/journaliser côté défense — assumé, car l'objectif ici est pédagogique.
- **Garde-fou `--yes`** sur le scanner de ports : impossible de lancer un scan sans confirmer
  explicitement l'autorisation.
- **Audit HTTP passif** : une seule requête GET, aucune charge utile, aucun test d'injection.
  Détecte les mêmes points qu'un outil comme Mozilla Observatory ou securityheaders.com.
- Tests unitaires avec un serveur HTTP local et un socket d'écoute local, donc **aucune requête
  réseau externe** n'est nécessaire pour valider le code.

## Pistes d'amélioration
Scan UDP, détection d'OS par fingerprinting TCP/IP, export Nmap XML, intégration avec le
`linux-hardening-audit` du même portfolio pour corréler recon externe et posture interne.

## Lien avec mes autres projets
Ce projet est le pendant **offensif** de `ssh-log-analyzer` et `linux-hardening-audit`
(défensifs) : il montre que je comprends les deux côtés — comment un attaquant repère une
surface d'attaque, et comment un défenseur la détecte et la réduit.
