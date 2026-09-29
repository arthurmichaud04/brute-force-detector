# Détecteur d'attaques par force brute (Python)

Outil d'analyse de logs qui détecte les tentatives d'attaque par **force brute**
sur un service SSH, en repérant les adresses IP générant un nombre anormal
d'échecs de connexion sur une courte période.

## Contexte

Une attaque par force brute consiste à essayer massivement des combinaisons
identifiant/mot de passe pour forcer un accès. Elle laisse une trace
caractéristique dans les logs : de nombreuses connexions échouées depuis une
même IP en peu de temps. Cet outil automatise leur détection — une tâche
typique d'analyse en centre opérationnel de sécurité (SOC).

## Fonctionnement

1. Le programme lit un fichier de logs d'authentification (format type `auth.log`).
2. Il extrait, via une expression régulière, les échecs de connexion et l'IP source.
3. Pour chaque IP, il compte les échecs à l'aide d'une **fenêtre de temps
   glissante** (par défaut : 60 secondes).
4. Toute IP dépassant un **seuil** d'échecs (par défaut : 5) est signalée comme
   suspecte.

L'approche par fenêtre glissante évite les faux positifs : trois échecs répartis
sur trois heures ne déclenchent pas d'alerte, contrairement à sept échecs en
trente secondes.

## Utilisation

```bash
python main.py sample_auth.log
```

Avec des paramètres personnalisés :

```bash
python main.py sample_auth.log --threshold 5 --window 60
```

Exemple de sortie :

```
/!\ 2 IP suspecte(s) détectée(s) (seuil : 5 échecs en 60s) :

  172.16.0.99        7 tentatives échouées
  192.168.1.10       6 tentatives échouées
```

## Structure

```
brute-force-detector/
├── detector.py         # Logique de détection (parsing, fenêtre glissante)
├── main.py             # Interface en ligne de commande
├── sample_auth.log     # Fichier de logs d'exemple
├── test_detector.py    # Tests
└── README.md
```

## Tests

```bash
python test_detector.py
```

Les tests couvrent : l'analyse des lignes de log (valides et non pertinentes),
la détection d'une IP attaquante, la non-détection d'une IP légitime, et le
calcul de la fenêtre glissante.

## Pistes d'amélioration

- Support d'autres formats de logs (Apache, Nginx, RDP)
- Export des alertes au format JSON ou CSV
- Blocage automatique via `iptables` / fail2ban
- Détection d'attaques distribuées (plusieurs IP coordonnées)

## Stack technique

- Python 3
- Bibliothèque standard uniquement (`re`, `datetime`, `collections`, `argparse`)

## Auteur

Arthur Michaud
