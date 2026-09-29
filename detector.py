"""
Détecteur d'attaques par force brute (brute force) à partir de logs SSH.

Principe : une attaque par force brute se traduit par un grand nombre de
tentatives de connexion échouées depuis une même adresse IP en peu de temps.
Ce module lit un fichier de logs, compte les échecs par IP dans une fenêtre
de temps glissante, et lève une alerte au-delà d'un seuil.

À but pédagogique / démonstration pour un poste en cybersécurité (analyse SOC).
"""

import re
from datetime import datetime
from collections import defaultdict


# Expression régulière pour repérer une ligne d'échec de connexion SSH.
# Exemple de ligne attendue :
# 2026-09-29 10:15:03 Failed password for root from 192.168.1.10 port 52344 ssh2
LOG_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"Failed password for .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_log_line(line: str):
    """
    Analyse une ligne de log.
    Retourne (datetime, ip) si c'est un échec de connexion, sinon None.
    """
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    date = datetime.strptime(match.group("date"), "%Y-%m-%d %H:%M:%S")
    ip = match.group("ip")
    return date, ip


def detect_brute_force(lines, threshold: int = 5, window_seconds: int = 60):
    """
    Détecte les IP suspectes.

    Paramètres :
        lines           : itérable de lignes de log
        threshold       : nombre d'échecs à partir duquel on alerte
        window_seconds  : fenêtre de temps (en secondes) sur laquelle on compte

    Retourne : dictionnaire { ip : nombre_max_d_echecs_dans_la_fenetre }
               pour les IP ayant atteint ou dépassé le seuil.
    """
    # On regroupe les horodatages d'échec par IP
    failures = defaultdict(list)
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            date, ip = parsed
            failures[ip].append(date)

    suspects = {}
    for ip, timestamps in failures.items():
        timestamps.sort()
        max_in_window = _max_events_in_window(timestamps, window_seconds)
        if max_in_window >= threshold:
            suspects[ip] = max_in_window

    return suspects


def _max_events_in_window(timestamps, window_seconds):
    """
    Fenêtre glissante : renvoie le nombre maximal d'événements
    trouvés dans n'importe quel intervalle de `window_seconds` secondes.
    """
    max_count = 0
    start = 0
    for end in range(len(timestamps)):
        # On rétrécit la fenêtre par la gauche tant qu'elle est trop large
        while (timestamps[end] - timestamps[start]).total_seconds() > window_seconds:
            start += 1
        count = end - start + 1
        max_count = max(max_count, count)
    return max_count
