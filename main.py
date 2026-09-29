"""
Interface en ligne de commande du détecteur de brute force.

Exemple :
    python main.py sample_auth.log
    python main.py sample_auth.log --threshold 5 --window 60
"""

import sys
import argparse
from detector import detect_brute_force


def main():
    parser = argparse.ArgumentParser(
        description="Détecte les attaques par force brute dans un fichier de logs SSH."
    )
    parser.add_argument("logfile", help="Chemin du fichier de logs à analyser")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Nombre d'échecs déclenchant une alerte (défaut : 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="Fenêtre de temps en secondes (défaut : 60)")
    args = parser.parse_args()

    try:
        with open(args.logfile, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Erreur : fichier introuvable : {args.logfile}")
        sys.exit(1)

    suspects = detect_brute_force(lines, args.threshold, args.window)

    if not suspects:
        print("Aucune attaque par force brute détectée.")
        return

    print(f"/!\\ {len(suspects)} IP suspecte(s) détectée(s) "
          f"(seuil : {args.threshold} échecs en {args.window}s) :\n")
    # On trie par nombre d'échecs décroissant
    for ip, count in sorted(suspects.items(), key=lambda x: x[1], reverse=True):
        print(f"  {ip:<18} {count} tentatives échouées")


if __name__ == "__main__":
    main()
