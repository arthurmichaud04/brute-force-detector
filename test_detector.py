"""
Tests du détecteur de brute force.
Lancer avec : python test_detector.py
"""

from datetime import datetime
from detector import parse_log_line, detect_brute_force, _max_events_in_window


def test_parse_ligne_valide():
    """Une ligne d'échec est correctement analysée."""
    line = "2026-09-29 10:15:01 Failed password for root from 192.168.1.10 port 52340 ssh2"
    result = parse_log_line(line)
    assert result is not None
    date, ip = result
    assert ip == "192.168.1.10"
    assert date == datetime(2026, 9, 29, 10, 15, 1)
    print("OK - parsing ligne valide")


def test_parse_ligne_invalide():
    """Une ligne de connexion réussie n'est pas un échec."""
    line = "2026-09-29 10:16:00 Accepted password for user from 10.0.0.5 port 41000 ssh2"
    assert parse_log_line(line) is None
    print("OK - parsing ligne non pertinente ignorée")


def test_detection_ip_suspecte():
    """Une IP avec beaucoup d'échecs rapprochés est détectée."""
    lines = [
        f"2026-09-29 10:15:0{i} Failed password for root from 1.2.3.4 port 5000 ssh2"
        for i in range(6)
    ]
    suspects = detect_brute_force(lines, threshold=5, window_seconds=60)
    assert "1.2.3.4" in suspects
    assert suspects["1.2.3.4"] >= 5
    print("OK - IP suspecte détectée")


def test_ip_legitime_ignoree():
    """Quelques échecs espacés ne déclenchent pas d'alerte."""
    lines = [
        "2026-09-29 10:15:00 Failed password for root from 5.6.7.8 port 5000 ssh2",
        "2026-09-29 11:15:00 Failed password for root from 5.6.7.8 port 5000 ssh2",
        "2026-09-29 12:15:00 Failed password for root from 5.6.7.8 port 5000 ssh2",
    ]
    suspects = detect_brute_force(lines, threshold=5, window_seconds=60)
    assert "5.6.7.8" not in suspects
    print("OK - IP légitime non signalée")


def test_fenetre_glissante():
    """La fenêtre glissante compte le pic maximal d'événements."""
    base = datetime(2026, 9, 29, 10, 0, 0)
    from datetime import timedelta
    # 4 événements en 10s, puis un isolé plus tard
    times = [base + timedelta(seconds=s) for s in [0, 3, 6, 9, 300]]
    assert _max_events_in_window(times, 60) == 4
    print("OK - fenêtre glissante")


if __name__ == "__main__":
    test_parse_ligne_valide()
    test_parse_ligne_invalide()
    test_detection_ip_suspecte()
    test_ip_legitime_ignoree()
    test_fenetre_glissante()
    print("\nTous les tests sont passés.")
