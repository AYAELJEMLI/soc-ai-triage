"""Lecture d'un fichier d'alertes au format Wazuh (alerts.json : un objet JSON par ligne)."""

import json
from datetime import datetime


def parse_ts(valeur):
    """Wazuh écrit les dates ainsi : 2026-10-14T02:10:03.123+0100."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(valeur, fmt)
        except ValueError:
            continue
    raise ValueError(f"date illisible : {valeur}")


def normaliser(brut):
    rule = brut["rule"]
    mitre = rule.get("mitre", {})
    data = brut.get("data", {})
    return {
        "time": parse_ts(brut["timestamp"]),
        "level": int(rule["level"]),
        "rule_id": str(rule["id"]),
        "description": rule.get("description", ""),
        "techniques": list(mitre.get("id", [])),
        "tactics": list(mitre.get("tactic", [])),
        "agent": brut.get("agent", {}).get("name", "?"),
        "srcip": data.get("srcip"),
        "user": data.get("srcuser") or data.get("dstuser"),
        "full_log": brut.get("full_log", ""),
    }


def charger_alertes(chemin):
    """Retourne (alertes normalisées, nombre de lignes ignorées car invalides)."""
    alertes, ignorees = [], 0
    with open(chemin, encoding="utf-8", errors="replace") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                alertes.append(normaliser(json.loads(ligne)))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                ignorees += 1
    return alertes, ignorees
