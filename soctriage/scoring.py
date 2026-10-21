"""Score de priorité explicable : chaque point est justifié par une raison affichée dans le rapport."""

PRIORITES = [(75, "P1", "Critique"), (55, "P2", "Élevée"), (30, "P3", "Moyenne"), (0, "P4", "Faible")]


def _premiere_occurrence(incident, tactique):
    heures = [a["time"] for a in incident["alertes"] if tactique in a["tactics"]]
    return min(heures) if heures else None


def noter(incident):
    """Retourne (score 0-100, priorité, libellé, raisons). Heuristique pédagogique, pas un standard."""
    raisons = []
    niveau_max = max(a["level"] for a in incident["alertes"])
    score = niveau_max * 4
    raisons.append(f"+{niveau_max * 4} : niveau de règle maximal = {niveau_max}")

    etapes = len(incident["tactiques"])
    if etapes > 1:
        bonus = min(5, etapes - 1) * 6
        score += bonus
        raisons.append(f"+{bonus} : {etapes} tactiques ATT&CK enchaînées ({', '.join(incident['tactiques'])})")

    brute = _premiere_occurrence(incident, "Credential Access")
    acces = _premiere_occurrence(incident, "Initial Access")
    if brute and acces and brute <= acces:
        score += 20
        raisons.append("+20 : accès obtenu après des tentatives de mots de passe (compte probablement compromis)")

    for tactique, points in (("Persistence", 10), ("Privilege Escalation", 10), ("Impact", 10)):
        if tactique in incident["tactiques"]:
            score += points
            raisons.append(f"+{points} : présence de la tactique {tactique}")

    score = min(100, score)
    for seuil, code, libelle in PRIORITES:
        if score >= seuil:
            return score, code, libelle, raisons
