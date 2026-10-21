"""Regroupement des alertes en incidents."""

from collections import defaultdict

# Ordre approximatif d'une intrusion (tactiques MITRE ATT&CK)
CHAINE = ["Reconnaissance", "Discovery", "Initial Access", "Credential Access", "Execution",
          "Persistence", "Privilege Escalation", "Defense Evasion", "Lateral Movement",
          "Collection", "Exfiltration", "Impact"]


def _rang(tactique):
    return CHAINE.index(tactique) if tactique in CHAINE else len(CHAINE)


def _finaliser(cle, alertes):
    alertes = sorted(alertes, key=lambda a: a["time"])
    tactiques, techniques = [], []
    for a in alertes:
        for t in a["tactics"]:
            if t not in tactiques:
                tactiques.append(t)
        for t in a["techniques"]:
            if t not in techniques:
                techniques.append(t)
    return {
        "cle": cle,
        "alertes": alertes,
        "debut": alertes[0]["time"],
        "fin": alertes[-1]["time"],
        "agents": sorted({a["agent"] for a in alertes}),
        "ips": sorted({a["srcip"] for a in alertes if a["srcip"]}),
        "comptes": sorted({a["user"] for a in alertes if a["user"]}),
        "tactiques": sorted(tactiques, key=_rang),
        "techniques": techniques,
    }


def construire_incidents(alertes, fenetre_s=900, niveau_min=5):
    """
    1. On écarte le bruit : alertes de niveau < niveau_min SANS technique MITRE
       (une alerte de niveau bas mais mappée ATT&CK reste utile, ex. connexion réussie).
    2. On groupe par IP source ; une pause de plus de fenetre_s secondes ouvre un nouvel incident.
    3. Une alerte locale sans IP (sudo, création de compte, modification de fichier) est rattachée
       à l'incident récent de la même machine ; sinon elle forme un incident à part.
    """
    utiles = [a for a in alertes if a["level"] >= niveau_min or a["techniques"]]
    utiles.sort(key=lambda a: a["time"])

    avec_ip = defaultdict(list)
    sans_ip = []
    for a in utiles:
        (avec_ip[a["srcip"]] if a["srcip"] else sans_ip).append(a)

    groupes = []  # liste de (cle, [alertes])
    for ip, liste in avec_ip.items():
        courant = [liste[0]]
        for a in liste[1:]:
            if (a["time"] - courant[-1]["time"]).total_seconds() > fenetre_s:
                groupes.append((ip, courant))
                courant = [a]
            else:
                courant.append(a)
        groupes.append((ip, courant))

    restes = []
    for a in sans_ip:
        candidats = [g for g in groupes
                     if any(x["agent"] == a["agent"] for x in g[1])
                     and 0 <= (a["time"] - g[1][-1]["time"]).total_seconds() <= fenetre_s]
        if candidats:
            max(candidats, key=lambda g: g[1][-1]["time"])[1].append(a)
        else:
            restes.append(a)

    par_agent = defaultdict(list)
    for a in restes:
        par_agent[a["agent"]].append(a)
    for agent, liste in par_agent.items():
        groupes.append((f"agent:{agent}", liste))

    return [_finaliser(cle, liste) for cle, liste in groupes]
