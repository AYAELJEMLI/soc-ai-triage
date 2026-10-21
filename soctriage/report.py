"""Génération du rapport d'incidents au format Markdown."""

from .sanitize import champ_sur, est_suspect, nettoyer

ACTIONS = {
    "T1110.001": "Bloquer l'IP source (pare-feu ou Active Response), vérifier les comptes ciblés, préférer l'authentification SSH par clé.",
    "T1110": "Bloquer l'IP source, vérifier les comptes ciblés, activer un verrouillage après échecs (fail2ban).",
    "T1078": "Considérer le compte comme compromis : réinitialiser le mot de passe, révoquer les sessions, auditer l'activité depuis la connexion.",
    "T1548.003": "Vérifier /etc/sudoers et les commandes sudo exécutées, retirer les droits NOPASSWD inutiles.",
    "T1136.001": "Lister les comptes créés (/etc/passwd), supprimer le compte non autorisé, vérifier les clés SSH.",
    "T1565.001": "Comparer les fichiers modifiés à une référence saine, restaurer depuis une sauvegarde, identifier l'auteur (auditd).",
    "T1046": "Identifier la cible du scan, vérifier les services exposés, bloquer l'IP si elle est hors périmètre.",
}


def _source(incident):
    return ", ".join(incident["ips"]) if incident["ips"] else "locale (aucune IP source)"


def resume_deterministe(incident, code, libelle):
    return (f"Incident {code} ({libelle}) : {len(incident['alertes'])} alertes sur {', '.join(incident['agents'])}, "
            f"source {_source(incident)}, de {incident['debut']:%H:%M:%S} à {incident['fin']:%H:%M:%S}. "
            f"Tactiques observées : {', '.join(incident['tactiques']) or 'aucune'}.")


def drapeaux_injection(incident):
    """Liste les champs d'alerte qui ressemblent à une injection de prompt."""
    trouves = []
    for a in incident["alertes"]:
        for nom, valeur in (("compte", a["user"]), ("description", a["description"]), ("journal brut", a["full_log"])):
            if valeur and est_suspect(valeur):
                trouves.append((a["time"].strftime("%H:%M:%S"), nom, nettoyer(valeur, 90)))
    return trouves


def rapport_markdown(analyses, ignorees=0):
    """analyses : liste de dicts {incident, score, code, libelle, raisons, resume_ia}."""
    out = ["# Rapport de triage d'alertes", ""]
    out.append(f"{len(analyses)} incident(s) identifié(s), classés par priorité."
               + (f" {ignorees} ligne(s) invalide(s) ignorée(s)." if ignorees else ""))
    out.append("")
    out.append("| Priorité | Score | Source | Machines | Alertes | Techniques |")
    out.append("|---|---|---|---|---|---|")
    for a in analyses:
        i = a["incident"]
        out.append(f"| {a['code']} | {a['score']} | {_source(i)} | {', '.join(i['agents'])} | "
                   f"{len(i['alertes'])} | {', '.join(i['techniques'])} |")
    for n, a in enumerate(analyses, 1):
        i = a["incident"]
        out += ["", f"## Incident {n} : {a['code']} {a['libelle']} (score {a['score']}/100)", "",
                resume_deterministe(i, a["code"], a["libelle"]), "", "**Pourquoi ce score**", ""]
        out += [f"- {r}" for r in a["raisons"]]
        out += ["", "**Chronologie**", "", "| Heure | Niveau | Règle | Technique | Compte |", "|---|---|---|---|---|"]
        for al in i["alertes"]:
            compte, _ = champ_sur(al["user"]) if al["user"] else ("", False)
            out.append(f"| {al['time']:%H:%M:%S} | {al['level']} | {nettoyer(al['description'], 70)} | "
                       f"{', '.join(al['techniques'])} | {compte} |")
        out += ["", "**Éléments à retenir (IOC)**", "",
                f"- IP sources : {', '.join(i['ips']) or 'aucune'}",
                f"- Machines : {', '.join(i['agents'])}",
                f"- Comptes concernés : {', '.join(champ_sur(c)[0] for c in i['comptes']) or 'aucun'}"]
        actions = [ACTIONS[t] for t in i["techniques"] if t in ACTIONS]
        out += ["", "**Actions recommandées**", ""]
        out += [f"- {x}" for x in dict.fromkeys(actions)] or ["- Investigation manuelle nécessaire."]
        flags = drapeaux_injection(i)
        if flags:
            out += ["", "**Tentative d'injection de prompt détectée dans les journaux**", "",
                    "Ces champs contiennent des instructions adressées à une IA. Ils ont été retirés des données "
                    "transmises au modèle et doivent eux-mêmes être traités comme un indicateur d'attaque.", ""]
            out += [f"- {h} · champ « {nom} » : `{texte}`" for h, nom, texte in flags]
        if a.get("resume_ia"):
            out += ["", "**Résumé généré par IA (à vérifier, ne modifie pas la priorité)**", "", a["resume_ia"]]
    return "\n".join(out) + "\n"
