import argparse
import os
import sys

from .incidents import construire_incidents
from .llm import faits_surs, resumer
from .parser import charger_alertes
from .report import rapport_markdown
from .scoring import noter


def main():
    p = argparse.ArgumentParser(prog="soctriage", description="Tri d'alertes Wazuh en incidents priorisés")
    p.add_argument("alertes", help="fichier d'alertes (un objet JSON par ligne)")
    p.add_argument("--fenetre", type=int, default=900, help="pause (s) qui sépare deux incidents (défaut 900)")
    p.add_argument("--niveau-min", type=int, default=5, help="niveau minimal hors alertes mappées ATT&CK (défaut 5)")
    p.add_argument("--sortie", default="rapport.md", help="fichier Markdown de sortie")
    p.add_argument("--llm", metavar="MODELE", help="ajoute un résumé IA via Ollama local (ex. llama3.2:3b)")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434/api/generate")
    a = p.parse_args()

    try:
        alertes, ignorees = charger_alertes(a.alertes)
    except FileNotFoundError:
        print(f"Fichier introuvable : {a.alertes}", file=sys.stderr)
        return 1

    analyses = []
    for inc in construire_incidents(alertes, a.fenetre, a.niveau_min):
        score, code, libelle, raisons = noter(inc)
        resume_ia = None
        if a.llm:
            faits, _ = faits_surs(inc, code)
            resume_ia = resumer(faits, a.llm, a.ollama_url)
            if resume_ia is None:
                print("Modèle local injoignable : résumé IA ignoré (le rapport reste complet).", file=sys.stderr)
        analyses.append({"incident": inc, "score": score, "code": code, "libelle": libelle,
                         "raisons": raisons, "resume_ia": resume_ia})
    analyses.sort(key=lambda x: -x["score"])

    print(f"{len(alertes)} alertes lues, {len(analyses)} incident(s)\n")
    print(f"{'Prio':5s}{'Score':>6s}  {'Source':16s}{'Alertes':>8s}  Techniques")
    for x in analyses:
        i = x["incident"]
        print(f"{x['code']:5s}{x['score']:>6d}  {(i['ips'] or ['locale'])[0]:16s}{len(i['alertes']):>8d}  {', '.join(i['techniques'])}")

    dossier = os.path.dirname(a.sortie)
    if dossier:
        os.makedirs(dossier, exist_ok=True)
    with open(a.sortie, "w", encoding="utf-8") as f:
        f.write(rapport_markdown(analyses, ignorees))
    print(f"\nRapport écrit dans {a.sortie}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
