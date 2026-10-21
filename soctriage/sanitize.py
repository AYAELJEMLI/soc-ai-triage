"""
Les logs sont des données NON FIABLES : un attaquant contrôle des champs comme le nom d'utilisateur
tenté en SSH. Avant de donner quoi que ce soit à un modèle de langage, on nettoie ces champs et
on repère les tentatives d'injection de prompt (OWASP LLM01).
"""

import re

MOTIFS_INJECTION = [
    r"ignore[rz]?\s+(all|toutes|tous|les|tes|vos|previous|prior|pr[ée]c[ée]dentes?)",
    r"(previous|prior|pr[ée]c[ée]dentes?)\s+(instructions?|consignes?)",
    r"system\s+prompt|prompt\s+syst[eè]me",
    r"you\s+are\s+(now|a)\b|tu\s+es\s+(maintenant|un)\b",
    r"disregard|oublie\s+(tout|tes)",
    r"(mark|classif|class|marque|classe)\w*\s.{0,30}(resolved|false\s+positive|benign|faux\s+positif|r[ée]solu|b[ée]nin)",
    r"</?\s*(system|assistant|data|user)\s*>",
]
_COMPILES = [re.compile(m, re.IGNORECASE) for m in MOTIFS_INJECTION]
_CONTROLE = re.compile(r"[\x00-\x1f\x7f]")


def nettoyer(texte, longueur_max=120):
    """Supprime les caractères de contrôle, compacte les espaces et tronque."""
    texte = _CONTROLE.sub(" ", str(texte or ""))
    texte = re.sub(r"\s+", " ", texte).strip()
    return texte[:longueur_max]


def est_suspect(texte):
    return any(m.search(str(texte or "")) for m in _COMPILES)


def champ_sur(valeur):
    """Retourne (valeur utilisable, champ suspect ?). Un champ suspect est retiré, jamais transmis."""
    if est_suspect(valeur):
        return "[CHAMP SUSPECT RETIRÉ]", True
    return nettoyer(valeur), False
