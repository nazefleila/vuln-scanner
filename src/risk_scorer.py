"""
risk_scorer.py
---------------
Calcule un score de risque contextualisé à partir du score CVSS brut,
en tenant compte du port sur lequel le service est exposé.

Aucun appel réseau ici : uniquement du calcul, ce qui rend ce module
facile à tester unitairement.
"""

# Ports considérés comme "sensibles" : accès distant (SSH, RDP), partage
# de fichiers (SMB), ou bases de données. Si un service vulnérable tourne
# sur l'un de ces ports, le risque réel est plus élevé qu'un service
# identique sur un port web classique.
HIGH_EXPOSURE_PORTS = {21, 22, 23, 445, 3389, 3306, 5432, 6379, 27017}

# Seuils officiels du standard CVSS (https://www.first.org/cvss/)
# Liste de tuples (seuil_minimum, label), du plus grave au moins grave.
SEVERITY_THRESHOLDS = [
    (9.0, "Critique"),
    (7.0, "Élevée"),
    (4.0, "Moyenne"),
    (0.1, "Faible"),
    (0.0, "Informative"),
]


def compute_risk_score(cvss_score: float, port: int) -> float:
    """
    Calcule un score de risque à partir du score CVSS brut.
    Amplifie le score de 15% si le service tourne sur un port sensible,
    plafonné à 10.0 (l'échelle CVSS ne dépasse jamais 10).
    """
    # Facteur multiplicateur : 1.15 (soit +15%) si port sensible, sinon 1.0 (inchangé)
    exposure_factor = 1.15 if port in HIGH_EXPOSURE_PORTS else 1.0

    score = cvss_score * exposure_factor

    # min(score, 10.0) : on ne garde jamais plus que 10.0, même après amplification
    score = min(score, 10.0)

    # round(..., 1) : arrondi à 1 décimale pour un affichage propre (ex: 9.87 -> 9.9)
    return round(score, 1)


def severity_label(score: float) -> str:
    """
    Retourne un label lisible (Critique/Élevée/Moyenne/Faible/Informative)
    en fonction du score, selon les seuils CVSS officiels.
    """
    # On parcourt les seuils du plus élevé au plus bas (grâce à l'ordre de la liste).
    # Dès qu'on trouve un seuil <= au score, c'est la bonne catégorie.
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Informative"


if __name__ == "__main__":
    # Petits tests manuels pour vérifier que la logique a du sens
    print("CVSS 9.8 sur port 445 (SMB, sensible) :", compute_risk_score(9.8, 445),
          "->", severity_label(compute_risk_score(9.8, 445)))

    print("CVSS 9.8 sur port 8080 (non sensible) :", compute_risk_score(9.8, 8080),
          "->", severity_label(compute_risk_score(9.8, 8080)))

    print("CVSS 4.3 sur port 22 (SSH, sensible) :", compute_risk_score(4.3, 22),
          "->", severity_label(compute_risk_score(4.3, 22)))