"""
Tests unitaires pour risk_scorer.py
Lancer avec : pytest tests\
"""

import sys
import os

# Ajoute le dossier src/ au chemin de recherche Python, pour pouvoir
# importer risk_scorer.py même si ce test est dans un dossier différent.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from risk_scorer import compute_risk_score, severity_label


def test_high_exposure_port_increases_risk():
    """Un port sensible (445) doit donner un score plus élevé qu'un port normal, à CVSS égal."""
    score_sensitive = compute_risk_score(8.0, port=445)
    score_normal = compute_risk_score(8.0, port=8080)
    assert score_sensitive > score_normal


def test_risk_score_never_exceeds_10():
    """Le score de risque ne doit jamais dépasser 10.0, même amplifié."""
    score = compute_risk_score(9.9, port=3389)
    assert score <= 10.0


def test_severity_labels():
    assert severity_label(9.5) == "Critique"
    assert severity_label(7.5) == "Élevée"
    assert severity_label(5.0) == "Moyenne"
    assert severity_label(1.0) == "Faible"