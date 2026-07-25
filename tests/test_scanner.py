"""
Tests unitaires pour scanner.py
Lancer avec : pytest tests\
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner import simplify_version


def test_simplify_version_extracts_major_minor():
    """Une version complète avec patch Ubuntu doit être réduite à major.minor."""
    assert simplify_version("6.6.1p1 Ubuntu 2ubuntu2.13") == "6.6"
    assert simplify_version("2.4.7") == "2.4"


def test_simplify_version_handles_no_digits():
    """Une version sans chiffres doit être retournée telle quelle."""
    assert simplify_version("") == ""
    assert simplify_version("unknown") == "unknown"