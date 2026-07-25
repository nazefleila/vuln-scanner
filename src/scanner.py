#!/usr/bin/env python3
"""
scanner.py
-----------
Point d'entrée du projet. Assemble les 4 modules en un pipeline complet :

  1. nmap_scanner  -> scan des ports/services ouverts
  2. cve_lookup    -> recherche des CVE pour chaque service
  3. risk_scorer   -> calcul du score de risque contextualisé
  4. report_generator -> génération du rapport final

Exemple :
  python src\\scanner.py --target scanme.nmap.org --fast
"""

import argparse
import os
from dotenv import load_dotenv

# Import des 4 modules qu'on a écrits précédemment.
# Comme tous les fichiers sont dans le même dossier src/, un import simple suffit.
from nmap_scanner import scan as nmap_scan
from cve_lookup import search_cve
from risk_scorer import compute_risk_score, severity_label
from report_generator import generate_markdown, save_report

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")


def parse_args():
    """Définit les arguments acceptés en ligne de commande."""
    parser = argparse.ArgumentParser(description="Scanner de vulnérabilités automatisé.")
    parser.add_argument("--target", required=True, help="Cible à scanner (IP, CIDR, ou hostname)")
    parser.add_argument("--fast", action="store_true", help="Scan rapide (top 20 ports)")
    parser.add_argument("--output", default="report.md", help="Nom du fichier de rapport")
    parser.add_argument("--max-cve", type=int, default=3, help="Nombre max de CVE par service")
    return parser.parse_args()


def run_pipeline(target: str, fast: bool, max_cve: int) -> list[dict]:
    """
    Exécute le pipeline complet et retourne la liste des findings,
    prête à être passée au générateur de rapport.
    """
    print(f"[1/4] Scan Nmap de {target}...")
    services = nmap_scan(target, fast=fast)
    print(f"      -> {len(services)} service(s) ouvert(s) détecté(s)")

    findings = []

    print("[2/4] Recherche des CVE pour chaque service...")
    for svc in services:
        # Construit une requête du type "OpenSSH 6.6.1p1" pour l'API NVD.
        # Si le produit n'a pas été détecté par Nmap (chaîne vide),
        # on retombe sur le simple nom du service (ex: "ssh").
        query = f"{svc['product']} {svc['version']}".strip() or svc["service"]
        if not query:
            continue

        cves = search_cve(query, api_key=NVD_API_KEY, max_results=max_cve)

        print(f"      -> {svc['host']}:{svc['port']} ({query}) : {len(cves)} CVE trouvée(s)")

        # [3/4] Pour chaque CVE trouvée, on calcule le score de risque contextualisé
        for cve in cves:
            risk = compute_risk_score(cve["cvss_score"], svc["port"])
            findings.append({
                "host": svc["host"],
                "port": svc["port"],
                "service": f"{svc['service']} ({query})",
                "cve_id": cve["id"],
                "cvss_score": cve["cvss_score"],
                "risk_score": risk,
                "severity": severity_label(risk),
                "description": cve["description"][:200],  # on tronque pour un rapport plus lisible
            })

    return findings


def main():
    args = parse_args()

    findings = run_pipeline(args.target, args.fast, args.max_cve)

    print(f"[4/4] Génération du rapport ({len(findings)} finding(s))...")
    report = generate_markdown(args.target, findings)
    save_report(report, args.output)

    print(f"\nRapport généré : {args.output}")


if __name__ == "__main__":
    main()