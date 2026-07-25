"""
report_generator.py
---------------------
Assemble les findings (host + port + CVE + score de risque) en un
rapport Markdown lisible, trié du plus critique au moins critique.
"""

from datetime import datetime


def generate_markdown(target: str, findings: list[dict]) -> str:
    """
    Génère le contenu Markdown complet du rapport.
    findings : liste de dicts avec les clés host, port, service, cve_id,
               cvss_score, risk_score, severity.
    """
    # Trie la liste par risk_score décroissant AVANT de générer le rapport.
    # C'est la partie la plus importante : sans ce tri, le rapport ne sert
    # à rien pour prioriser les corrections.
    sorted_findings = sorted(findings, key=lambda f: f["risk_score"], reverse=True)

    date = datetime.now().strftime("%Y-%m-%d %H:%M")

    # On construit le rapport ligne par ligne dans une liste, puis on
    # assemble tout à la fin avec "\n".join(...). C'est plus propre et
    # plus rapide que de faire des += sur une string au fur et à mesure.
    lines = [
        f"# Rapport de scan — {target}",
        "",
        f"*Généré le {date} — {len(sorted_findings)} finding(s)*",
        "",
        "| Hôte | Port | Service | CVE | CVSS | Risque | Sévérité |",
        "|------|------|---------|-----|------|--------|----------|",
    ]

    if not sorted_findings:
        lines.append("| — | — | — | Aucune CVE trouvée | — | — | — |")
    else:
        for f in sorted_findings:
            lines.append(
                f"| {f['host']} | {f['port']} | {f['service']} | {f['cve_id']} | "
                f"{f['cvss_score']} | {f['risk_score']} | {f['severity']} |"
            )

    # Section détaillée en dessous du tableau, avec la description de chaque CVE
    lines.append("")
    lines.append("## Détails")
    for f in sorted_findings:
        lines.append(f"\n### {f['cve_id']} — {f['host']}:{f['port']} ({f['service']})")
        lines.append(f"- **Score de risque** : {f['risk_score']} ({f['severity']})")
        lines.append(f"- **Description** : {f['description']}")

    return "\n".join(lines)


def save_report(content: str, filepath: str) -> None:
    """Écrit le contenu du rapport dans un fichier."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    # Données factices pour tester la génération sans dépendre des autres modules
    fake_findings = [
        {"host": "45.33.32.156", "port": 445, "service": "smb", "cve_id": "CVE-2017-7494",
         "cvss_score": 9.8, "risk_score": 10.0, "severity": "Critique",
         "description": "Exécution de code à distance via Samba."},
        {"host": "45.33.32.156", "port": 22, "service": "ssh", "cve_id": "CVE-2018-15473",
         "cvss_score": 5.3, "risk_score": 5.3, "severity": "Moyenne",
         "description": "Énumération d'utilisateurs via timing attack."},
    ]

    report = generate_markdown("45.33.32.156", fake_findings)
    save_report(report, "report_test.md")
    print("Rapport généré dans report_test.md")
    print(report)