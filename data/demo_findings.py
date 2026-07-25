"""
demo_findings.py
------------------
Données de démonstration pré-calculées, utilisées en mode démo du dashboard
quand Nmap n'est pas disponible (ex: hébergement cloud sans accès réseau bas niveau).

Ces données viennent d'un vrai scan effectué localement sur scanme.nmap.org,
la cible de test officielle fournie par l'équipe Nmap.
"""

DEMO_FINDINGS = [
    {
        "Hôte": "45.33.32.156",
        "Port": 22,
        "Service": "ssh (OpenSSH 6.6)",
        "CVE": "CVE-2015-5600",
        "CVSS": 8.5,
        "Risque": 9.8,
        "Sévérité": "Critique",
    },
    {
        "Hôte": "45.33.32.156",
        "Port": 22,
        "Service": "ssh (OpenSSH 6.6)",
        "CVE": "CVE-2016-6210",
        "CVSS": 5.9,
        "Risque": 6.8,
        "Sévérité": "Moyenne",
    },
    {
        "Hôte": "45.33.32.156",
        "Port": 80,
        "Service": "http (Apache httpd 2.4)",
        "CVE": "CVE-2021-44224",
        "CVSS": 8.2,
        "Risque": 8.2,
        "Sévérité": "Élevée",
    },
    {
        "Hôte": "45.33.32.156",
        "Port": 80,
        "Service": "http (Apache httpd 2.4)",
        "CVE": "CVE-2016-6814",
        "CVSS": 9.8,
        "Risque": 9.8,
        "Sévérité": "Critique",
    },
    {
        "Hôte": "45.33.32.156",
        "Port": 80,
        "Service": "http (Apache httpd 2.4)",
        "CVE": "CVE-2012-2378",
        "CVSS": 4.3,
        "Risque": 4.3,
        "Sévérité": "Moyenne",
    },
]

DEMO_SERVICES_COUNT = 2