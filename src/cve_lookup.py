import os
from dotenv import load_dotenv

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(keyword: str, api_key: str = None, max_results: int = 5) -> list[dict]:
    """
    Cherche les CVE correspondant à un mot-clé (ex: "Apache 2.4.7").
    Retourne une liste de dicts : [{"id": ..., "description": ..., "cvss_score": ...}, ...]
    triée par score CVSS décroissant.
    """
    if not keyword.strip():
        # Si Nmap n'a pas réussi à détecter de produit (product vide),
        # inutile d'interroger l'API avec une chaîne vide.
        return []

    # Les paramètres de la requête GET. requests les transforme automatiquement
    # en "?keywordSearch=Apache+2.4.7&resultsPerPage=5" dans l'URL.
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    # Si on a une clé API, on l'envoie dans les headers pour avoir un
    # rate-limit plus élevé (50 req/30s au lieu de 5 req/30s).
    headers = {"User-Agent": "vuln-scanner-project/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        response.raise_for_status()  # lève une exception si code HTTP 4xx/5xx
    except requests.RequestException as exc:
        # On n'arrête JAMAIS tout le programme pour une seule requête ratée.
        # On log l'erreur et on retourne une liste vide, pour que le reste
        # du scan continue sur les autres services.
        print(f"[!] Erreur API NVD pour '{keyword}': {exc}")
        return []
    finally:
        # Respecte le rate limit de l'API, que la requête ait réussi ou non.
        # Sans clé : max 5 req/30s -> on attend un peu plus de 6s par sécurité.
        # Avec clé : max 50 req/30s -> ~0.7s suffit, on met 1s par sécurité.
        time.sleep(1.0 if api_key else 6.5)

    data = response.json()
    results = []

    # La réponse JSON a la forme : {"vulnerabilities": [{"cve": {...}}, ...]}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # Les descriptions existent en plusieurs langues, on prend l'anglaise.
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "Pas de description disponible."
        )

        # Le score CVSS peut être rangé sous différentes clés selon l'âge
        # de la CVE (les nouvelles utilisent CVSS v3.1, les anciennes v2).
        # On essaie dans l'ordre du plus récent au plus ancien.
        metrics = cve.get("metrics", {})
        score = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                break

        results.append({
            "id": cve_id,
            "description": description,
            "cvss_score": float(score),
        })

    # Tri décroissant : la CVE la plus grave en premier.
    results.sort(key=lambda c: c["cvss_score"], reverse=True)
    return results


if __name__ == "__main__":
    matches = search_cve("Apache 2.4.7", api_key=NVD_API_KEY, max_results=3)
    for m in matches:
        print(m)