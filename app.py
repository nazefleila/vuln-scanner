"""
app.py
-------
Interface web Streamlit pour lancer des scans et visualiser les résultats
sans passer par la ligne de commande.

Lancer avec : streamlit run app.py
"""

import streamlit as st
import pandas as pd
import sys
import os
from data.demo_findings import DEMO_FINDINGS, DEMO_SERVICES_COUNT
# Permet d'importer les modules du dossier src/ depuis ce fichier
# situé à la racine du projet.
sys.path.insert(0, "src")

from nmap_scanner import scan as nmap_scan
from cve_lookup import search_cve
from risk_scorer import compute_risk_score, severity_label
from scanner import simplify_version
from dotenv import load_dotenv

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Configuration de la page (titre de l'onglet navigateur, icône, largeur)
st.set_page_config(page_title="Vuln Scanner", page_icon="🔍", layout="wide")
demo_mode = st.toggle(
    "🎭 Mode démo (sans Nmap, utilise des résultats pré-calculés)",
    value=True,
    help="Désactive ce mode si tu utilises l'app en local avec Nmap installé, pour lancer un vrai scan."
)
st.title("🔍 Vuln-Scanner Dashboard")
st.caption("Scanner de vulnérabilités automatisé avec scoring de risque CVSS")

# --- Formulaire de saisie ---
col1, col2 = st.columns([3, 1])
with col1:
    target = st.text_input("Cible à scanner", value="scanme.nmap.org")
with col2:
    fast = st.checkbox("Scan rapide (top 20 ports)", value=True)
if st.button("🚀 Lancer le scan", type="primary"):

    if demo_mode:
        # --- MODE DÉMO : pas d'appel réseau, données pré-calculées ---
        st.info("🎭 Mode démo activé — affichage de résultats pré-calculés (scan réel effectué localement).")
        findings = DEMO_FINDINGS
        services_count = DEMO_SERVICES_COUNT
    else:
        # --- MODE RÉEL : scan Nmap + recherche CVE en direct ---
        with st.spinner("Scan Nmap en cours..."):
            try:
                services = nmap_scan(target, fast=fast)
            except Exception as e:
                st.error(f"Erreur Nmap : {e}. Essaie le mode démo si Nmap n'est pas disponible sur ce serveur.")
                st.stop()

        services_count = len(services)
        st.success(f"{services_count} service(s) ouvert(s) détecté(s)")

        findings = []
        progress_bar = st.progress(0)

        for i, svc in enumerate(services):
            simplified = simplify_version(svc["version"])
            query = f"{svc['product']} {simplified}".strip() or svc["service"]

            if query:
                cves = search_cve(query, api_key=NVD_API_KEY, max_results=3)
                for cve in cves:
                    risk = compute_risk_score(cve["cvss_score"], svc["port"])
                    findings.append({
                        "Hôte": svc["host"],
                        "Port": svc["port"],
                        "Service": f"{svc['service']} ({query})",
                        "CVE": cve["id"],
                        "CVSS": cve["cvss_score"],
                        "Risque": risk,
                        "Sévérité": severity_label(risk),
                    })

            progress_bar.progress((i + 1) / len(services))

    # --- Affichage commun aux deux modes ---
    if findings:
        df = pd.DataFrame(findings)
        df = df.sort_values("Risque", ascending=False)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total findings", len(df))
        col2.metric("Critiques", len(df[df["Sévérité"] == "Critique"]))
        col3.metric("Élevées", len(df[df["Sévérité"] == "Élevée"]))
        col4.metric("Score max", df["Risque"].max())

        st.subheader("Résultats détaillés")
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Aucune CVE trouvée pour les services détectés.")

else:
    st.info("👆 Entre une cible et clique sur 'Lancer le scan' pour commencer.")