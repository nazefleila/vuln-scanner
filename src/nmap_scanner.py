"""
nmap_scanner.py
-----------------
Scanne une cible avec Nmap et retourne une liste de services détectés,
en ne gardant que les ports ouverts.
"""

import nmap


def scan(target: str, fast: bool = True) -> list[dict]:
    """
    Scanne la cible et retourne une liste de dictionnaires :
    [{"host": ..., "port": ..., "service": ..., "product": ..., "version": ...}, ...]
    Ne garde que les ports dont l'état est "open".
    """
    scanner = nmap.PortScanner()

    # -sV = détection de version, indispensable dans les DEUX cas car sans ça
    # on n'aurait que le nom du port (ex: "http") sans savoir quel logiciel
    # tourne dessus (ex: "Apache 2.4.7") — et c'est CE détail qu'on utilisera
    # ensuite pour chercher les CVE.
    if fast:
        arguments = "-sV --top-ports 20"
    else:
        arguments = "-sV -p-"

    scanner.scan(hosts=target, arguments=arguments)

    results = []

    # all_hosts() retourne la liste des IP/hosts qui ont répondu au scan
    # (ex: ['45.33.32.156']). S'il n'y a rien, la boucle ne fait juste rien.
    for host in scanner.all_hosts():

        # all_protocols() retourne les protocoles scannés pour CET host
        # (généralement juste ['tcp'], parfois ['tcp', 'udp'] si demandé)
        for proto in scanner[host].all_protocols():

            # scanner[host][proto] est un dictionnaire dont les CLÉS sont
            # les numéros de port (ex: {21: {...}, 22: {...}, 80: {...}}).
            # .keys() nous donne juste la liste des numéros de port.
            ports = scanner[host][proto].keys()

            for port in ports:
                port_info = scanner[host][proto][port]

                # On ignore tout ce qui n'est pas "open" : un port "closed"
                # ou "filtered" n'a aucun service exploitable dessus, donc
                # ça ne sert à rien de chercher des CVE pour un port fermé.
                if port_info.get("state") != "open":
                    continue

                results.append({
                    "host": host,
                    "port": port,
                    "service": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                })

    return results


# Ce bloc ne s'exécute QUE si tu lances ce fichier directement
# (python src\nmap_scanner.py), pas s'il est importé depuis un autre fichier.
# C'est le pattern standard en Python pour ajouter un "mode test" à un module.
if __name__ == "__main__":
    findings = scan("scanme.nmap.org", fast=True)
    for f in findings:
        print(f)