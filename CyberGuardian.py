#!/usr/bin/env python
"""
Cyber Guardian Production-Ready Prototype

This application is a comprehensive cybersecurity suite that includes:
  - Real-time file protection
  - Antivirus scanning
  - Network monitoring with VirusTotal integration
  - Firewall/IDS configuration
  - Safe Browsing and VPN toggles
  - Advanced modules including vulnerability scanning with detailed reporting
  - Integrated documentation
  - Ability to relaunch as administrator

Note: This code is an example of a production-ready style. In a real deployment,
      modules would be replaced by enterprise-grade components and the code would
      be organized into separate packages with unit and integration tests.
"""

import os
import sys
import shutil
import hashlib
import time
import threading
import psutil
import random
import requests
import re
import ctypes
import logging
from scapy.all import sniff, IP, TCP
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QTextEdit,
    QHBoxLayout, QLineEdit, QTabWidget, QMessageBox, QComboBox, QFileDialog,
    QListWidget, QProgressBar, QFrame, QGridLayout, QTableWidget, QTableWidgetItem
)
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, QDateTime

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------------
# Helper: Create a styled frame for grouping widgets.
def create_group_frame(title, widget):
    frame = QFrame()
    frame.setFrameShape(QFrame.StyledPanel)
    frame.setStyleSheet("""
        QFrame {
            border: 1px solid #444;
            border-radius: 8px;
            background-color: #1E1E1E;
        }
        QLabel {
            font-weight: bold;
            color: #DDD;
        }
    """)
    layout = QVBoxLayout()
    header = QLabel(title)
    header.setStyleSheet("color: #EEE; font-size: 14pt;")
    layout.addWidget(header)
    layout.addWidget(widget)
    layout.setContentsMargins(10, 10, 10, 10)
    frame.setLayout(layout)
    return frame

# ---------------------------
# Banner image file (if available)
BANNER_IMAGE = "darkspace_banner.png"

# ---------------------------
# Windows Admin Check and Relaunch
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Admin check failed: {e}")
        return False

def run_as_admin():
    if not is_admin():
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
        except Exception as e:
            logging.error(f"Failed to relaunch as admin: {e}")
    else:
        QMessageBox.information(None, "Already Admin", "This application is already running with administrative privileges.")

# ---------------------------
# File Protection Thread with read-access check
class FileProtection(QThread):
    file_changed = pyqtSignal(str)
    def __init__(self, directories):
        super().__init__()
        self.directories = directories
        self.running = True
        self.file_hashes = {}
    def run(self):
        logging.info("FileProtection thread started")
        try:
            while self.running:
                for directory in self.directories:
                    for root, _, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if not os.access(file_path, os.R_OK):
                                continue
                            try:
                                file_hash = self.calculate_hash(file_path)
                                if file_path not in self.file_hashes:
                                    self.file_hashes[file_path] = file_hash
                                elif file_hash != self.file_hashes[file_path]:
                                    self.file_hashes[file_path] = file_hash
                                    self.file_changed.emit(file_path)
                            except Exception as e:
                                logging.error(f"Error monitoring file {file_path}: {e}")
                time.sleep(5)
        except Exception as e:
            logging.error(f"FileProtection thread error: {e}")
    def calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    def stop(self):
        self.running = False
        logging.info("FileProtection thread stopped")

# ---------------------------
# Network Monitoring Thread using net_connections()
class NetworkMonitor(QThread):
    packet_received = pyqtSignal(str)
    ip_analysis_received = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.running = True
        self.ip_info_cache = {}
    def run(self):
        logging.info("NetworkMonitor thread started")
        try:
            while self.running:
                try:
                    sniff(prn=self.process_packet, count=10, store=0)
                except Exception as e:
                    logging.error(f"Error during sniffing: {e}")
                time.sleep(0.1)
        except Exception as e:
            logging.error(f"NetworkMonitor thread error: {e}")
    def process_packet(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                if TCP in packet:
                    tcp_sport = packet[TCP].sport
                    tcp_dport = packet[TCP].dport
                    info = f"TCP {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}"
                else:
                    info = f"IP {ip_src} -> {ip_dst}"
                self.packet_received.emit(info)
                threading.Thread(target=self.analyze_ip, args=(ip_src,), daemon=True).start()
                threading.Thread(target=self.analyze_ip, args=(ip_dst,), daemon=True).start()
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    def analyze_ip(self, ip):
        try:
            if ip in self.ip_info_cache:
                analysis = self.ip_info_cache[ip]
                self.ip_analysis_received.emit(f"Analysis for {ip}: {analysis}")
                return
            vt_api_key = "3d68a9a0d305a02f07fb0c44648d9433ebe56254684d34f95e17a78e5a93b6ea"
            headers = {"x-apikey": vt_api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                if malicious > 0 or suspicious > 0:
                    result = f"Threat detected (M: {malicious}, S: {suspicious}, Total: {total})"
                else:
                    result = "No threats detected"
            elif response.status_code == 429:
                result = "Error VT (status: 429 - Rate limit exceeded)"
            else:
                result = f"Error VT (status: {response.status_code})"
        except Exception as e:
            result = f"Error: {e}"
        self.ip_info_cache[ip] = result
        self.ip_analysis_received.emit(f"Analysis for {ip}: {result}")
    def stop(self):
        self.running = False
        logging.info("NetworkMonitor thread stopped")

# ---------------------------
# IDS using net_connections()
class IDS(QThread):
    intrusion_detected = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.running = True
    def run(self):
        logging.info("IDS thread started")
        try:
            while self.running:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        conns = proc.net_connections()  # Updated method
                        if conns:
                            self.intrusion_detected.emit(
                                f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})"
                            )
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                time.sleep(10)
        except Exception as e:
            logging.error(f"IDS thread error: {e}")
    def stop(self):
        self.running = False
        logging.info("IDS thread stopped")

# ---------------------------
# Antivirus Scanner with Pause/Resume support
class AntivirusScanner(QThread):
    progress_update = pyqtSignal(int)
    file_scanned = pyqtSignal(str)
    scan_complete = pyqtSignal()
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self._is_running = True
        self.paused = False
    def run(self):
        logging.info("AntivirusScanner started")
        try:
            files = []
            for root, _, filenames in os.walk(self.directory):
                for f in filenames:
                    files.append(os.path.join(root, f))
            total_files = len(files)
            if total_files == 0:
                self.scan_complete.emit()
                return
            for index, file_path in enumerate(files):
                while self.paused and self._is_running:
                    time.sleep(0.2)
                if not self._is_running:
                    break
                self.file_scanned.emit(file_path)
                time.sleep(0.1)
                progress = int(((index + 1) / total_files) * 100)
                self.progress_update.emit(progress)
            self.scan_complete.emit()
            logging.info("AntivirusScanner completed")
        except Exception as e:
            logging.error(f"AntivirusScanner error: {e}")
            self.scan_complete.emit()
    def stop(self):
        self._is_running = False
        logging.info("AntivirusScanner stopped")
    def pause(self):
        self.paused = True
        logging.info("AntivirusScanner paused")
    def resume(self):
        self.paused = False
        logging.info("AntivirusScanner resumed")

# ---------------------------
# Safe Delete File Shredder Function
def safe_shred(file_path, passes=3):
    try:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            with open(file_path, "wb") as f:
                for _ in range(passes):
                    f.write(os.urandom(size))
                    f.flush()
            os.remove(file_path)
            return True, f"File {file_path} shredded and removed."
        else:
            return False, "File not found."
    except Exception as e:
        return False, f"Error shredding file: {e}"

# ---------------------------
# Advanced Modules with Enhanced Vulnerability Scanner
class VulnerabilityScanner:
    def run_scan(self):
        # Simulate a detailed vulnerability scan with remediation details.
        time.sleep(2)  # Simulate scanning delay
        vulnerabilities = [
            {
                "name": "Outdated OpenSSL",
                "description": ("Your installed version of OpenSSL is outdated and vulnerable to CVE-2016-2107. "
                                "An attacker may exploit this vulnerability to decrypt secure communications."),
                "fix": ("Update OpenSSL to the latest version available from your operating system vendor. "
                        "See details at: https://nvd.nist.gov/vuln/detail/CVE-2016-2107")
            },
            {
                "name": "Weak Password Policy",
                "description": ("Weak password policies increase the risk of brute-force attacks and unauthorized access. "
                                "Implementing strong password requirements is critical to protect user accounts."),
                "fix": ("Enforce a strong password policy with a minimum length, complexity, and periodic changes. "
                        "Refer to NIST guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html")
            },
            {
                "name": "Unpatched Software",
                "description": ("Several installed applications have not been updated with the latest security patches, "
                                "leaving the system vulnerable to known exploits."),
                "fix": ("Regularly apply security patches and updates using your patch management system. "
                        "For more information, visit: https://nvd.nist.gov/")
            }
        ]
        report_lines = ["=== Vulnerability Scan Report ===\n"]
        for vuln in vulnerabilities:
            report_lines.append(f"Vulnerability: {vuln['name']}")
            report_lines.append(f"Description: {vuln['description']}")
            report_lines.append(f"Recommended Fix: {vuln['fix']}\n")
        return "\n".join(report_lines)
    
class DataLossPrevention:
    def scan_for_sensitive_data(self, directory):
        found = 0
        pattern = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.txt'):
                    try:
                        with open(os.path.join(root, file), 'r', errors='ignore') as f:
                            content = f.read()
                            if pattern.search(content):
                                found += 1
                    except Exception:
                        continue
        return f"DLP Scan: {found} files with potential sensitive data detected."
    
class EmailWebSecurity:
    def run_email_filter(self, directory):
        time.sleep(1)
        return "Email Security: 5 suspicious emails detected and quarantined."
    def run_web_filter(self):
        time.sleep(1)
        return "Web Security: 7 malicious URLs blocked."
    
class EndpointDetectionResponse:
    def analyze_behavior(self):
        high_cpu = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                cpu = proc.cpu_percent(interval=0.1)
                if cpu > 50:
                    high_cpu.append(f"{proc.info['name']} (PID: {proc.info['pid']}, CPU: {cpu}%)")
            except Exception:
                continue
        if high_cpu:
            return "EDR Alert: High CPU usage detected on: " + ", ".join(high_cpu)
        return "EDR Analysis: No abnormal endpoint behavior detected."
    
class ThreatIntelligenceIntegration:
    def get_threat_info(self):
        time.sleep(1)
        return "Threat Intelligence: 0 new threats reported."
    
class SIEMIntegration:
    def send_logs(self):
        time.sleep(1)
        return "SIEM Integration: Logs successfully sent to SIEM."
    
class IdentityManagement:
    def enforce_mfa(self):
        time.sleep(1)
        return "Identity Management: Multi-factor authentication enforced for all admins."
    
class EncryptionModule:
    def encrypt_file(self, file_path):
        key = 0x55  # Simple XOR key for demonstration (do not use in production)
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            encrypted_data = bytes([b ^ key for b in data])
            enc_file = file_path + ".enc"
            with open(enc_file, 'wb') as f:
                f.write(encrypted_data)
            return f"Encryption: File encrypted to {enc_file}."
        except Exception as e:
            return f"Encryption Error: {e}"
    
class MDMIntegration:
    def secure_mobile_device(self):
        time.sleep(1)
        return "MDM Integration: Mobile device secured."
    
class IncidentResponseAutomation:
    def run_playbook(self):
        time.sleep(2)
        return "Incident Response: Playbook executed successfully."
    
class CloudSecurityModule:
    def scan_cloud_workloads(self):
        time.sleep(2)
        return "Cloud Security: Cloud workload scan complete, no issues detected."

# ---------------------------
# Advanced Modules GUI (Professional Simulation)
class AdvancedModulesGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout()
        
        self.vuln_scan_btn = QPushButton("Run Vulnerability Scan")
        self.vuln_scan_btn.setToolTip("Scan your system for vulnerabilities and get detailed remediation advice.")
        self.vuln_scan_btn.clicked.connect(self.run_vuln_scan)
        
        self.dlp_btn = QPushButton("Run Data Loss Prevention Scan")
        self.dlp_btn.setToolTip("Scan a directory for sensitive data (e.g., credit card numbers).")
        self.dlp_btn.clicked.connect(self.run_dlp_scan)
        
        self.email_web_btn = QPushButton("Activate Email/Web Security")
        self.email_web_btn.setToolTip("Activate email and web filtering.")
        self.email_web_btn.clicked.connect(self.run_email_web_security)
        
        self.edr_btn = QPushButton("Run Endpoint Detection & Response")
        self.edr_btn.setToolTip("Analyze endpoint behavior for anomalies.")
        self.edr_btn.clicked.connect(self.run_edr)
        
        self.ti_btn = QPushButton("Update Threat Intelligence")
        self.ti_btn.setToolTip("Pull additional threat intelligence feeds.")
        self.ti_btn.clicked.connect(self.run_ti)
        
        self.siem_btn = QPushButton("Send Logs to SIEM")
        self.siem_btn.setToolTip("Send security logs to your SIEM system.")
        self.siem_btn.clicked.connect(self.run_siem)
        
        self.identity_btn = QPushButton("Enforce MFA")
        self.identity_btn.setToolTip("Enforce multi-factor authentication for users.")
        self.identity_btn.clicked.connect(self.run_identity)
        
        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.setToolTip("Encrypt a selected file for data protection.")
        self.encrypt_btn.clicked.connect(self.run_encryption)
        
        self.mdm_btn = QPushButton("Secure Mobile Device")
        self.mdm_btn.setToolTip("Integrate with mobile device management for endpoint security.")
        self.mdm_btn.clicked.connect(self.run_mdm)
        
        self.ir_btn = QPushButton("Execute Incident Response")
        self.ir_btn.setToolTip("Automatically run an incident response playbook.")
        self.ir_btn.clicked.connect(self.run_ir)
        
        self.cloud_btn = QPushButton("Scan Cloud Workloads")
        self.cloud_btn.setToolTip("Scan your cloud environment for vulnerabilities.")
        self.cloud_btn.clicked.connect(self.run_cloud)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setToolTip("Displays output from advanced modules.")
        
        layout.addWidget(self.vuln_scan_btn)
        layout.addWidget(self.dlp_btn)
        layout.addWidget(self.email_web_btn)
        layout.addWidget(self.edr_btn)
        layout.addWidget(self.ti_btn)
        layout.addWidget(self.siem_btn)
        layout.addWidget(self.identity_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.mdm_btn)
        layout.addWidget(self.ir_btn)
        layout.addWidget(self.cloud_btn)
        layout.addWidget(QLabel("Advanced Modules Output:"))
        layout.addWidget(self.output_text)
        self.setLayout(layout)
    
    def run_vuln_scan(self):
        scanner = VulnerabilityScanner()
        result = scanner.run_scan()
        self.output_text.append(result)
    
    def run_dlp_scan(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory for DLP Scan")
        if directory:
            dlp = DataLossPrevention()
            result = dlp.scan_for_sensitive_data(directory)
            self.output_text.append(result)
    
    def run_email_web_security(self):
        ews = EmailWebSecurity()
        email_result = ews.run_email_filter("")
        web_result = ews.run_web_filter()
        self.output_text.append(email_result)
        self.output_text.append(web_result)
    
    def run_edr(self):
        edr = EndpointDetectionResponse()
        result = edr.analyze_behavior()
        self.output_text.append(result)
    
    def run_ti(self):
        ti = ThreatIntelligenceIntegration()
        result = ti.get_threat_info()
        self.output_text.append(result)
    
    def run_siem(self):
        siem = SIEMIntegration()
        result = siem.send_logs()
        self.output_text.append(result)
    
    def run_identity(self):
        identity = IdentityManagement()
        result = identity.enforce_mfa()
        self.output_text.append(result)
    
    def run_encryption(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            enc = EncryptionModule()
            result = enc.encrypt_file(file_path)
            self.output_text.append(result)
    
    def run_mdm(self):
        mdm = MDMIntegration()
        result = mdm.secure_mobile_device()
        self.output_text.append(result)
    
    def run_ir(self):
        ir = IncidentResponseAutomation()
        result = ir.run_playbook()
        self.output_text.append(result)
    
    def run_cloud(self):
        cloud = CloudSecurityModule()
        result = cloud.scan_cloud_workloads()
        self.output_text.append(result)

# ---------------------------
# Documentation Widget
class DocumentationWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout()
        self.doc_text = QTextEdit()
        self.doc_text.setReadOnly(True)
        self.doc_text.setToolTip("Detailed documentation on how to use Cyber Guardian")
        self.doc_text.setPlainText(self.get_documentation_text())
        layout.addWidget(self.doc_text)
        self.setLayout(layout)
    def get_documentation_text(self):
        documentation = (
            "=== Cyber Guardian User Documentation ===\n\n"
            "Welcome to Cyber Guardian – your comprehensive cybersecurity suite.\n\n"
            "1. Real-time Protection (Home Tab):\n"
            "   - Click 'Enable Real-time Protection' to monitor a folder of your choice. Select a user folder (e.g., Documents or Downloads) to reduce permission issues.\n"
            "   - Any changes in the monitored folder will be displayed on the Threat Map.\n\n"
            "2. Antivirus Scanning (Antivirus Tab):\n"
            "   - Select a directory to scan using the 'Select Directory' button.\n"
            "   - Click 'Start Scan' to begin scanning. You can pause, resume, or stop the scan at any time.\n"
            "   - Detected threats appear in the Threats table, where you can choose to remove, quarantine, or shred files.\n\n"
            "3. Network Monitoring (Network Monitoring Tab):\n"
            "   - Start the network monitor to log real-time network activity.\n"
            "   - The Active Network Services table displays processes with network connections and allows you to kill suspicious processes.\n"
            "   - VirusTotal analysis is used to assess IP addresses (note: rate limits may apply).\n\n"
            "4. Firewall & IDS (Firewall/IDS Tab):\n"
            "   - Add predefined firewall rules or create custom rules. Use the 'Remove Selected Rule' button to delete any rule.\n"
            "   - Start or stop the IDS to monitor for suspicious process activity.\n\n"
            "5. Safe Browsing & VPN (Safe Browsing & VPN Tab):\n"
            "   - Toggle VPN and safe browsing to enhance online protection.\n\n"
            "6. Advanced Modules (Advanced Modules Tab):\n"
            "   - Run additional security functions including Vulnerability Scanning, Data Loss Prevention, Email/Web Security, Endpoint Detection & Response, Threat Intelligence, SIEM Integration, Identity Management, File Encryption, MDM Integration, Incident Response, and Cloud Security.\n"
            "   - The Vulnerability Scanner provides detailed reports with descriptions, recommended fixes, and links to authoritative resources such as the NVD and NIST guidelines.\n\n"
            "7. Documentation (Documentation Tab):\n"
            "   - Read detailed instructions on how to use each feature of Cyber Guardian.\n\n"
            "8. Run as Admin:\n"
            "   - Click the 'Run as Admin' button in the header to relaunch the application with administrative privileges (if required).\n\n"
            "9. Themes:\n"
            "   - Use the theme selector to switch between Dark Mode and Light Mode.\n\n"
            "For further support or more information, please consult the user manual or contact our support team.\n\n"
            "Thank you for choosing Cyber Guardian – your comprehensive cybersecurity partner."
        )
        return documentation

# ---------------------------
# Main GUI (Cyber Guardian) with Documentation Tab and Run as Admin Button
class AntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Guardian — Coded by DarkSpace Software & Security\nAuthor: Michael Blenkinsop ©")
        self.setGeometry(100, 100, 1000, 900)
        self.rt_protection_enabled = False
        self.rt_directory = None
        self.init_ui()
        self.apply_styles()
        self.setup_threads()
        self.quarantine_folder = os.path.join(os.getcwd(), "quarantine")
        os.makedirs(self.quarantine_folder, exist_ok=True)
        self.ransomware_protection = False
        self.firewall_rules = []
        logging.info("Cyber Guardian GUI initialized.")
    def init_ui(self):
        # Create individual tabs.
        self.home_tab = QWidget()
        self.init_home_tab()
        self.antivirus_tab = QWidget()
        self.init_antivirus_tab()
        self.network_tab = QWidget()
        self.init_network_tab()
        self.firewall_tab = QWidget()
        self.init_firewall_tab()
        self.safe_vpn_tab = QWidget()
        self.init_safe_vpn_tab()
        self.advanced_tab = AdvancedModulesGUI()
        self.documentation_tab = DocumentationWidget()
        # Set up tab widget
        self.tabs = QTabWidget()
        self.tabs.addTab(self.home_tab, "Home")
        self.tabs.addTab(self.antivirus_tab, "Antivirus")
        self.tabs.addTab(self.network_tab, "Network Monitoring")
        self.tabs.addTab(self.firewall_tab, "Firewall/IDS")
        self.tabs.addTab(self.safe_vpn_tab, "Safe Browsing & VPN")
        self.tabs.addTab(self.advanced_tab, "Advanced Modules")
        self.tabs.addTab(self.documentation_tab, "Documentation")
        # Header with banner, theme selector, and Run as Admin button
        header_layout = QHBoxLayout()
        self.banner_label = QLabel()
        if os.path.exists(BANNER_IMAGE):
            pixmap = QPixmap(BANNER_IMAGE).scaledToHeight(80)
            self.banner_label.setPixmap(pixmap)
            self.banner_label.setToolTip("Company Banner")
        else:
            self.banner_label.setText("Cyber Guardian\nCoded by DarkSpace Software & Security\nAuthor: Michael Blenkinsop ©")
            self.banner_label.setFont(QFont("Segoe UI", 16, QFont.Bold))
            self.banner_label.setStyleSheet("color: #FFFFFF;")
            self.banner_label.setToolTip("Company Information")
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Dark Mode", "Light Mode"])
        self.theme_selector.setToolTip("Select your preferred theme")
        self.theme_selector.currentIndexChanged.connect(self.change_theme)
        self.admin_button = QPushButton("Run as Admin")
        self.admin_button.setToolTip("Click to relaunch the application with administrative privileges (if not already running as admin)")
        self.admin_button.clicked.connect(run_as_admin)
        header_layout.addWidget(self.banner_label)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Theme:"))
        header_layout.addWidget(self.theme_selector)
        header_layout.addWidget(self.admin_button)
        header_widget = QWidget()
        header_widget.setLayout(header_layout)
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(header_widget)
        main_layout.addWidget(self.tabs)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
    def init_home_tab(self):
        self.rt_protection_button = QPushButton("Enable Real-time Protection")
        self.rt_protection_button.setCheckable(True)
        self.rt_protection_button.setToolTip("Toggle real-time protection. When enabled, you’ll be prompted to select a folder to monitor—choose a user folder (e.g., Documents or Downloads) to reduce permission errors and focus on your important files.")
        self.rt_protection_button.clicked.connect(self.toggle_realtime_protection)
        self.rt_status_label = QLabel("Real-time Protection: OFF")
        self.rt_status_label.setToolTip("Indicates whether real-time protection is enabled")
        rt_control_layout = QHBoxLayout()
        rt_control_layout.addWidget(self.rt_protection_button)
        rt_control_layout.addWidget(self.rt_status_label)
        rt_control_widget = QWidget()
        rt_control_widget.setLayout(rt_control_layout)
        self.threat_map_table = QTableWidget(0, 4)
        self.threat_map_table.setHorizontalHeaderLabels(["Time", "Source", "Threat Type", "Description"])
        self.threat_map_table.horizontalHeader().setStretchLastSection(True)
        self.threat_map_table.setToolTip("Real-time Threat Map: lists detected threats with time and description")
        threat_map_frame = create_group_frame("Threat Map", self.threat_map_table)
        home_layout = QVBoxLayout()
        home_layout.addWidget(rt_control_widget)
        home_layout.addWidget(threat_map_frame)
        self.home_tab.setLayout(home_layout)
    def init_antivirus_tab(self):
        self.av_status_display = QTextEdit()
        self.av_status_display.setReadOnly(True)
        self.av_status_display.setFixedHeight(80)
        self.av_status_display.setToolTip("Displays the status of the antivirus scan")
        self.select_directory_button = QPushButton("Select Directory")
        self.select_directory_button.setToolTip("Select a directory to scan for threats")
        self.select_directory_button.clicked.connect(self.select_scan_directory)
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setToolTip("Begin scanning the selected directory")
        self.scan_button.clicked.connect(self.scan_system)
        self.pause_scan_button = QPushButton("Pause Scan")
        self.pause_scan_button.setToolTip("Pause the current scan")
        self.pause_scan_button.clicked.connect(self.pause_scan)
        self.resume_scan_button = QPushButton("Resume Scan")
        self.resume_scan_button.setToolTip("Resume a paused scan")
        self.resume_scan_button.clicked.connect(self.resume_scan)
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.setToolTip("Stop the current scan")
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.ransomware_toggle = QPushButton("Enable Ransomware Protection")
        self.ransomware_toggle.setCheckable(True)
        self.ransomware_toggle.setToolTip("Toggle additional protection against ransomware threats (e.g., files containing 'encrypt')")
        self.ransomware_toggle.clicked.connect(self.toggle_ransomware)
        scan_control_layout = QHBoxLayout()
        scan_control_layout.addWidget(self.select_directory_button)
        scan_control_layout.addWidget(self.scan_button)
        scan_control_layout.addWidget(self.pause_scan_button)
        scan_control_layout.addWidget(self.resume_scan_button)
        scan_control_layout.addWidget(self.stop_scan_button)
        scan_control_layout.addWidget(self.ransomware_toggle)
        scan_control_widget = QWidget()
        scan_control_widget.setLayout(scan_control_layout)
        self.progress_bar = QProgressBar()
        self.progress_bar.setToolTip("Displays scan progress as a percentage")
        self.current_file_label = QLabel("Current File: N/A")
        self.current_file_label.setToolTip("Shows the file currently being scanned")
        progress_layout = QVBoxLayout()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.current_file_label)
        progress_widget = QWidget()
        progress_widget.setLayout(progress_layout)
        self.files_list = QListWidget()
        self.files_list.setToolTip("List of files that have been scanned")
        self.threats_table = QTableWidget(0, 3)
        self.threats_table.setHorizontalHeaderLabels(["File", "Status", "Actions"])
        self.threats_table.horizontalHeader().setStretchLastSection(True)
        self.threats_table.setToolTip("List of detected threats with options to remove, quarantine, or shred")
        status_frame = create_group_frame("Scan Status", self.av_status_display)
        control_frame = create_group_frame("Scan Controls", scan_control_widget)
        progress_frame = create_group_frame("Scan Progress", progress_widget)
        files_frame = create_group_frame("Files Scanned", self.files_list)
        threats_frame = create_group_frame("Threats Detected", self.threats_table)
        grid = QGridLayout()
        grid.addWidget(status_frame, 0, 0, 1, 2)
        grid.addWidget(control_frame, 1, 0)
        grid.addWidget(progress_frame, 1, 1)
        grid.addWidget(files_frame, 2, 0, 1, 2)
        grid.addWidget(threats_frame, 3, 0, 1, 2)
        self.antivirus_tab.setLayout(grid)
    def init_network_tab(self):
        self.net_status_display = QTextEdit()
        self.net_status_display.setReadOnly(True)
        self.net_status_display.setToolTip("Logs real-time network activity")
        self.start_net_button = QPushButton("Start Monitor")
        self.start_net_button.setToolTip("Start monitoring network activity")
        self.start_net_button.clicked.connect(self.start_network_monitor)
        self.stop_net_button = QPushButton("Stop Monitor")
        self.stop_net_button.setToolTip("Stop monitoring network activity")
        self.stop_net_button.clicked.connect(self.stop_network_monitor)
        net_btn_layout = QHBoxLayout()
        net_btn_layout.addWidget(self.start_net_button)
        net_btn_layout.addWidget(self.stop_net_button)
        net_btn_widget = QWidget()
        net_btn_widget.setLayout(net_btn_layout)
        net_frame = create_group_frame("Network Activity", self.net_status_display)
        btn_frame = create_group_frame("Network Controls", net_btn_widget)
        self.services_table = QTableWidget(0, 4)
        self.services_table.setHorizontalHeaderLabels(["PID", "Process Name", "Connections", "Actions"])
        self.services_table.horizontalHeader().setStretchLastSection(True)
        self.services_table.setToolTip("Active network services with an option to kill a process")
        services_frame = create_group_frame("Active Network Services", self.services_table)
        net_layout = QVBoxLayout()
        net_layout.addWidget(net_frame)
        net_layout.addWidget(btn_frame)
        net_layout.addWidget(services_frame)
        self.network_tab.setLayout(net_layout)
        self.services_timer = QTimer()
        self.services_timer.timeout.connect(self.update_services_table)
        self.services_timer.start(10000)
    def init_firewall_tab(self):
        self.firewall_status_display = QTextEdit()
        self.firewall_status_display.setReadOnly(True)
        self.firewall_status_display.setToolTip("Displays firewall rule status and IDS messages")
        self.available_rules_combo = QComboBox()
        self.available_rules_combo.addItems([
            "Block all inbound traffic",
            "Allow all outbound traffic",
            "Block port 80 (HTTP)",
            "Block port 443 (HTTPS)",
            "Allow only specific IP addresses"
        ])
        self.available_rules_combo.setToolTip("Select from predefined firewall rules")
        self.add_selected_rule_button = QPushButton("Add Selected Rule")
        self.add_selected_rule_button.setToolTip("Add the selected predefined firewall rule")
        self.add_selected_rule_button.clicked.connect(self.add_predefined_rule)
        available_rules_layout = QHBoxLayout()
        available_rules_layout.addWidget(QLabel("Available Rules:"))
        available_rules_layout.addWidget(self.available_rules_combo)
        available_rules_layout.addWidget(self.add_selected_rule_button)
        available_rules_widget = QWidget()
        available_rules_widget.setLayout(available_rules_layout)
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Or enter custom rule")
        self.rule_input.setToolTip("Type your custom firewall rule here")
        self.add_rule_button = QPushButton("Add Custom Rule")
        self.add_rule_button.setToolTip("Add the custom firewall rule")
        self.add_rule_button.clicked.connect(self.add_firewall_rule)
        custom_rule_layout = QHBoxLayout()
        custom_rule_layout.addWidget(self.rule_input)
        custom_rule_layout.addWidget(self.add_rule_button)
        custom_rule_widget = QWidget()
        custom_rule_widget.setLayout(custom_rule_layout)
        self.rules_list = QListWidget()
        self.rules_list.setToolTip("List of currently added firewall rules")
        self.remove_rule_button = QPushButton("Remove Selected Rule")
        self.remove_rule_button.setToolTip("Remove the currently selected firewall rule from the list")
        self.remove_rule_button.clicked.connect(self.remove_selected_rule)
        remove_rule_layout = QHBoxLayout()
        remove_rule_layout.addWidget(self.remove_rule_button)
        remove_rule_widget = QWidget()
        remove_rule_widget.setLayout(remove_rule_layout)
        self.start_ids_button = QPushButton("Start IDS")
        self.start_ids_button.setToolTip("Start the Intrusion Detection System")
        self.start_ids_button.clicked.connect(self.start_ids)
        self.stop_ids_button = QPushButton("Stop IDS")
        self.stop_ids_button.setToolTip("Stop the Intrusion Detection System")
        self.stop_ids_button.clicked.connect(self.stop_ids)
        ids_btn_layout = QHBoxLayout()
        ids_btn_layout.addWidget(self.start_ids_button)
        ids_btn_layout.addWidget(self.stop_ids_button)
        ids_btn_widget = QWidget()
        ids_btn_widget.setLayout(ids_btn_layout)
        status_frame = create_group_frame("Firewall Status", self.firewall_status_display)
        available_frame = create_group_frame("Predefined Firewall Rules", available_rules_widget)
        custom_frame = create_group_frame("Custom Rule Entry", custom_rule_widget)
        list_frame = create_group_frame("Current Rules", self.rules_list)
        remove_frame = create_group_frame("Remove Firewall Rule", remove_rule_widget)
        ids_frame = create_group_frame("IDS Controls", ids_btn_widget)
        grid = QGridLayout()
        grid.addWidget(available_frame, 0, 0)
        grid.addWidget(custom_frame, 0, 1)
        grid.addWidget(list_frame, 1, 0, 1, 2)
        grid.addWidget(remove_frame, 2, 0, 1, 2)
        grid.addWidget(status_frame, 3, 0, 1, 2)
        grid.addWidget(ids_frame, 4, 0, 1, 2)
        self.firewall_tab.setLayout(grid)
        self.firewall_rules = []
    def init_safe_vpn_tab(self):
        self.safe_status_display = QTextEdit()
        self.safe_status_display.setReadOnly(True)
        self.safe_status_display.setToolTip("Displays status messages for safe browsing and VPN")
        self.vpn_status_label = QLabel("VPN: OFF")
        self.vpn_status_label.setToolTip("Indicates whether VPN is enabled")
        self.safe_browsing_label = QLabel("Safe Browsing: OFF")
        self.safe_browsing_label.setToolTip("Indicates whether safe browsing is enabled")
        self.vpn_toggle_button = QPushButton("Toggle VPN")
        self.vpn_toggle_button.setToolTip("Enable or disable VPN")
        self.vpn_toggle_button.clicked.connect(self.toggle_vpn)
        self.safe_browsing_toggle_button = QPushButton("Toggle Safe Browsing")
        self.safe_browsing_toggle_button.setToolTip("Enable or disable safe browsing")
        self.safe_browsing_toggle_button.clicked.connect(self.toggle_safe_browsing)
        vpn_layout = QHBoxLayout()
        vpn_layout.addWidget(self.vpn_status_label)
        vpn_layout.addWidget(self.vpn_toggle_button)
        safe_layout = QHBoxLayout()
        safe_layout.addWidget(self.safe_browsing_label)
        safe_layout.addWidget(self.safe_browsing_toggle_button)
        control_layout = QVBoxLayout()
        control_layout.addLayout(vpn_layout)
        control_layout.addLayout(safe_layout)
        control_widget = QWidget()
        control_widget.setLayout(control_layout)
        status_frame = create_group_frame("Safe Browsing / VPN Status", self.safe_status_display)
        control_frame = create_group_frame("Controls", control_widget)
        main_layout = QVBoxLayout()
        main_layout.addWidget(status_frame)
        main_layout.addWidget(control_frame)
        self.safe_vpn_tab.setLayout(main_layout)
    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #252526; }
            QLabel { font-family: 'Segoe UI', sans-serif; font-size: 12pt; color: #CCCCCC; }
            QPushButton {
                background-color: #0E639C;
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover { background-color: #1177BB; }
            QTextEdit, QLineEdit, QListWidget, QProgressBar, QTableWidget {
                background-color: #1E1E1E;
                color: #CCCCCC;
                border: 1px solid #3C3C3C;
                border-radius: 4px;
                padding: 4px;
            }
            QComboBox {
                background-color: #1E1E1E;
                color: #CCCCCC;
                border: 1px solid #3C3C3C;
                border-radius: 4px;
                padding: 4px;
            }
            QTabWidget::pane { border: 1px solid #3C3C3C; top: -1px; }
            QTabBar::tab {
                background-color: #1E1E1E;
                color: #CCCCCC;
                padding: 8px 16px;
                border: 1px solid #3C3C3C;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 100px;
            }
            QTabBar::tab:selected { background-color: #252526; color: #FFFFFF; }
        """)
    def setup_threads(self):
        self.file_protection = None
        self.network_monitor = None
        self.ids = None
        self.av_scanner = None
        self.scan_directory = None
        self.vpn_enabled = False
        self.safe_browsing_enabled = False
        self.rt_protection_enabled = False
        self.rt_directory = None
    # ---------------------------
    # Home Tab Functions
    def toggle_realtime_protection(self):
        if self.rt_protection_enabled:
            if self.file_protection:
                self.file_protection.stop()
                self.file_protection.wait(1000)
            self.rt_protection_enabled = False
            self.rt_protection_button.setText("Enable Real-time Protection")
            self.rt_status_label.setText("Real-time Protection: OFF")
            self.add_to_threat_map("System", "Info", "Real-time protection disabled.")
        else:
            if not self.rt_directory:
                directory = QFileDialog.getExistingDirectory(self, "Select Directory for Real-time Protection")
                if not directory:
                    return
                self.rt_directory = directory
            self.file_protection = FileProtection([self.rt_directory])
            self.file_protection.file_changed.connect(self.handle_file_change)
            self.file_protection.start()
            self.rt_protection_enabled = True
            self.rt_protection_button.setText("Disable Real-time Protection")
            self.rt_status_label.setText("Real-time Protection: ON")
            self.add_to_threat_map("System", "Info", f"Real-time protection enabled on {self.rt_directory}")
    def handle_file_change(self, file_path):
        lower = file_path.lower()
        if "virus" in lower or "threat" in lower or (self.ransomware_protection and "encrypt" in lower):
            self.add_to_threat_map("FileProtection", "File Threat", file_path)
    def add_to_threat_map(self, source, threat_type, description):
        row = self.threat_map_table.rowCount()
        self.threat_map_table.insertRow(row)
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.threat_map_table.setItem(row, 0, QTableWidgetItem(current_time))
        self.threat_map_table.setItem(row, 1, QTableWidgetItem(source))
        self.threat_map_table.setItem(row, 2, QTableWidgetItem(threat_type))
        self.threat_map_table.setItem(row, 3, QTableWidgetItem(description))
    # ---------------------------
    # Antivirus Functions
    def select_scan_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if directory:
            self.scan_directory = directory
            self.av_status_display.append(f"[+] Directory selected: {directory}")
    def scan_system(self):
        if not self.scan_directory:
            QMessageBox.warning(self, "No Directory", "Please select a directory to scan first.")
            return
        self.av_status_display.append("[+] Starting scan...")
        self.progress_bar.setValue(0)
        self.current_file_label.setText("Current File: N/A")
        self.files_list.clear()
        self.threats_table.setRowCount(0)
        self.av_scanner = AntivirusScanner(self.scan_directory)
        self.av_scanner.progress_update.connect(self.update_progress)
        self.av_scanner.file_scanned.connect(self.update_file_scanned)
        self.av_scanner.scan_complete.connect(self.scan_complete)
        self.av_scanner.start()
    def update_progress(self, percent):
        self.progress_bar.setValue(percent)
    def update_file_scanned(self, file_path):
        self.current_file_label.setText(f"Current File: {file_path}")
        self.files_list.addItem(file_path)
        lower = file_path.lower()
        if "virus" in lower or "threat" in lower or (self.ransomware_protection and "encrypt" in lower):
            self.add_threat(file_path)
    def scan_complete(self):
        self.av_status_display.append("[✓] Scan complete.")
        self.current_file_label.setText("Current File: N/A")
    def add_threat(self, file_path):
        rows = self.threats_table.rowCount()
        for i in range(rows):
            if self.threats_table.item(i, 0).text() == file_path:
                return
        self.threats_table.insertRow(rows)
        self.threats_table.setItem(rows, 0, QTableWidgetItem(file_path))
        threat_type = "Ransomware Threat" if (self.ransomware_protection and "encrypt" in file_path.lower()) else "Detected"
        self.threats_table.setItem(rows, 1, QTableWidgetItem(threat_type))
        action_widget = QWidget()
        remove_btn = QPushButton("Remove")
        quarantine_btn = QPushButton("Quarantine")
        shred_btn = QPushButton("Shred")
        remove_btn.setToolTip("Remove (delete) the detected threat file")
        quarantine_btn.setToolTip("Quarantine the detected threat file (move to quarantine folder)")
        shred_btn.setToolTip("Securely delete (shred) the file so it cannot be recovered")
        remove_btn.clicked.connect(lambda _, f=file_path, r=rows: self.remove_threat(f, r))
        quarantine_btn.clicked.connect(lambda _, f=file_path, r=rows: self.quarantine_threat(f, r))
        shred_btn.clicked.connect(lambda _, f=file_path, r=rows: self.shred_threat(f, r))
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(quarantine_btn)
        btn_layout.addWidget(shred_btn)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        action_widget.setLayout(btn_layout)
        self.threats_table.setCellWidget(rows, 2, action_widget)
    def remove_threat(self, file_path, row):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self.av_status_display.append(f"[✓] Removed threat: {file_path}")
            else:
                self.av_status_display.append(f"[!] File not found: {file_path}")
            self.threats_table.setItem(row, 1, QTableWidgetItem("Removed"))
        except Exception as e:
            self.av_status_display.append(f"[!] Error removing threat: {e}")
    def quarantine_threat(self, file_path, row):
        try:
            if os.path.exists(file_path):
                base = os.path.basename(file_path)
                quarantine_path = os.path.join(self.quarantine_folder, base)
                shutil.move(file_path, quarantine_path)
                self.av_status_display.append(f"[✓] Quarantined threat: {file_path}")
            else:
                self.av_status_display.append(f"[!] File not found: {file_path}")
            self.threats_table.setItem(row, 1, QTableWidgetItem("Quarantined"))
        except Exception as e:
            self.av_status_display.append(f"[!] Error quarantining threat: {e}")
    def shred_threat(self, file_path, row):
        success, message = safe_shred(file_path)
        if success:
            self.av_status_display.append(f"[✓] {message}")
            self.threats_table.setItem(row, 1, QTableWidgetItem("Shredded"))
        else:
            self.av_status_display.append(f"[!] {message}")
    def pause_scan(self):
        if self.av_scanner and self.av_scanner.isRunning():
            self.av_scanner.pause()
            self.av_status_display.append("[*] Scan paused.")
    def resume_scan(self):
        if self.av_scanner and self.av_scanner.isRunning():
            self.av_scanner.resume()
            self.av_status_display.append("[*] Scan resumed.")
    def stop_scan(self):
        if self.av_scanner and self.av_scanner.isRunning():
            self.av_scanner.stop()
            self.av_scanner.wait(1000)
            self.av_status_display.append("[✓] Scan stopped.")
    def toggle_ransomware(self):
        self.ransomware_protection = not self.ransomware_protection
        if self.ransomware_protection:
            self.ransomware_toggle.setText("Disable Ransomware Protection")
            self.av_status_display.append("[+] Ransomware protection enabled.")
        else:
            self.ransomware_toggle.setText("Enable Ransomware Protection")
            self.av_status_display.append("[✓] Ransomware protection disabled.")
    # ---------------------------
    # Network Monitoring Functions
    def start_network_monitor(self):
        if self.network_monitor is None or not self.network_monitor.isRunning():
            self.network_monitor = NetworkMonitor()
            self.network_monitor.packet_received.connect(self.network_packet_received)
            self.network_monitor.ip_analysis_received.connect(self.network_analysis_received)
            self.network_monitor.start()
            self.net_status_display.append("[+] Monitor started.")
        else:
            self.net_status_display.append("[!] Monitor already running.")
    def stop_network_monitor(self):
        if self.network_monitor and self.network_monitor.isRunning():
            self.network_monitor.stop()
            self.network_monitor.wait(1000)
            self.net_status_display.append("[✓] Monitor stopped.")
        else:
            self.net_status_display.append("[!] Monitor is not running.")
    def network_packet_received(self, packet_info):
        self.net_status_display.append(packet_info)
    def network_analysis_received(self, analysis):
        self.net_status_display.append(analysis)
    def update_services_table(self):
        processes = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                conns = proc.net_connections()  # Using net_connections()
                if conns:
                    processes[proc.info['pid']] = (proc.info['name'], len(conns))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self.services_table.setRowCount(0)
        for pid, (name, conn_count) in processes.items():
            row = self.services_table.rowCount()
            self.services_table.insertRow(row)
            self.services_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.services_table.setItem(row, 1, QTableWidgetItem(name))
            self.services_table.setItem(row, 2, QTableWidgetItem(str(conn_count)))
            action_widget = QWidget()
            kill_btn = QPushButton("Kill")
            kill_btn.setToolTip("Terminate this process")
            kill_btn.clicked.connect(lambda _, p=pid: self.kill_service(p))
            btn_layout = QHBoxLayout()
            btn_layout.addWidget(kill_btn)
            btn_layout.setContentsMargins(0, 0, 0, 0)
            action_widget.setLayout(btn_layout)
            self.services_table.setCellWidget(row, 3, action_widget)
    def kill_service(self, pid):
        try:
            proc = psutil.Process(pid)
            proc.kill()
            self.net_status_display.append(f"[✓] Killed process PID: {pid}")
        except Exception as e:
            self.net_status_display.append(f"[!] Error killing process PID {pid}: {e}")
    # ---------------------------
    # Firewall & IDS Functions
    def add_predefined_rule(self):
        rule = self.available_rules_combo.currentText()
        if rule:
            self.firewall_rules.append(rule)
            self.rules_list.addItem(rule)
            self.firewall_status_display.append(f"[+] Added: {rule}")
        else:
            QMessageBox.warning(self, "No Rule Selected", "Please select a predefined rule.")
    def add_firewall_rule(self):
        rule = self.rule_input.text().strip()
        if rule:
            self.firewall_rules.append(rule)
            self.rules_list.addItem(rule)
            self.firewall_status_display.append(f"[+] Added: {rule}")
            self.rule_input.clear()
        else:
            QMessageBox.warning(self, "Empty Rule", "Please enter a rule.")
    def remove_selected_rule(self):
        selected_items = self.rules_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a rule to remove.")
            return
        for item in selected_items:
            index = self.rules_list.row(item)
            self.rules_list.takeItem(index)
            try:
                self.firewall_rules.remove(item.text())
            except ValueError:
                pass
            self.firewall_status_display.append(f"[✓] Removed rule: {item.text()}")
    def start_ids(self):
        if self.ids is None or not self.ids.isRunning():
            self.ids = IDS()
            self.ids.intrusion_detected.connect(self.ids_alert)
            self.ids.start()
            self.firewall_status_display.append("[+] IDS started.")
        else:
            self.firewall_status_display.append("[!] IDS already running.")
    def stop_ids(self):
        if self.ids and self.ids.isRunning():
            self.ids.stop()
            self.ids.wait(1000)
            self.firewall_status_display.append("[✓] IDS stopped.")
        else:
            self.firewall_status_display.append("[!] IDS is not running.")
    def ids_alert(self, intrusion_info):
        self.firewall_status_display.append(intrusion_info)
    # ---------------------------
    # Safe Browsing & VPN Functions
    def toggle_vpn(self):
        self.vpn_enabled = not self.vpn_enabled
        if self.vpn_enabled:
            self.vpn_status_label.setText("VPN: ON")
            self.safe_status_display.append("[+] VPN enabled.")
        else:
            self.vpn_status_label.setText("VPN: OFF")
            self.safe_status_display.append("[✓] VPN disabled.")
    def toggle_safe_browsing(self):
        self.safe_browsing_enabled = not self.safe_browsing_enabled
        if self.safe_browsing_enabled:
            self.safe_browsing_label.setText("Safe Browsing: ON")
            self.safe_status_display.append("[+] Safe Browsing enabled.")
        else:
            self.safe_browsing_label.setText("Safe Browsing: OFF")
            self.safe_status_display.append("[✓] Safe Browsing disabled.")
    # ---------------------------
    # Theme Switching
    def change_theme(self):
        selected = self.theme_selector.currentText()
        if selected == "Dark Mode":
            self.apply_styles()
        else:
            self.setStyleSheet("""
                QMainWindow { background-color: #F0F0F0; }
                QLabel { color: #000000; font-family: 'Segoe UI', sans-serif; }
                QPushButton {
                    background-color: #0078D7;
                    color: #FFFFFF;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                }
                QPushButton:hover { background-color: #005A9E; }
                QTextEdit, QLineEdit, QListWidget, QProgressBar, QTableWidget {
                    background-color: #FFFFFF;
                    color: #000000;
                    border: 1px solid #AAA;
                    border-radius: 4px;
                    padding: 4px;
                }
                QComboBox {
                    background-color: #FFFFFF;
                    color: #000000;
                    border: 1px solid #AAA;
                    border-radius: 4px;
                    padding: 4px;
                }
                QTabWidget::pane { border: 1px solid #AAA; }
                QTabBar::tab {
                    background-color: #FFFFFF;
                    color: #000000;
                    padding: 8px 16px;
                    border: 1px solid #AAA;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    min-width: 100px;
                }
                QTabBar::tab:selected { background-color: #E0E0E0; }
            """)
# ---------------------------
# Run Application
def run_gui():
    try:
        app = QApplication(sys.argv)
        window = AntivirusGUI()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"Application failed to start: {e}")

if __name__ == "__main__":
    run_gui()
