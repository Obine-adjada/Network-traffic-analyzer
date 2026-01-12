#!/usr/bin/env python3
"""
Détecteur d'anomalies réseau
Intègre GeoIP, Blacklist, Corrélation et Threat Intelligence
"""

from scapy.all import rdpcap, IP, TCP, UDP, Raw
from collections import defaultdict, Counter
import datetime
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'threat_intel'))

try:
    from geoip_detector import GeoIPDetector
    from blacklist_checker import BlacklistChecker
    from alert_correlator import AlertCorrelator
    from enricher import ThreatIntelligenceEnricher
    ADVANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f" Modules avancés non disponibles : {e}")
    ADVANCED_MODULES_AVAILABLE = False


class AnomalyDetector:
    def __init__(self, pcap_file):
        """Initialise le détecteur d'anomalies"""
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.alerts = []
        
        # Seuils
        self.PORT_SCAN_THRESHOLD = 10
        self.HIGH_TRAFFIC_THRESHOLD = 1000000
        
        # Ports dangereux
        self.INSECURE_PORTS = {
            21: 'FTP', 23: 'Telnet', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 3306: 'MySQL'
        }
        
        self.SUSPICIOUS_PORTS = {
            1337: 'Elite/Backdoor', 31337: 'BackOrifice', 
            4444: 'Metasploit', 6667: 'IRC'
        }
        
        if ADVANCED_MODULES_AVAILABLE:
            print("\n[*] Initialisation des modules avancés...")
            self.geoip_detector = GeoIPDetector()
            self.blacklist_checker = BlacklistChecker()
            self.alert_correlator = AlertCorrelator(time_window_seconds=300)
            
            try:
                import json
                config_path = os.path.join(project_root, 'config.json')
                with open(config_path, 'r') as f:
                    ti_config = json.load(f).get('threat_intelligence', {})
            except:
                ti_config = {}
            
            self.threat_intel = ThreatIntelligenceEnricher(ti_config)
        else:
            self.geoip_detector = None
            self.blacklist_checker = None
            self.alert_correlator = None
            self.threat_intel = None
    
    def detect_all(self):
        """Lance toutes les détections"""
        print(f"\nDétection d'anomalies sur {self.pcap_file}...")
        print(f" Analyse de {len(self.packets)} paquets...\n")

        self._detect_port_scan()
        self._detect_insecure_protocols()
        self._detect_suspicious_ports()
        self._detect_excessive_traffic()
        self._detect_fragmented_packets()
        
        # Détections avancées
        if ADVANCED_MODULES_AVAILABLE:
            if self.geoip_detector:
                self._detect_geographical_anomalies()
            
            if self.blacklist_checker:
                self._detect_blacklisted_ips()
            
            if self.threat_intel:
                print("\nEnrichissement Threat Intelligence...")
                self.alerts = self.threat_intel.enrich_alerts(self.alerts)
            
            if self.alert_correlator:
                print("\n Corrélation des alertes...")
                self.alert_correlator.add_alerts_batch(self.alerts)
                self.incidents = self.alert_correlator.correlate()
            else:
                self.incidents = []
        else:
            self.incidents = []
        
        return self.alerts
    
    def _detect_geographical_anomalies(self):
        """Détecte les connexions vers pays à haut risque"""
        print(" Détection géographique...")
        
        destination_ips = {packet[IP].dst for packet in self.packets if IP in packet}
        
        for ip in destination_ips:
            country = self.geoip_detector.get_country(ip)
            
            if self.geoip_detector.is_high_risk_country(country):
                self._add_alert(
                    severity='HIGH',
                    category='High Risk Country',
                    description=f"Connexion vers pays à haut risque : {country}",
                    details=f"IP destination : {ip}",
                    destination_ip=ip
                )
    
    def _detect_blacklisted_ips(self):
        """Détecte les IPs malveillantes"""
        print("Vérification des blacklists...")
        
        all_ips = set()
        for packet in self.packets:
            if IP in packet:
                all_ips.add(packet[IP].src)
                all_ips.add(packet[IP].dst)
        
        for ip in all_ips:
            result = self.blacklist_checker.check_ip(ip)
            
            if result['is_malicious']:
                self._add_alert(
                    severity='CRITICAL',
                    category='Malicious IP',
                    description=f"IP malveillante connue",
                    details=f"IP: {ip} | Sources: {', '.join(result['sources'])}",
                    source_ip=ip
                )
    
    def _detect_port_scan(self):
        """Détecte les scans de ports"""
        ip_ports = defaultdict(set)
        
        for packet in self.packets:
            if IP in packet and TCP in packet:
                ip_ports[packet[IP].src].add(packet[TCP].dport)
        
        for ip, ports in ip_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                self._add_alert(
                    severity='HIGH',
                    category='Port Scan',
                    description=f"Scan de ports détecté depuis {ip}",
                    details=f"{len(ports)} ports contactés",
                    source_ip=ip
                )
    
    def _detect_insecure_protocols(self):
        """Détecte les protocoles non sécurisés"""
        insecure_connections = defaultdict(list)
        
        for packet in self.packets:
            if IP in packet and TCP in packet:
                dst_port = packet[TCP].dport
                
                if dst_port in self.INSECURE_PORTS:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = self.INSECURE_PORTS[dst_port]
                    
                    insecure_connections[protocol].append({'src': src_ip, 'dst': dst_ip})
                    
                    # Cherche des credentials
                    if Raw in packet and self._contains_credentials(packet[Raw].load):
                        self._add_alert(
                            severity='CRITICAL',
                            category='Credentials in Clear',
                            description=f"Identifiants en clair détectés",
                            details=f"Protocole {protocol} (port {dst_port})",
                            source_ip=src_ip,
                            destination_ip=dst_ip
                        )
        
        for protocol, connections in insecure_connections.items():
            self._add_alert(
                severity='MEDIUM',
                category='Insecure Protocol',
                description=f"Utilisation de {protocol} (non chiffré)",
                details=f"{len(connections)} connexions",
                source_ip=connections[0]['src']
            )
    
    def _detect_suspicious_ports(self):
        """Détecte les ports suspects"""
        for packet in self.packets:
            if IP in packet and (TCP in packet or UDP in packet):
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                
                if port in self.SUSPICIOUS_PORTS:
                    self._add_alert(
                        severity='HIGH',
                        category='Suspicious Port',
                        description=f"Connexion vers port suspect : {port}",
                        details=f"{self.SUSPICIOUS_PORTS[port]}",
                        source_ip=packet[IP].src,
                        destination_ip=packet[IP].dst
                    )
    
    def _detect_excessive_traffic(self):
        """Détecte le trafic excessif"""
        ip_traffic = defaultdict(int)
        
        for packet in self.packets:
            if IP in packet:
                ip_traffic[packet[IP].src] += len(packet)
        
        for ip, total_bytes in ip_traffic.items():
            if total_bytes > self.HIGH_TRAFFIC_THRESHOLD:
                self._add_alert(
                    severity='MEDIUM',
                    category='High Traffic',
                    description=f"Trafic excessif depuis {ip}",
                    details=f"Volume : {total_bytes / 1024 / 1024:.2f} MB",
                    source_ip=ip
                )
    
    def _detect_fragmented_packets(self):
        """Détecte la fragmentation"""
        fragmented_count = sum(1 for p in self.packets 
                              if IP in p and (p[IP].flags == 'MF' or p[IP].frag > 0))
        
        if fragmented_count > 5:
            self._add_alert(
                severity='LOW',
                category='Packet Fragmentation',
                description=f"Fragmentation détectée",
                details=f"{fragmented_count} paquets fragmentés"
            )
    
    def _contains_credentials(self, payload):
        """Cherche des credentials dans le payload"""
        keywords = [b'user', b'pass', b'login', b'password', b'username']
        try:
            return any(kw in payload.lower() for kw in keywords)
        except:
            return False
    
    def _add_alert(self, severity, category, description, details, source_ip=None, destination_ip=None):
        """Ajoute une alerte"""
        self.alerts.append({
            'timestamp': datetime.datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details,
            'source_ip': source_ip,
            'destination_ip': destination_ip
        })
    
    def print_alerts(self):
        """Affiche les alertes"""
        if not self.alerts:
            print(" Aucune anomalie détectée !")
            return

        print(f" ALERTES DE SÉCURITÉ ({len(self.alerts)} détectées)")
       
        severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_alerts = [a for a in self.alerts if a['severity'] == severity]
            
            if severity_alerts:
                print(f"\n{severity_icons[severity]} {severity} ({len(severity_alerts)}):")
                for i, alert in enumerate(severity_alerts, 1):
                    print(f"\n  [{i}] {alert['category']}")
                    print(f"      {alert['description']}")
                    print(f"      Détails: {alert['details']}")
                    if alert['source_ip']:
                        print(f"      Source: {alert['source_ip']}")
                    if alert['destination_ip']:
                        print(f"      Destination: {alert['destination_ip']}")

        if ADVANCED_MODULES_AVAILABLE and hasattr(self, 'incidents') and self.incidents:
            self.alert_correlator.print_incidents()
            self.alert_correlator.print_summary()

        if ADVANCED_MODULES_AVAILABLE and self.threat_intel:
            self._print_threat_intel()
    
    def _print_threat_intel(self):
        """Affiche les données Threat Intelligence"""
        print(" THREAT INTELLIGENCE ENRICHMENT")
        
        stats = self.threat_intel.get_statistics()
        print(f"\n Statistiques :")
        print(f"  • IPs enrichies : {stats['total_enriched']}")
        print(f"  • Cache hits : {stats['cache_hits']}")
        print(f"  • Appels API : {stats['api_calls']}")
        
        print(f"\n🔴 IPs à risque :")
        threat_count = 0
        for ip, data in self.threat_intel.cache.items():
            if data.get('threat_score', 0) > 50:
                threat_count += 1
                print(f"\n  [{threat_count}] {ip}")
                print(f"      Niveau : {data.get('threat_level', 'UNKNOWN')}")
                print(f"      Score : {data.get('threat_score', 0)}/100")
                
                sources = data.get('sources', {})
                if 'abuseipdb' in sources:
                    abuse = sources['abuseipdb']
                    print(f"      AbuseIPDB : {abuse.get('abuse_confidence_score', 0)}%")
                if 'virustotal' in sources:
                    vt = sources['virustotal']
                    print(f"      VirusTotal : {vt.get('malicious', 0)} détections")
        
        if threat_count == 0:
            print(" Aucune IP dangereuse")
   
    def get_stats(self):
        """Retourne les statistiques"""
        if not self.alerts:
            return {'total': 0, 'by_severity': {}, 'by_category': {}}
        
        return {
            'total': len(self.alerts),
            'by_severity': dict(Counter(a['severity'] for a in self.alerts)),
            'by_category': dict(Counter(a['category'] for a in self.alerts)),
            'alerts': self.alerts,
            'incidents': self.incidents if hasattr(self, 'incidents') else []
        }

# Test
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 anomaly_detector.py <fichier.pcap>")
        sys.exit(1)
    
    detector = AnomalyDetector(sys.argv[1])
    detector.detect_all()
    detector.print_alerts()