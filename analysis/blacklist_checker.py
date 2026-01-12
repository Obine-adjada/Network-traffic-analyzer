#!/usr/bin/env python3
"""
Module de vérification de blacklist
Vérifie les IPs contre une blacklist locale d'IPs malveillantes
"""

class BlacklistChecker:
    def __init__(self):
        """Initialise le checker avec blacklist locale"""
        # Blacklist locale 
        self.LOCAL_BLACKLIST = {
            '185.220.101.1': 'Tor Exit Node',
            '45.142.212.61': 'Known Malware C2',
            '104.248.144.120': 'Botnet Infrastructure',
            '192.0.2.1': 'Test IP - Documentation'
        }
        
        print(" Blacklist Checker initialisé")
        print(f" {len(self.LOCAL_BLACKLIST)} IPs en blacklist locale")
    
    def check_ip(self, ip_address):
        """Vérifie si une IP est malveillante"""
        result = {
            'ip': ip_address,
            'is_malicious': False,
            'sources': [],
            'reasons': [],
            'confidence': 0
        }
        
        if ip_address in self.LOCAL_BLACKLIST:
            result['is_malicious'] = True
            result['sources'].append('Local Blacklist')
            result['reasons'].append(self.LOCAL_BLACKLIST[ip_address])
            result['confidence'] = 100
        
        return result
    
    def add_to_blacklist(self, ip_address, reason):
        """Ajoute une IP à la blacklist locale"""
        self.LOCAL_BLACKLIST[ip_address] = reason
        print(f" IP ajoutée à la blacklist : {ip_address} ({reason})")
    
    def remove_from_blacklist(self, ip_address):
        """Retire une IP de la blacklist"""
        if ip_address in self.LOCAL_BLACKLIST:
            del self.LOCAL_BLACKLIST[ip_address]
            print(f" IP retirée de la blacklist : {ip_address}")
        else:
            print(f" IP non trouvée dans la blacklist : {ip_address}")
    
    def get_blacklist(self):
        """Retourne la blacklist complète"""
        return self.LOCAL_BLACKLIST

if __name__ == "__main__":
    print(" Blacklist Checker")
    print("\nCe module vérifie les IPs contre une blacklist locale.")
    
    checker = BlacklistChecker()
    print("\n Test terminé !")