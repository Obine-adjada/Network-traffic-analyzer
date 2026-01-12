#!/usr/bin/env python3
"""
Gestionnaire de logs avec rotation automatique
"""

import os
import gzip
import shutil
from datetime import datetime, timedelta
import json

class LogManager:
    """
    Gère les logs avec rotation quotidienne et compression
    """
    def __init__(self, log_dir='logs'):
        """
        log_dir = Dossier où stocker les logs
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        today = datetime.now().strftime('%Y-%m-%d')
        self.current_log_file = os.path.join(log_dir, f'alerts_{today}.log')
        
        print(f" Log Manager initialisé")
        print(f" • Dossier : {log_dir}")
        print(f"• Fichier actuel : {self.current_log_file}")
    
    def log_alert(self, alert):
        """
        Écrit une alerte dans le fichier de log
        Format : JSON 
        """
        # Ajout d'un timestamp 
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        # JSON
        with open(self.current_log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def log_message(self, message, level='INFO'):
        """
        Juste un message de log simple
        Format : [TIMESTAMP] [LEVEL] Message
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{timestamp}] [{level}] {message}\n"
        
        with open(self.current_log_file, 'a') as f:
            f.write(log_line)
    
    def rotate_logs(self):
        """
        Rotation quotidienne des logs :
        - Logs > 1 jour, compression en .gz
        - Logs > 7 jours, suppression
        """
        print(" Rotation des logs...")
        
        compressed_count = 0
        deleted_count = 0
        
        for filename in os.listdir(self.log_dir):
            if not filename.startswith('alerts_') or not filename.endswith('.log'):
                continue
            
            filepath = os.path.join(self.log_dir, filename)
            file_date_str = filename.replace('alerts_', '').replace('.log', '')
            
            try:
                file_date = datetime.strptime(file_date_str, '%Y-%m-%d')
                age_days = (datetime.now() - file_date).days
                
                # Fichier > 1 jour, Compression
                if age_days >= 1:
                    gz_path = filepath + '.gz'
                    
                    if not os.path.exists(gz_path):
                        with open(filepath, 'rb') as f_in:
                            with gzip.open(gz_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        os.remove(filepath)
                        compressed_count += 1
                        print(f"    Compression : {filename}")
                
                # Fichier > 7 jours, Suppression
                if age_days >= 7:
                    gz_path = filepath + '.gz'
                    if os.path.exists(gz_path):
                        os.remove(gz_path)
                        deleted_count += 1
                        print(f"   Supprimé : {filename}.gz")
            
            except ValueError:
                continue
        
        print(f" Rotation terminée : {compressed_count} compressés, {deleted_count} supprimés")
    
    def get_stats(self):
        """Retourne des statistiques sur les logs"""
        stats = {
            'total_files': 0,
            'total_size_mb': 0,
            'oldest_log': None,
            'newest_log': None
        }
        
        log_files = []
        
        for filename in os.listdir(self.log_dir):
            if filename.startswith('alerts_'):
                filepath = os.path.join(self.log_dir, filename)
                size = os.path.getsize(filepath)
                
                stats['total_files'] += 1
                stats['total_size_mb'] += size / (1024 * 1024)
                
                log_files.append(filename)
        
        if log_files:
            stats['oldest_log'] = min(log_files)
            stats['newest_log'] = max(log_files)
        
        return stats
    
    def tail_logs(self, lines=20):
        """
        Affiche les N dernières lignes du log 
        """
        if not os.path.exists(self.current_log_file):
            return []
        
        with open(self.current_log_file, 'r') as f:
            return f.readlines()[-lines:]


# Test du module
if __name__ == "__main__":
    print(" Log Manager - Test")
    
    log_manager = LogManager()
    
    print("\n Test d'écriture...")
    
    test_alert = {
        'severity': 'CRITICAL',
        'category': 'Port Scan',
        'description': 'Test alert',
        'source_ip': '192.168.1.100'
    }
    
    log_manager.log_alert(test_alert)
    log_manager.log_message("Daemon démarré", "INFO")
    log_manager.log_message("Capture en cours", "INFO")
    
    print("  3 entrées écrites")
    
    print("\n Statistiques des logs :")
    stats = log_manager.get_stats()
    print(f"    • Fichiers : {stats['total_files']}")
    print(f"    • Taille totale : {stats['total_size_mb']:.2f} MB")
    
    print("\n Les lignes du log :")
    for line in log_manager.tail_logs(5):
        print(f"    {line.strip()}")
    
    print("\n Test terminé ")