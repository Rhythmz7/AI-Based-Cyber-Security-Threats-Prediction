# data_generator.py
import time
import random
import json
from datetime import datetime
from db_manager import Database
import os

class ThreatGenerator:
    def __init__(self, db):
        self.db = db
        self.attack_types = [
            'DDoS', 'Malware', 'Phishing', 'SQL Injection', 'Ransomware',
            'Zero-Day', 'Brute Force', 'XSS', 'Man-in-the-Middle', 'Trojan',
            'Worm', 'Spyware', 'Botnet', 'Keylogger', 'Cryptojacking'
        ]
        self.countries = [
            'USA', 'China', 'Russia', 'India', 'Germany', 'UK', 'France',
            'Brazil', 'Japan', 'Canada', 'South Korea', 'Australia',
            'Netherlands', 'Italy', 'Spain', 'Mexico', 'Turkey', 'Iran'
        ]

    def generate_threat(self):
        country = random.choice(self.countries)
        attack_type = random.choice(self.attack_types)
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        severity_name = random.choice(list(severity_map.keys()))
        severity_score = severity_map[severity_name]
        
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        timestamp = datetime.now().isoformat()
        
        threat = {
            'timestamp': timestamp,
            'country': country,
            'attack_type': attack_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'severity_name': severity_name,
            'severity_score': severity_score,
            'protocol': random.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'FTP'])
        }
        
        # Insert into database
        self.db.insert_log(
            ts=timestamp,
            src=src_ip,
            dst=dst_ip,
            proto=threat['protocol'],
            threat=attack_type,
            severity=severity_score,
            raw_json=json.dumps(threat)
        )
        
        # 50% chance of generating an alert for High/Critical
        if severity_score > 2 and random.random() > 0.5:
            self.db.insert_alert(
                ts=timestamp,
                ip=src_ip,
                threat=attack_type,
                severity=severity_score,
                desc=f"High severity {attack_type} detected from {src_ip}"
            )
        
        return threat

def main():
    try:
        # --- Get credentials from GitHub environment variables ---
        db_pass = os.environ.get("DB_PASS")
        db_user = os.environ.get("DB_USER")
        db_host = os.environ.get("DB_HOST")
        db_name = os.environ.get("DB_NAME")
        db_port = os.environ.get("DB_PORT", 5432)

        if not all([db_pass, db_user, db_host, db_name]):
            print("Error: Database credentials not found in environment variables.")
            print("Script will not run.")
            return

        db = Database(
            db_type="postgres",
            host=db_host,
            user=db_user,
            password=db_pass,
            database=db_name,
            port=int(db_port)
        )
        # --- End of credentials block ---

        generator = ThreatGenerator(db)
        print("Running threat generator for a fixed batch...")

        # --- MODIFIED: Run 50 times and then stop ---
        for i in range(50):
            threat = generator.generate_threat()
            print(f"({i+1}/50) Generated Threat: {threat['attack_type']}")
        
        print("Batch generation complete.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'db' in locals() and db.connection:
            db.close()
            print("Database connection closed.")

if __name__ == "__main__":
    main()