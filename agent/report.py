import sqlite3
import pandas as pd
from datetime import datetime

class IncidentManager:
    def __init__(self, db_path="incidents.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize SQLite database table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                attack_type TEXT,
                severity TEXT,
                description TEXT,
                mitigation TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def save_incident(self, incident_data, log_data):
        """Save a classified incident to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract details
        timestamp = log_data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        source_ip = log_data.get('source_ip', 'Unknown')
        
        cursor.execute('''
            INSERT INTO incidents (timestamp, source_ip, attack_type, severity, description, mitigation)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            source_ip,
            incident_data.get('attack_type'),
            incident_data.get('severity'),
            incident_data.get('description'),
            incident_data.get('mitigation')
        ))
        
        conn.commit()
        conn.close()

    def get_all_incidents(self):
        """Retrieve all incidents from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query("SELECT * FROM incidents ORDER BY id DESC", conn)
            conn.close()
            return df
        except Exception as e:
            return pd.DataFrame()
            
    def generate_report(self):
        """Generate a summary report of all incidents."""
        df = self.get_all_incidents()
        if df.empty:
            return "No incidents found."
        
        report = "CYBER SECURITY INCIDENT REPORT\n"
        report += "="*30 + "\n\n"
        for index, row in df.iterrows():
            report += f"ID: {row['id']}\n"
            report += f"Time: {row['timestamp']}\n"
            report += f"Source IP: {row['source_ip']}\n"
            report += f"Type: {row['attack_type']} ({row['severity']})\n"
            report += f"Description: {row['description']}\n"
            report += f"Mitigation: {row['mitigation']}\n"
            report += "-"*30 + "\n"
        return report
