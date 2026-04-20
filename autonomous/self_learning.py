import json
import sqlite3
import hashlib
import re
import requests
from datetime import datetime
from urllib.parse import urlparse

class AutonomousLearning:
    def __init__(self, knowledge_db="knowledge.db"):
        self.knowledge_db = knowledge_db
        self.learning_sources = []
        self.confidence_threshold = 0.7
        self.last_update = None
        self.model_version = "1.0.0"
        
    def learn_from_web(self, url):
        try:
            resp = requests.get(url, timeout=10, verify=False)
            content = resp.text
            return self.process_learning_content(content, url)
        except Exception as e:
            return {"error": str(e)}
        
    def process_learning_content(self, content, source, validation_score=0.5):
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        payload_pattern = r'<script>.*?</script>|<\?php.*?\?>|\bexec\s*\(|\beval\s*\('
        
        vulns = re.findall(cve_pattern, content)
        payloads = re.findall(payload_pattern, content)
        
        if vulns:
            for cve in set(vulns):
                self.store_learned_data(cve, "vulnerability", source, validation_score)
                
        self.store_learned_data(
            f"learned_{datetime.now().timestamp()}",
            "content",
            source,
            validation_score
        )
        
        return {
            "learned": True,
            "cves_found": len(vulns),
            "payloads_found": len(payloads)
        }
        
    def store_learned_data(self, topic, content, source, validation_score):
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        c.execute('''SELECT id FROM learned_data WHERE hash = ?''', (content_hash,))
        if c.fetchone():
            conn.close()
            return False
            
        c.execute('''INSERT INTO learned_data 
                     (topic, content, source, hash, date_added, validation_score)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (topic, content, source, content_hash,
                   datetime.now().isoformat(), validation_score))
        conn.commit()
        conn.close()
        return True
        
    def add_learning_source(self, url, source_type):
        self.learning_sources.append({
            "url": url,
            "type": source_type,
            "added": datetime.now().isoformat()
        })
        
    def fetch_cve_database(self):
        sources = [
            "https://cve.mitre.org/data/cves/",
            "https://nvd.nist.gov/feeds/json/cves/1.0/"
        ]
        results = []
        for source in sources:
            try:
                result = self.learn_from_web(source)
                results.append(result)
            except:
                pass
        return results
        
    def add_technique(self, name, category, description, steps, effectiveness):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO techniques 
                     (name, category, description, steps, effectiveness, date_added)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (name, category, description, steps, effectiveness,
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
    def get_new_techniques(self):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute("SELECT * FROM techniques ORDER BY date_added DESC LIMIT 10")
        rows = c.fetchall()
        conn.close()
        return rows
        
    def validate_knowledge(self, topic):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''SELECT validation_score FROM learned_data 
                     WHERE topic = ?''', (topic,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else 0
        
    def self_update(self):
        update_info = {
            "version": self.model_version,
            "timestamp": datetime.now().isoformat(),
            "sources_count": len(self.learning_sources),
            "knowledge_version": "1.0.0"
        }
        
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM learned_data")
        update_info["total_learned"] = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
        update_info["total_vulnerabilities"] = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM techniques")
        update_info["total_techniques"] = c.fetchone()[0]
        
        conn.close()
        
        self.last_update = datetime.now()
        return update_info
        
    def update_model_version(self, new_version):
        self.model_version = new_version
        return {"updated": True, "version": new_version}

autonomous = AutonomousLearning()