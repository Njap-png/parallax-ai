import json
import os
import sqlite3
import hashlib
import re
from datetime import datetime
from pathlib import Path

class ParallaxAI:
    def __init__(self, knowledge_db="knowledge.db", memory_db="memory.db"):
        self.knowledge_db = knowledge_db
        self.memory_db = memory_db
        self.tools = {}
        self.scopes = []
        self.model_version = "1.0.0"
        self.initialized = False
        self.init_databases()
        self.load_tools()
        
    def init_databases(self):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                     (id INTEGER PRIMARY KEY, cve_id TEXT, name TEXT, severity TEXT,
                      description TEXT, payload TEXT, fix TEXT, date_added TEXT,
                      category TEXT, confirmed INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS techniques
                     (id INTEGER PRIMARY KEY, name TEXT, category TEXT,
                      description TEXT, steps TEXT, effectiveness REAL,
                      date_added TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS tools
                     (id INTEGER PRIMARY KEY, name TEXT, type TEXT,
                      capabilities TEXT, implementation TEXT, date_added TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS learned_data
                     (id INTEGER PRIMARY KEY, topic TEXT, content TEXT,
                      source TEXT, hash TEXT, date_added TEXT,
                      validation_score REAL DEFAULT 0)''')
        conn.commit()
        conn.close()
        
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS interactions
                     (id INTEGER PRIMARY KEY, input_text TEXT, response TEXT,
                      tool_used TEXT, success INTEGER, timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                     (id INTEGER PRIMARY KEY, session_id TEXT, start_time TEXT,
                      end_time TEXT, findings INTEGER)''')
        conn.commit()
        conn.close()
        self.initialized = True
        
    def load_tools(self):
        self.tools = {
            "scanner": {},
            "exploit": {},
            "analysis": {},
            "decoder": {},
            "navigation": {}
        }
        
    def add_vulnerability(self, cve_id, name, severity, description, payload, fix, category):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO vulnerabilities 
                     (cve_id, name, severity, description, payload, fix, date_added, category)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (cve_id, name, severity, description, payload, fix, 
                   datetime.now().isoformat(), category))
        conn.commit()
        conn.close()
        
    def learn(self, topic, content, source, validation_score=0.0):
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''SELECT id FROM learned_data WHERE hash = ?''', (content_hash,))
        if c.fetchone():
            conn.close()
            return False
        c.execute('''INSERT INTO learned_data (topic, content, source, hash, date_added, validation_score)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (topic, content, source, content_hash, 
                   datetime.now().isoformat(), validation_score))
        conn.commit()
        conn.close()
        
    def self_update(self):
        vulnerabilities = self.get_recent_vulnerabilities()
        techniques = self.get_techniques()
        return {
            "vulnerabilities_count": len(vulnerabilities),
            "techniques_count": len(techniques),
            "knowledge_version": self.model_version,
            "last_update": datetime.now().isoformat()
        }
        
    def get_recent_vulnerabilities(self):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute("SELECT * FROM vulnerabilities ORDER BY date_added DESC")
        rows = c.fetchall()
        conn.close()
        return rows
    
    def get_techniques(self):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute("SELECT * FROM techniques ORDER BY effectiveness DESC")
        rows = c.fetchall()
        conn.close()
        return rows
        
    def add_scope(self, scope):
        if scope not in self.scopes:
            self.scopes.append(scope)
            return True
        return False
        
    def remove_scope(self, scope):
        if scope in self.scopes:
            self.scopes.remove(scope)
            return True
        return False
        
    def register_tool(self, tool_type, tool_name, implementation, capabilities):
        self.tools[tool_type][tool_name] = {
            "implementation": implementation,
            "capabilities": capabilities
        }
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO tools (name, type, capabilities, implementation, date_added)
                     VALUES (?, ?, ?, ?, ?)''',
                  (tool_name, tool_type, capabilities, implementation,
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()

parallax = ParallaxAI()