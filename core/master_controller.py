#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import hashlib
import re
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

MISSION = "Learn / Adapt / Execute"
VERSION = "3.0.0-MASTER"

@dataclass
class AgentSpec:
    name: str
    domain: str
    capability: str
    spawn_cmd: str
    return_cmd: str
    status: str = "dormant"

class AdaptiveMode(Enum):
    NOVICE = "novice"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class SecurityDomain(Enum):
    NETWORK = "network"
    WEB = "web"
    BINARY = "binary"
    MALWARE = "malware"
    CRYPTO = "crypto"
    BOUNTY = "bounty"
    CLOUD = "cloud"
    OSINT = "osint"
    EXPLOIT_DEV = "exploit_dev"
    BLUE_TEAM = "blue_team"

AGENTS = [
    AgentSpec("RECON", "Network/OSINT", "Reconnaissance, enumeration", "/spawn recon", "/return recon"),
    AgentSpec("EXPLOIT", "Binary/Web", "Exploit development", "/spawn exploit", "/return exploit"),
    AgentSpec("MALWARE", "Malware Analysis", "Malware analysis", "/spawn malware", "/return malware"),
    AgentSpec("HUNTER", "Bug Bounty", "Vulnerability hunting", "/spawn hunt", "/return hunt"),
    AgentSpec("DECODER", "Cryptography", "Decoding/encoding", "/spawn decode", "/return decode"),
    AgentSpec("INTEL", "OSINT", "Intelligence gathering", "/spawn intel", "/return intel"),
    AgentSpec("REPORT", "Reporting", "Report generation", "/spawn report", "/return report"),
    AgentSpec("EDUCATOR", "Education", "Security education", "/spawn edu", "/return edu"),
    AgentSpec("CODEAUDIT", "Code Review", "Secure code auditing", "/spawn audit", "/return audit"),
    AgentSpec("EVOLVER", "Self-Evolution", "Self-improvement", "/spawn evolve", "/return evolve"),
]

class MasterController:
    PROMPT = """ParallaxForge MASTER CONTROLLER v3.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Mission: {mission}
Status: {status}
Learning Mode: {mode}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[10 SUB-AGENTS AVAILABLE]
  RECON   | EXPLOIT | MALWARE | HUNTER
  DECODER | INTEL  | REPORT | EDUCATOR
  CODEAUDIT | EVOLVER
[10 SECURITY DOMAINS]
  Network | Web | Binary | Malware | Crypto
  BugBounty | Cloud | OSINT | ExploitDev | BlueTeam
[COMMANDS]
  /spawn <agent>  /return <agent>  /hunt <target>
  /decode <data>  /analyze <target>  /mission <plan>
  /evolve         /ctf <challenge>   /learn <topic>
  /status        /help             /exit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
> """
    
    def __init__(self, workdir="."):
        self.workdir = workdir
        self.mission = MISSION
        self.version = VERSION
        self.mode = AdaptiveMode.NOVICE
        self.mode_level = 1
        self.active_agents = {}
        self.knowledge_base = {}
        self.failure_log = []
        self.technique_scores = {}
        self.scopes = []
        self.session_id = None
        self.history = []
        self.current_mission = None
        self.db_path = os.path.join(workdir, "parallax_master.db")
        self.init_db()
        self.detect_mode()
        
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS knowledge
                     (id INTEGER PRIMARY KEY, topic TEXT, content TEXT,
                      source TEXT, hash TEXT, date_added TEXT,
                      validation_score REAL, strength INTEGER)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS techniques
                     (id INTEGER PRIMARY KEY, name TEXT, domain TEXT,
                      description TEXT, steps TEXT, success_count INTEGER,
                      failure_count INTEGER, date_added TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS missions
                     (id INTEGER PRIMARY KEY, name TEXT, phase TEXT,
                      status TEXT, findings TEXT, date_added TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS findings
                     (id INTEGER PRIMARY KEY, title TEXT, severity TEXT,
                      domain TEXT, description TEXT, evidence TEXT,
                      remediation TEXT, date_added TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS reports
                     (id INTEGER PRIMARY KEY, type TEXT, content TEXT,
                      format TEXT, date_added TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS evolution_log
                     (id INTEGER PRIMARY KEY, action TEXT, topic TEXT,
                      old_value TEXT, new_value TEXT, date_added TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS mode_history
                     (id INTEGER PRIMARY KEY, from_mode TEXT, to_mode TEXT,
                      reason TEXT, date_added TEXT)''')
        
        conn.commit()
        conn.close()
        
    def detect_mode(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM knowledge")
        count = c.fetchone()[0]
        c.execute("SELECT SUM(success_count) FROM techniques")
        successes = c.fetchone()[0] or 0
        conn.close()
        
        if count > 100 and successes > 50:
            self.mode = AdaptiveMode.EXPERT
            self.mode_level = 4
        elif count > 50 and successes > 20:
            self.mode = AdaptiveMode.ADVANCED
            self.mode_level = 3
        elif count > 20 and successes > 5:
            self.mode = AdaptiveMode.INTERMEDIATE
            self.mode_level = 2
        else:
            self.mode = AdaptiveMode.NOVICE
            self.mode_level = 1
            
    def get_prompt(self) -> str:
        mode_str = self.mode.value.upper()
        status = "ACTIVE" if self.active_agents else "READY"
        agents_active = ", ".join([a for a in self.active_agents.keys()]) if self.active_agents else "NONE"
        return f"""{self.PROMPT.format(mission=self.mission, status=status, mode=mode_str)}
Active Agents: {agents_active}
Mission: {self.current_mission or 'None'}
> """
        
    def spawn_agent(self, agent_name: str, task: str = "") -> Dict:
        name = agent_name.upper()
        
        if name not in [a.name for a in AGENTS]:
            return {"error": f"Unknown agent: {name}"}
            
        agent_info = {
            "name": name,
            "task": task,
            "spawned_at": datetime.now().isoformat(),
            "status": "active",
            "session_id": self.session_id
        }
        
        self.active_agents[name] = agent_info
        self.log_history(f"spawn {name}", task)
        
        return {
            "spawned": name,
            "task": task,
            "available_commands": self.get_agent_commands(name)
        }
        
    def return_agent(self, agent_name: str) -> Dict:
        name = agent_name.upper()
        
        if name not in self.active_agents:
            return {"error": f"Agent {name} not active"}
            
        result = self.active_agents[name].copy()
        del self.active_agents[name]
        
        self.log_history(f"return {name}", str(result))
        return {"returned": name, "result": result}
        
    def get_agent_commands(self, agent_name: str) -> List[str]:
        commands = {
            "RECON": ["/recon <target>", "/scan_ports", "/whois", "/subdom", "/techdetect"],
            "EXPLOIT": ["/exploit <cve>", "/dev <target>", "/verify <poc>"],
            "MALWARE": ["/analyze <file>", "/strings", "/unpack", "/behavior"],
            "HUNTER": ["/hunt <scope>", "/recon <target>", "/validate", "/submit"],
            "DECODER": ["/decode <data>", "/encode <data>", "/auto", "/hash"],
            "INTEL": ["/osint <target>", "/search <query>", "/dorks"],
            "REPORT": ["/report vuln", "/report bounty", "/report malware"],
            "EDUCATOR": ["/learn <topic>", "/explain", "/tutorial"],
            "CODEAUDIT": ["/audit <file>", "/findings", "/secure"],
            "EVOLVER": ["/evolve", "/improve", "/gap"]
        }
        return commands.get(agent_name, [])
        
    def add_scope(self, scope: str) -> bool:
        if scope not in self.scopes:
            self.scopes.append(scope)
            self.log_history("add_scope", scope)
            return True
        return False
        
    def remove_scope(self, scope: str) -> bool:
        if scope in self.scopes:
            self.scopes.remove(scope)
            self.log_history("remove_scope", scope)
            return True
        return False
        
    def create_session(self, scope: str = "default") -> str:
        self.session_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{scope}".encode()
        ).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO missions (name, phase, status, date_added)
                     VALUES (?, ?, ?, ?)''',
                  (f"session_{self.session_id}", "init", "active",
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        self.log_history("create_session", scope)
        return self.session_id
        
    def log_history(self, command: str, result: str = ""):
        self.history.append({
            "command": command,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
    def record_success(self, technique: str, domain: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT id FROM techniques WHERE name = ? AND domain = ?''',
                  (technique, domain))
        row = c.fetchone()
        
        if row:
            c.execute('''UPDATE techniques SET success_count = success_count + 1
                         WHERE name = ? AND domain = ?''',
                      (technique, domain))
        else:
            c.execute('''INSERT INTO techniques (name, domain, success_count, failure_count, date_added)
                         VALUES (?, ?, 1, 0, ?)''',
                      (technique, domain, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        self.detect_mode()
        
    def record_failure(self, technique: str, domain: str, reason: str = ""):
        self.failure_log.append({
            "technique": technique,
            "domain": domain,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT id FROM techniques WHERE name = ? AND domain = ?''',
                  (technique, domain))
        row = c.fetchone()
        
        if row:
            c.execute('''UPDATE techniques SET failure_count = failure_count + 1
                         WHERE name = ? AND domain = ?''',
                      (technique, domain))
        else:
            c.execute('''INSERT INTO techniques (name, domain, success_count, failure_count, date_added)
                         VALUES (?, ?, 0, 1, ?)''',
                      (technique, domain, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
    def learn(self, topic: str, content: str, source: str = "manual") -> bool:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT id FROM knowledge WHERE hash = ?''', (content_hash,))
        if c.fetchone():
            conn.close()
            return False
            
        strength = self.calculate_strength(content)
        
        c.execute('''INSERT INTO knowledge (topic, content, source, hash, date_added, validation_score, strength)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (topic, content, source, content_hash,
                   datetime.now().isoformat(), 0.5, strength))
        conn.commit()
        conn.close()
        self.detect_mode()
        return True
        
    def calculate_strength(self, content: str) -> int:
        score = 0
        if len(content) > 100: score += 1
        if len(content) > 500: score += 1
        if "CVE-" in content: score += 2
        if "exploit" in content.lower(): score += 1
        if "remediation" in content.lower(): score += 1
        if "patch" in content.lower(): score += 1
        return min(score, 10)
        
    def evolve(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT topic, strength FROM knowledge ORDER BY strength ASC LIMIT 10")
        weak_topics = c.fetchall()
        
        c.execute("SELECT name, success_count, failure_count FROM techniques ORDER BY success_count DESC")
        technique_stats = c.fetchall()
        
        gaps = []
        for topic, strength in weak_topics:
            if strength < 5:
                gaps.append(f"Weak: {topic} (strength: {strength})")
                
        improvements = []
        for name, success, failure in technique_stats:
            if failure > success and failure > 0:
                rate = success / (success + failure)
                if rate < 0.5:
                    improvements.append(f"Improve: {name} (rate: {rate:.2f})")
        
        conn.close()
        
        self.log_history("evolve", f"gaps: {len(gaps)}, improvements: {len(improvements)}")
        self.detect_mode()
        
        return {
            "mode": self.mode.value,
            "mode_level": self.mode_level,
            "gaps_identified": gaps,
            "improvements_needed": improvements,
            "knowledge_count": len(weak_topics),
            "techniques_analyzed": len(technique_stats)
        }
        
    def status(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM knowledge")
        knowledge_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM techniques")
        techniques_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM findings")
        findings_count = c.fetchone()[0]
        
        c.execute("SELECT SUM(success_count) FROM techniques")
        successes = c.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "version": self.version,
            "mission": self.mission,
            "mode": self.mode.value,
            "mode_level": self.mode_level,
            "active_agents": list(self.active_agents.keys()),
            "scopes": self.scopes,
            "session": self.session_id,
            "knowledge": knowledge_count,
            "techniques": techniques_count,
            "findings": findings_count,
            "successes": successes,
            "failures": len(self.failure_log)
        }
        
    def get_findings(self, domain: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        if domain:
            c.execute("SELECT * FROM findings WHERE domain = ?", (domain,))
        else:
            c.execute("SELECT * FROM findings")
            
        rows = c.fetchall()
        conn.close()
        
        return [{"id": r[0], "title": r[1], "severity": r[2], "domain": r[3],
                "description": r[4], "evidence": r[5], "remediation": r[6]}
               for r in rows]
        
    def add_finding(self, title: str, severity: str, domain: str,
                   description: str, evidence: str, remediation: str) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO findings 
                     (title, severity, domain, description, evidence, remediation, date_added)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (title, severity, domain, description, evidence, remediation,
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return c.lastrowid


master_controller = MasterController()