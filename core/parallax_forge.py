#!/usr/bin/env python3
import json
import os
import sqlite3
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

class TaskType(Enum):
    RECON = "recon"
    WEB_APP = "web_app"
    API = "api"
    MALWARE = "malware"
    REVERSE_ENGINEERING = "reverse_engineering"
    REPORTING = "reporting"
    DETECTION = "detection"
    REMEDIATION = "remediation"
    COMPLIANCE = "compliance"
    GENERAL = "general"

class AuthorizationLevel(Enum):
    UNAUTHORIZED = "unauthorized"
    AUTHORIZED_SAFE = "authorized_safe"
    AUTHORIZED_TESTING = "authorized_testing"
    FULL_ACCESS = "full_access"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

@dataclass
class SecurityFinding:
    title: str
    severity: str
    asset_scope: str
    description: str
    impact: str
    steps_to_reproduce: List[str]
    evidence: str
    remediation: str
    confidence: str = "medium"
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None

@dataclass
class MalwareAnalysisResult:
    classification: str
    behavior_summary: str
    static_indicators: List[str]
    dynamic_indicators: List[str]
    persistence_traits: List[str]
    network_indicators: List[str]
    detection_rules: List[str]
    confidence: str = "medium"

class ParallaxForge:
    CORE_IDENTITY = "ParallaxForge - Cybersecurity AI Assistant"
    VERSION = "2.0.0"
    
    def __init__(self, knowledge_db="knowledge.db", memory_db="memory.db"):
        self.knowledge_db = knowledge_db
        self.memory_db = memory_db
        self.scopes = []
        self.authorized_assets = []
        self.current_session = None
        self.audit_log = []
        self.tools = {}
        self.model_version = "2.0.0"
        self.initialized = False
        self.safety_rules_active = True
        self.init_databases()
        self.load_tools()
        
    def init_databases(self):
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                     (id INTEGER PRIMARY KEY, cve_id TEXT, name TEXT, severity TEXT,
                      description TEXT, payload TEXT, fix TEXT, date_added TEXT,
                      category TEXT, confirmed INTEGER DEFAULT 0,
                      cwe_id TEXT, cvss_score REAL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS techniques
                     (id INTEGER PRIMARY KEY, name TEXT, category TEXT,
                      description TEXT, steps TEXT, effectiveness REAL,
                      date_added TEXT, mitre_id TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS tools
                     (id INTEGER PRIMARY KEY, name TEXT, type TEXT,
                      capabilities TEXT, implementation TEXT, date_added TEXT,
                      safety_level TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS learned_data
                     (id INTEGER PRIMARY KEY, topic TEXT, content TEXT,
                      source TEXT, hash TEXT, date_added TEXT,
                      validation_score REAL DEFAULT 0,
                      validated INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS findings
                     (id INTEGER PRIMARY KEY, title TEXT, severity TEXT,
                      asset_scope TEXT, description TEXT, impact TEXT,
                      evidence TEXT, remediation TEXT, confidence TEXT,
                      cve_id TEXT, cwe_id TEXT, date_added TEXT,
                      authorization_verified INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS malware_samples
                     (id INTEGER PRIMARY KEY, sha256 TEXT, classification TEXT,
                      behavior_summary TEXT, static_indicators TEXT,
                      dynamic_indicators TEXT, network_indicators TEXT,
                      date_analyzed TEXT, confidence TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS detection_rules
                     (id INTEGER PRIMARY KEY, name TEXT, rule_type TEXT,
                      rule_content TEXT, target TEXT, date_added TEXT,
                      tested INTEGER DEFAULT 0, effectiveness REAL)''')
        
        conn.commit()
        conn.close()
        
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS interactions
                     (id INTEGER PRIMARY KEY, input_text TEXT, response TEXT,
                      tool_used TEXT, success INTEGER, timestamp TEXT,
                      authorization_checked INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                     (id INTEGER PRIMARY KEY, session_id TEXT, start_time TEXT,
                      end_time TEXT, findings INTEGER, scope TEXT,
                      authorization_level TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                     (id INTEGER PRIMARY KEY, action TEXT, target TEXT,
                      result TEXT, timestamp TEXT, authorized INTEGER,
                      scope_verified INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS report_templates
                     (id INTEGER PRIMARY KEY, template_type TEXT,
                      title_format TEXT, content_template TEXT,
                      fields_required TEXT)''')
        
        conn.commit()
        conn.close()
        self.initialized = True
        self._load_default_templates()
        
    def _load_default_templates(self):
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        
        c.execute('''SELECT COUNT(*) FROM report_templates''')
        if c.fetchone()[0] == 0:
            bug_bounty_template = json.dumps({
                "title": "{ vulnerability } on { asset }",
                "severity": "High/Medium/Low",
                "asset_scope": "{ URL/Function }",
                "description": "Description of the vulnerability",
                "impact": "Business/security impact",
                "steps_to_reproduce": ["1. ", "2. ", "3. "],
                "expected": "Expected behavior",
                "actual": "Actual behavior",
                "evidence": "Screenshots/logs",
                "remediation": "Suggested fix",
                "references": []
            })
            
            c.execute('''INSERT INTO report_templates 
                         (template_type, title_format, content_template, fields_required)
                         VALUES (?, ?, ?, ?)''',
                      ("bug_bounty", bug_bounty_template, bug_bounty_template,
                       json.dumps(["title", "severity", "asset_scope", "description", "impact", "steps_to_reproduce", "evidence", "remediation"])))
            
            conn.commit()
        conn.close()
        
    def load_tools(self):
        self.tools = {
            "scanner": {},
            "exploit": {},
            "analysis": {},
            "decoder": {},
            "navigation": {},
            "detection": {},
            "reporting": {}
        }
        
    def verify_authorization(self, target: str, action: str = "read") -> Tuple[bool, str]:
        if not self.scopes:
            return False, "No scope defined. Please specify target scope."
        
        in_scope = any(
            target.startswith(scope) or scope in target 
            for scope in self.scopes
        )
        
        if not in_scope:
            return False, f"Target {target} not in defined scope: {self.scopes}"
        
        self._log_action("authorization_check", target, "authorized", True)
        return True, "Authorization verified"
        
    def _log_action(self, action: str, target: str, result: str, 
                   authorized: bool = True, scope_verified: bool = True):
        entry = {
            "action": action,
            "target": target,
            "result": result,
            "timestamp": datetime.now().isoformat(),
            "authorized": authorized,
            "scope_verified": scope_verified
        }
        self.audit_log.append(entry)
        
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        c.execute('''INSERT INTO audit_log 
                     (action, target, result, timestamp, authorized, scope_verified)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (action, target, result, entry["timestamp"], 
                   1 if authorized else 0, 1 if scope_verified else 0))
        conn.commit()
        conn.close()
        
    def add_scope(self, scope: str) -> bool:
        if scope not in self.scopes:
            self.scopes.append(scope)
            return True
        return False
        
    def remove_scope(self, scope: str) -> bool:
        if scope in self.scopes:
            self.scopes.remove(scope)
            return True
        return False
        
    def add_authorized_asset(self, asset: str, description: str = "") -> bool:
        self.authorized_assets.append({"asset": asset, "description": description})
        return True
        
    def register_tool(self, tool_type: str, tool_name: str, 
                      implementation: str, capabilities: str,
                      safety_level: str = "safe"):
        self.tools[tool_type][tool_name] = {
            "implementation": implementation,
            "capabilities": capabilities,
            "safety_level": safety_level
        }
        
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO tools 
                     (name, type, capabilities, implementation, date_added, safety_level)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (tool_name, tool_type, capabilities, implementation,
                   datetime.now().isoformat(), safety_level))
        conn.commit()
        conn.close()
        
    def add_vulnerability(self, cve_id: str, name: str, severity: str,
                          description: str, payload: str, fix: str,
                          category: str, cwe_id: str = None,
                          cvss_score: float = None) -> bool:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO vulnerabilities 
                     (cve_id, name, severity, description, payload, fix,
                      date_added, category, cwe_id, cvss_score)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (cve_id, name, severity, description, payload, fix,
                   datetime.now().isoformat(), category, cwe_id, cvss_score))
        conn.commit()
        conn.close()
        return True
        
    def add_finding(self, finding: SecurityFinding) -> int:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO findings 
                     (title, severity, asset_scope, description, impact,
                      evidence, remediation, confidence, cve_id, cwe_id,
                      date_added)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (finding.title, finding.severity, finding.asset_scope,
                   finding.description, finding.impact, finding.evidence,
                   finding.remediation, finding.confidence,
                   finding.cve_id, finding.cwe_id,
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return c.lastrowid
        
    def store_detection_rule(self, name: str, rule_type: str,
                             rule_content: str, target: str) -> bool:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''INSERT INTO detection_rules 
                     (name, rule_type, rule_content, target, date_added)
                     VALUES (?, ?, ?, ?, ?)''',
                  (name, rule_type, rule_content, target,
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
        
    def learn(self, topic: str, content: str, source: str,
              validation_score: float = 0.0) -> bool:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        c.execute('''SELECT id FROM learned_data WHERE hash = ?''',
                  (content_hash,))
        if c.fetchone():
            conn.close()
            return False
            
        c.execute('''INSERT INTO learned_data 
                     (topic, content, source, hash, date_added,
                      validation_score)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (topic, content, source, content_hash,
                   datetime.now().isoformat(), validation_score))
        conn.commit()
        conn.close()
        return True
        
    def get_findings(self, severity: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        if severity:
            c.execute('''SELECT * FROM findings WHERE severity = ?
                         ORDER BY date_added DESC''',
                      (severity,))
        else:
            c.execute('''SELECT * FROM findings ORDER BY date_added DESC''')
            
        rows = c.fetchall()
        conn.close()
        
        findings = []
        for row in rows:
            findings.append({
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "asset_scope": row[3],
                "description": row[4],
                "impact": row[5],
                "evidence": row[6],
                "remediation": row[7],
                "confidence": row[8],
                "cve_id": row[9],
                "cwe_id": row[10],
                "date_added": row[11]
            })
        return findings
        
    def get_vulnerabilities(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        c.execute('''SELECT * FROM vulnerabilities 
                     ORDER BY date_added DESC LIMIT ?''',
                  (limit,))
        rows = c.fetchall()
        conn.close()
        
        vulns = []
        for row in rows:
            vulns.append({
                "cve_id": row[1],
                "name": row[2],
                "severity": row[3],
                "description": row[4],
                "category": row[8],
                "cvss_score": row[10]
            })
        return vulns
        
    def get_detection_rules(self, rule_type: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        if rule_type:
            c.execute('''SELECT * FROM detection_rules 
                         WHERE rule_type = ? ORDER BY date_added DESC''',
                      (rule_type,))
        else:
            c.execute('''SELECT * FROM detection_rules 
                         ORDER BY date_added DESC''')
            
        rows = c.fetchall()
        conn.close()
        
        rules = []
        for row in rows:
            rules.append({
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "content": row[3],
                "target": row[4],
                "tested": row[6],
                "effectiveness": row[7]
            })
        return rules
        
    def self_update(self) -> Dict:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
        vulns_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM techniques")
        techs_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM learned_data")
        learned_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM findings")
        findings_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM detection_rules")
        rules_count = c.fetchone()[0]
        
        conn.close()
        
        return {
            "model": self.CORE_IDENTITY,
            "version": self.model_version,
            "capabilities": list(self.tools.keys()),
            "knowledge": {
                "vulnerabilities": vulns_count,
                "techniques": techs_count,
                "learned": learned_count,
                "findings": findings_count,
                "detection_rules": rules_count
            },
            "current_scopes": self.scopes,
            "authorized_assets": len(self.authorized_assets),
            "safety_active": self.safety_rules_active,
            "last_update": datetime.now().isoformat(),
            "audit_entries": len(self.audit_log)
        }
        
    def create_session(self, scope: str, auth_level: str = "authorized_safe") -> str:
        session_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{scope}".encode()
        ).hexdigest()[:16]
        
        self.current_session = session_id
        
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        c.execute('''INSERT INTO sessions 
                     (session_id, start_time, scope, authorization_level)
                     VALUES (?, ?, ?, ?)''',
                  (session_id, datetime.now().isoformat(), scope, auth_level))
        conn.commit()
        conn.close()
        
        return session_id
        
    def get_audit_log(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        c.execute('''SELECT * FROM audit_log 
                     ORDER BY timestamp DESC LIMIT ?''',
                  (limit,))
        rows = c.fetchall()
        conn.close()
        
        entries = []
        for row in rows:
            entries.append({
                "id": row[0],
                "action": row[1],
                "target": row[2],
                "result": row[3],
                "timestamp": row[4],
                "authorized": row[5],
                "scope_verified": row[6]
            })
        return entries
        
    def generate_report(self, finding_id: int = None,
                     format: str = "markdown") -> str:
        conn = sqlite3.connect(self.knowledge_db)
        c = conn.cursor()
        
        if finding_id:
            c.execute('''SELECT * FROM findings WHERE id = ?''',
                      (finding_id,))
        else:
            c.execute('''SELECT * FROM findings 
                         ORDER BY date_added DESC LIMIT 10''')
            
        rows = c.fetchall()
        conn.close()
        
        if format == "markdown":
            report = "# Security Findings Report\n\n"
            for row in rows:
                report += f"## {row[1]} ({row[2]})\n\n"
                report += f"**Scope:** {row[3]}\n\n"
                report += f"**Description:** {row[4]}\n\n"
                report += f"**Impact:** {row[5]}\n\n"
                report += f"**Evidence:** {row[6]}\n\n"
                report += f"**Remediation:** {row[7]}\n\n"
                report += f"**Confidence:** {row[8]}\n\n"
                if row[9]:
                    report += f"**CVE:** {row[9]}\n\n"
                report += "---\n\n"
            return report
            
        return json.dumps([dict(row) for row in rows], indent=2)
        
    def spawn_agent(self, agent_type: TaskType, task: str) -> Dict:
        agent_info = {
            "type": agent_type.value,
            "task": task,
            "spawned_at": datetime.now().isoformat(),
            "status": "initialized"
        }
        
        self._log_action("agent_spawn", agent_type.value, task, True)
        return agent_info
        
    def validate_safe_operation(self, action: str, target: str) -> Dict:
        disallowed_patterns = [
            "unauthorized", "credential theft", "phishing",
            "evasion", "persistence", "exfiltration",
            "destructive", "weaponize", "stealth"
        ]
        
        action_lower = action.lower()
        target_lower = target.lower()
        
        for pattern in disallowed_patterns:
            if pattern in action_lower or pattern in target_lower:
                return {
                    "safe": False,
                    "reason": f"Action contains restricted pattern: {pattern}",
                    "alternative": "Consider defensive/remediation approach"
                }
                
        return {"safe": True, "reason": "Action appears safe"}


parallax = ParallaxForge()