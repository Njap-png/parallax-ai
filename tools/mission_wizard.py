#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.master_controller import master_controller
from core.auto_decoder import auto_decoder
from tools.scanner import web_scanner, network_scanner, subdomain_scanner, dir_scanner
from tools.ctf import ctf_engine

class MissionWizard:
    PHASES = {
        1: {"name": "RECON", "desc": "Target enumeration"},
        2: {"name": "SCAN", "desc": "Vulnerability discovery"},
        3: {"name": "VALIDATE", "desc": "Proof of concept"},
        4: {"name": "REPORT", "desc": "Document findings"},
        5: {"name": "SUBMIT", "desc": "Bug bounty submission"}
    }
    
    def __init__(self):
        self.controller = master_controller
        self.scanner = web_scanner
        self.net_scanner = network_scanner
        self.sub_scanner = subdomain_scanner
        self.dir_scanner = dir_scanner
        self.target = None
        self.scope = []
        self.current_phase = 0
        self.findings = []
        
    def start(self, target: str):
        self.target = target
        self.current_phase = 1
        return {
            "target": target,
            "phase": 1,
            "name": "RECON",
            "description": "Starting reconnaissance...",
            "next": "Automated recon will begin. You can also use /recon manually."
        }
        
    def execute_phase(self, phase: int, target: str = None):
        target = target or self.target
        
        if phase == 1:
            return self._reconnaissance(target)
        elif phase == 2:
            return self._scan(target)
        elif phase == 3:
            return self._validate(target)
        elif phase == 4:
            return self._report()
        elif phase == 5:
            return self._submit()
        else:
            return {"error": f"Invalid phase: {phase}"}
            
    def _reconnaissance(self, target: str):
        results = {
            "phase": 1,
            "name": "RECONnaissance",
            "target": target,
            "subdomains": [],
            "ports": [],
            "tech": "Scanning...",
            "findings": []
        }
        
        results["subdomains"] = self.sub_scanner.enumerate(target)
        results["ports"] = self.net_scanner.scan_ports(target)
        
        return results
        
    def _scan(self, target: str):
        results = {
            "phase": 2,
            "name": "SCAN",
            "target": target,
            "vulnerabilities": [],
            "scan_type": "full"
        }
        
        results["vulnerabilities"] = self.scanner.full_scan(target)
        
        return results
        
    def _validate(self, target: str):
        return {
            "phase": 3,
            "name": "VALIDATE",
            "target": target,
            "status": "Ready for PoC development",
            "tools": ["Burp Suite", "SQLMap", "Metasploit", "Custom scripts"]
        }
        
    def _report(self):
        return {
            "phase": 4,
            "name": "REPORT",
            "findings": self.findings,
            "template": "Use /report vuln for template"
        }
        
    def _submit(self):
        return {
            "phase": 5,
            "name": "SUBMIT",
            "status": "Ready for submission",
            "platforms": ["HackerOne", "Bugcrowd", "Open Bug Bounty"]
        }
        
    def get_status(self):
        return {
            "target": self.target,
            "phase": self.current_phase,
            "phase_name": self.PHASES.get(self.current_phase, {}).get("name", "UNKNOWN"),
            "findings_count": len(self.findings)
        }
        
    def add_finding(self, finding: dict):
        self.findings.append(finding)
        
    def help(self):
        help_text = """
=== MISSION WIZARD ===

5-Phase Autonomous Operation:

Phase 1: RECON
  - Subdomain enumeration
  - Port scanning
  - Technology detection
  - WHOIS lookup
  
Phase 2: SCAN
  - XSS scanning
  - SQL injection
  - SSRF testing
  - Sensitive files
  - CORS misconfiguration
  
Phase 3: VALIDATE
  - Proof of concept development
  - Exploitation
  - Impact analysis
  
Phase 4: REPORT
  - Full vulnerability report
  - Severity assessment
  - Remediation guidance
  
Phase 5: SUBMIT
  - Bug bounty platform submission
  - Follow-up

Commands:
  /mission start <target>  - Start new mission
  /mission next            - Proceed to next phase
  /mission status         - Show mission status
  /mission abort          - Abort current mission
"""
        return help_text


mission_wizard = MissionWizard()


def start_mission(target: str):
    return mission_wizard.start(target)

def next_phase(target: str = None):
    phase = mission_wizard.current_phase + 1
    return mission_wizard.execute_phase(phase, target)

def mission_status():
    return mission_wizard.get_status()

def abort_mission():
    mission_wizard.target = None
    mission_wizard.current_phase = 0
    mission_wizard.findings = []
    return {"aborted": True}

def mission_help():
    return mission_wizard.help()