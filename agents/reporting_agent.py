#!/usr/bin/env python3
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class BugBountyReport:
    title: str
    severity: str
    asset_scope: str
    description: str
    impact: str
    steps_to_reproduce: List[str]
    expected_behavior: str
    actual_behavior: str
    evidence: str
    remediation: str
    references: List[str]
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    
    def to_markdown(self) -> str:
        report = f"""# {self.title}

## Severity
{self.severity}

## Asset / Scope
{self.asset_scope}

## Description
{self.description}

## Impact
{self.impact}

## Steps to Reproduce
"""
        for i, step in enumerate(self.steps_to_reproduce, 1):
            report += f"{i}. {step}\n"
            
        report += f"""
## Expected Behavior
{self.expected_behavior}

## Actual Behavior
{self.actual_behavior}

## Evidence
{self.evidence}

## Remediation
{self.remediation}

"""
        if self.cve_id:
            report += f"## CVE\n{self.cve_id}\n\n"
        if self.cwe_id:
            report += f"## CWE\n{self.cwe_id}\n\n"
            
        if self.references:
            report += "## References\n"
            for ref in self.references:
                report += f"- {ref}\n"
                
        return report
        
    def to_hackerone(self) -> Dict:
        return {
            "title": self.title,
            "severity": {
                "rating": self.severity.lower()
            },
            "vulnerability_details": {
                "cwe_id": self.cwe_id,
                "cve_id": self.cve_id
            },
            "impact": self.impact,
            "description": f"{self.description}\n\n### Steps to Reproduce\n" + 
                          "\n".join(f"{i}. {s}" for i, s in enumerate(self.steps_to_reproduce, 1)),
            "original_report": {
                "steps": self.steps_to_reproduce,
                "expected": self.expected_behavior,
                "actual": self.actual_behavior
            },
            "remediation": self.remediation,
            "references": self.references
        }
        
    def to_json(self) -> str:
        return json.dumps({
            "title": self.title,
            "severity": self.severity,
            "asset_scope": self.asset_scope,
            "description": self.description,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id
        }, indent=2)


class ReportingAgent:
    """Reporting Agent - Converts findings into professional security reports"""
    
    NAME = "Reporting Agent"
    VERSION = "2.0.0"
    
    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]
    
    def __init__(self, memory_db="memory.db"):
        self.memory_db = memory_db
        self.templates = {}
        self._load_templates()
        
    def _load_templates(self):
        self.templates = {
            "bug_bounty": {
                "format": "markdown",
                "required_fields": [
                    "title", "severity", "asset_scope", "description",
                    "impact", "steps_to_reproduce", "evidence", "remediation"
                ]
            },
            "internal": {
                "format": "markdown",
                "required_fields": [
                    "title", "severity", "affected_systems", "description",
                    "impact", "steps_to_reproduce", "evidence", 
                    "remediation", "risk_rating"
                ]
            },
            "executive": {
                "format": "markdown",
                "required_fields": [
                    "summary", "risk_level", "key_findings", 
                    "business_impact", "recommendations"
                ]
            },
            "technical": {
                "format": "markdown",
                "required_fields": [
                    "title", "description", "technical_details",
                    "proof_of_concept", "impact", "remediation",
                    "references"
                ]
            }
        }
        
    def create_bug_bounty_report(self, finding: Dict) -> BugBountyReport:
        return BugBountyReport(
            title=finding.get("title", "Untitled Finding"),
            severity=finding.get("severity", "Medium"),
            asset_scope=finding.get("asset_scope", "N/A"),
            description=finding.get("description", ""),
            impact=finding.get("impact", ""),
            steps_to_reproduce=finding.get("steps_to_reproduce", []),
            expected_behavior=finding.get("expected", "Expected behavior"),
            actual_behavior=finding.get("actual", "Actual behavior"),
            evidence=finding.get("evidence", ""),
            remediation=finding.get("remediation", ""),
            references=finding.get("references", []),
            cve_id=finding.get("cve_id"),
            cwe_id=finding.get("cwe_id")
        )
        
    def create_report_from_findings(self, findings: List[Dict],
                                 format: str = "markdown") -> str:
        if format == "markdown":
            report = "# Security Findings Report\n\n"
            report += f"Generated: {datetime.now().isoformat()}\n\n"
            report += f"Total Findings: {len(findings)}\n\n"
            report += "---\n\n"
            
            severity_order = ["critical", "high", "medium", "low", "informational"]
            sorted_findings = sorted(
                findings, 
                key=lambda x: severity_order.index(x.get("severity", "medium").lower())
                              if x.get("severity", "").lower() in severity_order 
                              else 2
            )
            
            for finding in sorted_findings:
                severity = finding.get("severity", "N/A")
                report += f"## [{severity.upper()}] {finding.get('title', 'Untitled')}\n\n"
                report += f"**Asset:** {finding.get('asset_scope', 'N/A')}\n\n"
                report += f"**Description:** {finding.get('description', '')}\n\n"
                report += f"**Impact:** {finding.get('impact', '')}\n\n"
                
                steps = finding.get("steps_to_reproduce", [])
                if steps:
                    report += "**Steps to Reproduce:**\n"
                    for i, step in enumerate(steps, 1):
                        report += f"{i}. {step}\n"
                    report += "\n"
                    
                report += f"**Evidence:** {finding.get('evidence', '')}\n\n"
                report += f"**Remediation:** {finding.get('remediation', '')}\n\n"
                
                if finding.get("cve_id"):
                    report += f"**CVE:** {finding['cve_id']}\n\n"
                if finding.get("cwe_id"):
                    report += f"**CWE:** {finding['cwe_id']}\n\n"
                    
                report += "---\n\n"
                
            return report
            
        return json.dumps(findings, indent=2)
        
    def create_executive_summary(self, findings: List[Dict]) -> str:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        
        for finding in findings:
            sev = finding.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        summary = "# Executive Security Summary\n\n"
        summary += f"Generated: {datetime.now().isoformat()}\n\n"
        summary += f"## Overview\n\n"
        summary += f"Total Findings: {len(findings)}\n\n"
        summary += "## Severity Breakdown\n\n"
        for severity, count in severity_counts.items():
            summary += f"- **{severity.capitalize()}:** {count}\n"
            
        summary += "\n## Key Risks\n\n"
        
        critical_findings = [f for f in findings if f.get("severity", "").lower() == "critical"]
        high_findings = [f for f in findings if f.get("severity", "").lower() == "high"]
        
        if critical_findings:
            summary += "### Critical Risks\n"
            for f in critical_findings:
                summary += f"- {f.get('title', 'Untitled')}: {f.get('impact', '')}\n"
            summary += "\n"
            
        if high_findings:
            summary += "### High Risks\n"
            for f in high_findings:
                summary += f"- {f.get('title', 'Untitled')}: {f.get('impact', '')}\n"
            summary += "\n"
            
        summary += "## Recommendations\n\n"
        summary += "1. Immediate action on critical findings\n"
        summary += "2. Prioritize high severity items in next sprint\n"
        summary += "3. Implement detection rules\n"
        summary += "4. Schedule follow-up assessment\n"
        
        return summary
        
    def create_remediation_plan(self, findings: List[Dict]) -> str:
        severity_order = ["critical", "high", "medium", "low", "informational"]
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.index(x.get("severity", "medium").lower())
                        if x.get("severity", "").lower() in severity_order
                        else 2
        )
        
        plan = "# Remediation Plan\n\n"
        plan += f"Generated: {datetime.now().isoformat()}\n\n"
        
        for severity in severity_order:
            severity_findings = [f for f in sorted_findings 
                        if f.get("severity", "").lower() == severity]
                        
            if severity_findings:
                plan += f"## {severity.upper()} Priority\n\n"
                
                for i, f in enumerate(severity_findings, 1):
                    plan += f"### {i}. {f.get('title', 'Untitled')}\n\n"
                    plan += f"**Severity:** {f.get('severity', 'N/A')}\n\n"
                    plan += f"**Remediation:** {f.get('remediation', 'N/A')}\n\n"
                    
                    if f.get("remediation_deadline"):
                        plan += f"**Target Date:** {f.get('remediation_deadline')}\n\n"
                        
                    plan += "---\n\n"
                    
        return plan
        
    def create_cvss_vector(self, finding: Dict) -> str:
        av = "N"  # Attack Vector
        ac = "N"  # Attack Complexity
        pr = "N"  # Privileges Required
        ui = "N"  # User Interaction
        s = "N"   # Scope
        c = "N"   # Confidentiality
        i = "N"   # Integrity
        a = "N"   # Availability
        
        sev = finding.get("severity", "medium").lower()
        
        if sev == "critical":
            av, ac, pr, ui, s, c, i, a = "N", "L", "N", "N", "C", "H", "H", "H"
        elif sev == "high":
            av, ac, pr, ui, s, c, i, a = "N", "L", "N", "N", "U", "H", "H", "H"
        elif sev == "medium":
            av, ac, pr, ui, s, c, i, a = "N", "L", "N", "N", "U", "M", "M", "M"
        else:
            av, ac, pr, ui, s, c, i, a = "N", "H", "N", "N", "U", "L", "L", "L"
            
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        
    def store_report(self, report_type: str, content: str, metadata: Dict) -> bool:
        conn = sqlite3.connect(self.memory_db)
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO interactions 
                         (input_text, response, tool_used, success, timestamp)
                         VALUES (?, ?, ?, ?, ?)''',
                      (f"report:{report_type}", content, "reporting_agent", 1,
                       datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return True
        except:
            return False
        
    def export_to_yaml(self, finding: Dict) -> str:
        import yaml
        return yaml.dump(finding, default_flow_style=False)


reporting_agent = ReportingAgent()