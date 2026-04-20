#!/usr/bin/env python3
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import hashlib

class DetectionAgent:
    """Detection Agent - Creates YARA, Sigma, SIEM, EDR detection rules"""
    
    NAME = "Detection Agent"
    VERSION = "2.0.0"
    
    def __init__(self, knowledge_db="knowledge.db"):
        self.knowledge_db = knowledge_db
        self.rules = []
        
    def create_yara_rule(self, name: str, strings: List[Dict], 
                      condition: str, metadata: Dict = None) -> str:
        rule = f'''
rule {name.replace(" ", "_").replace("-", "_")}
{{
    meta:
        author = "ParallaxForge"
        description = "Detection rule for {name}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
{self._format_metadata(metadata)}
    
    strings:
{self._format_yara_strings(strings)}
    
    condition:
        {condition}
}}
'''
        return rule
        
    def _format_yara_strings(self, strings: List[Dict]) -> str:
        formatted = []
        for s in strings:
            formatted.append(f'        {s["name"]} = "{s["value"]}"')
        return '\n'.join(formatted)
        
    def _format_metadata(self, metadata: Dict) -> str:
        if not metadata:
            return ""
        formatted = []
        for key, value in metadata.items():
            formatted.append(f'        {key} = "{value}"')
        return '\n'.join(formatted)
        
    def create_sigma_rule(self, name: str, detection: Dict,
                          level: str = "medium") -> str:
        rule = {
            "title": name,
            "id": hashlib.md5(name.encode()).hexdigest()[:8],
            "status": "experimental",
            "author": "ParallaxForge",
            "date": datetime.now().strftime('%Y-%m-%d'),
            "level": level,
            "detection": detection,
            "fields": detection.get("selection", {}).keys()
        }
        
        yaml_output = f'''title: {name}
id: {rule["id"]}
status: {rule["status"]}
author: {rule["author"]}
date: {rule["date"]}
level: {level}
detection:
  selection:
{self._format_sigma_selection(detection.get("selection", {}))}
  condition: {detection.get("condition", "selection")}
'''
        return yaml_output
        
    def _format_sigma_selection(self, selection: Dict) -> str:
        formatted = []
        for key, value in selection.items():
            if isinstance(value, str):
                formatted.append(f'    {key}: "{value}"')
            else:
                formatted.append(f'    {key}: {value}')
        return '\n'.join(formatted)
        
    def create_ioc_extraction(self, indicators: List[Dict]) -> Dict:
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "file_hashes": [],
            "email_addresses": [],
            "registry_keys": [],
            "mutexes": []
        }
        
        import re
        
        for indicator in indicators:
            indicator_str = str(indicator)
            
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            iocs["ip_addresses"].extend(re.findall(ip_pattern, indicator_str))
            
            url_pattern = r'https?://[^\s]+'
            iocs["urls"].extend(re.findall(url_pattern, indicator_str))
            
            md5_pattern = r'\b[a-fA-F0-9]{{32}}\b'
            iocs["file_hashes"].extend(re.findall(md5_pattern, indicator_str))
            
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            iocs["email_addresses"].extend(re.findall(email_pattern, indicator_str))
            
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
            
        return iocs
        
    def create_elasticsearch_query(self, index: str, 
                                 detection: Dict) -> Dict:
        query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": []
                }
            }
        }
        
        for field, value in detection.get("selection", {}).items():
            query["query"]["bool"]["must"].append({
                "match": {field: value}
            })
            
        return query
        
    def create_kql_query(self, detection: Dict) -> str:
        conditions = []
        
        for field, value in detection.get("selection", {}).items():
            if isinstance(value, str):
                conditions.append(f'{field} == "{value}"')
            else:
                conditions.append(f'{field} == {value}')
                
        return ' and '.join(conditions)
        
    def create_splunk_search(self, detection: Dict) -> str:
        conditions = []
        
        for field, value in detection.get("selection", {}).items():
            if isinstance(value, str):
                conditions.append(f'{field}="{value}"')
            else:
                conditions.append(f'{field}={value}')
                
        return ' '.join(conditions)
        
    def create_edr_rule(self, name: str, 
                       process_indicators: List[str],
                       file_indicators: List[str] = None,
                       network_indicators: List[str] = None) -> Dict:
        rule = {
            "name": name,
            "description": f"EDR detection for {name}",
            "author": "ParallaxForge",
            "created": datetime.now().isoformat(),
            "rules": []
        }
        
        for indicator in process_indicators:
            rule["rules"].append({
                "type": "process",
                "indicator": indicator,
                "action": "alert"
            })
            
        if file_indicators:
            for indicator in file_indicators:
                rule["rules"].append({
                    "type": "file",
                    "indicator": indicator,
                    "action": "alert"
                })
                
        if network_indicators:
            for indicator in network_indicators:
                rule["rules"].append({
                    "type": "network",
                    "indicator": indicator,
                    "action": "alert"
                })
                
        return rule
        
    def create_logsearch_rule(self, name: str, 
                               search_pattern: str,
                               log_source: str) -> Dict:
        return {
            "name": name,
            "description": f"Log search rule for {name}",
            "search": search_pattern,
            "source": log_source,
            "author": "ParallaxForge",
            "created": datetime.now().isoformat()
        }
        
    def store_rule(self, name: str, rule_type: str,
                   rule_content: str, target: str = "") -> bool:
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
        
    def create_detection_for_malware(self, analysis_result: Dict) -> Dict:
        rules = {}
        
        hashes = analysis_result.get("hashes", {})
        if hashes.get("sha256"):
            sha256 = hashes["sha256"]
            rules["yara"] = self.create_yara_rule(
                f"Malware_{sha256[:8]}",
                [{"name": "hash", "value": sha256}],
                "any of them",
                {"sha256": sha256}
            )
            
        strings_data = analysis_result.get("strings", [])
        suspicious_strings = [s for s in strings_data if len(s) > 20][:10]
        if suspicious_strings:
            yara_strings = [
                {"name": f"s{i}", "value": s} 
                for i, s in enumerate(suspicious_strings)
            ]
            rules["yara"] = self.create_yara_rule(
                "SuspiciousStrings",
                yara_strings,
                "any of them"
            )
            
        network_indicators = analysis_result.get("network_indicators", {})
        if network_indicators.get("urls"):
            rules["network"] = {
                "description": "Block suspicious URLs",
                "indicators": network_indicators["urls"][:10]
            }
            
        suspicious_apis = analysis_result.get("suspicious_apis", [])
        if suspicious_apis:
            rules["process"] = self.create_edr_rule(
                "SuspiciousAPIs",
                suspicious_apis
            )
            
        return rules
        
    def create_detection_for_web(self, findings: Dict) -> Dict:
        rules = {}
        
        if findings.get("xss"):
            rules["sigma"] = self.create_sigma_rule(
                "XSS_Detection",
                {
                    "selection": {
                        "event": "accesslog",
                        "uri": "*<script*"
                    },
                    "condition": "selection"
                },
                "high"
            )
            
        if findings.get("sqli"):
            rules["sigma"] = self.create_sigma_rule(
                "SQLi_Detection",
                {
                    "selection": {
                        "event": "accesslog",
                        "uri": "*'OR*'"
                    },
                    "condition": "selection"
                },
                "high"
            )
            
        return rules
        
    def generate_all_rules(self, context: str, 
                        indicators: List[Dict]) -> Dict:
        all_rules = {
            "yara": self.create_yara_rule(
                context,
                [{"name": "indicator", "value": str(indicators[0]) if indicators else ""}],
                "any of them"
            ),
            "sigma": self.create_sigma_rule(
                context,
                {"selection": {"field": "value"}, "condition": "selection"}
            ),
            "edr": self.create_edr_rule(
                context,
                [str(i) for i in indicators[:5]]
            ),
            "kql": self.create_kql_query(
                {"selection": {"field": "value"}}
            ),
            "splunk": self.create_splunk_search(
                {"selection": {"field": "value"}}
            )
        }
        
        return all_rules


detection_agent = DetectionAgent()