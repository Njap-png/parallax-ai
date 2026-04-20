#!/usr/bin/env python3
import requests
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class WebAppAgent:
    """Web Application Security Agent - Reviews auth, sessions, input validation, CSRF, XSS, etc."""
    
    NAME = "Web App Agent"
    VERSION = "2.0.0"
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings = []
        
    def analyze(self, target: str) -> Dict:
        results = {
            "target": target,
            "authentication": None,
            "session": None,
            "authorization": None,
            "csrf": None,
            "xss": [],
            "sqli": [],
            "ssrf": [],
            "idor": [],
            "other_issues": []
        }
        return results
        
    def check_authentication(self, url: str) -> Dict:
        findings = {
            "weak_password_policy": False,
            "no_mfa": False,
            "insecure_session": False,
            "password_reset_flaw": False,
            "login_enumeration": False
        }
        
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            if "login" in url.lower() or "signin" in url.lower():
                if resp.status_code == 200:
                    findings["login_form_found"] = True
                    
            if "password" in resp.text.lower():
                findings["password_field_detected"] = True
                
        except Exception as e:
            findings["error"] = str(e)
            
        return findings
        
    def check_session_management(self, url: str) -> Dict:
        findings = {
            "secure_flag_missing": False,
            "http_only_missing": False,
            "same_site_missing": False,
            "session_timeout": None,
            "session_fixation": False
        }
        
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            cookies = self.session.cookies
            
            for cookie in cookies:
                if not cookie.has_nonstandard_attr('Secure') and not cookie.secure:
                    findings["secure_flag_missing"] = True
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.http_only:
                    findings["http_only_missing"] = True
                    
        except Exception as e:
            findings["error"] = str(e)
            
        return findings
        
    def check_csrf(self, url: str) -> Dict:
        findings = {
            "csrf_token_missing": False,
            "csrf_token_weak": False,
            "double_submit": False,
            "referer_check": False
        }
        
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            html = resp.text
            
            forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL)
            for form in forms:
                if 'csrf' not in form.lower() and 'token' not in form.lower():
                    findings["csrf_token_missing"] = True
                    
                if 'name="_token"' not in form and 'name="csrf_token"' not in form:
                    findings["csrf_token_missing"] = True
                    
        except Exception as e:
            findings["error"] = str(e)
            
        return findings
        
    def check_xss(self, url: str) -> Dict:
        findings = {
            "reflected": [],
            "stored": [],
            "dom": []
        }
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>"
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        
        if params:
            for param in params.keys():
                for payload in xss_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        resp = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                        
                        if payload in resp.text:
                            findings["reflected"].append({
                                "parameter": param,
                                "payload": payload,
                                "url": url
                            })
                    except:
                        pass
                        
        return findings
        
    def check_sqli(self, url: str) -> Dict:
        findings = {
            "error_based": [],
            "blind": [],
            "union_based": []
        }
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '00:00:05'--"
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        
        if params:
            for param in params.keys():
                for payload in sqli_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        resp = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                        
                        error_keywords = ["sql", "syntax", "mysql", "oracle", "postgresql", "sqlite"]
                        if any(kw in resp.text.lower() for kw in error_keywords):
                            findings["error_based"].append({
                                "parameter": param,
                                "payload": payload,
                                "evidence": "SQL error detected"
                            })
                    except:
                        pass
                        
        return findings
        
    def check_ssrf(self, url: str) -> Dict:
        findings = {
            "vulnerable": [],
            "internal_access": []
        }
        
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://metadata.google.internal"
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}
        
        if params:
            for param in params.keys():
                for payload in ssrf_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        resp = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                        
                        if "localhost" in resp.text or "127.0.0.1" in resp.text:
                            findings["vulnerable"].append({
                                "parameter": param,
                                "payload": payload
                            })
                    except:
                        pass
                        
        return findings
        
    def check_idor(self, url: str, id_param: str = "id") -> Dict:
        findings = {
            "horizontal": [],
            "vertical": []
        }
        
        for i in range(1, 20):
            try:
                params = {id_param: str(i)}
                resp = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                
                if resp.status_code == 200:
                    findings["horizontal"].append({
                        "parameter": id_param,
                        "tested_value": str(i),
                        "status": resp.status_code
                    })
            except:
                pass
                
        return findings
        
    def check_information_disclosure(self, url: str) -> Dict:
        findings = {
            "debug_mode": False,
            "stack_trace": False,
            "sensitive_files": [],
            "version_info": False
        }
        
        sensitive_paths = [
            "/.git/config",
            "/.env",
            "/phpinfo.php",
            "/server-status",
            "/actuator/env",
            "/debug",
            "/heapdump"
        ]
        
        try:
            for path in sensitive_paths:
                full_url = urljoin(url, path)
                resp = self.session.get(full_url, timeout=5, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 0:
                    findings["sensitive_files"].append({
                        "path": path,
                        "status": resp.status_code
                    })
        except:
            pass
            
        return findings
        
    def scan_target(self, url: str) -> Dict:
        results = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "authentication": self.check_authentication(url),
            "session": self.check_session_management(url),
            "csrf": self.check_csrf(url),
            "xss": self.check_xss(url),
            "sqli": self.check_sqli(url),
            "ssrf": self.check_ssrf(url),
            "idor": self.check_idor(url),
            "info_disclosure": self.check_information_disclosure(url)
        }
        
        self.findings = results
        return results


webapp_agent = WebAppAgent()