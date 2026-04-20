#!/usr/bin/env python3
import requests
import socket
import whois
import re
import json
import ssl
import OpenSSL
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import html

class ReconAgent:
    """Reconnaissance Agent - Gathers public information, scope, attack surface, documentation"""
    
    NAME = "Recon Agent"
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
            "whois": None,
            "dns": None,
            "headers": None,
            "technologies": [],
            "subdomains": [],
            "ports": [],
            "ssl_info": None,
            "endpoints": [],
            "emails": [],
            "social": []
        }
        return results
        
    def get_whois(self, domain: str) -> Dict:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails
            }
        except Exception as e:
            return {"error": str(e)}
            
    def resolve_dns(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except:
            return None
            
    def get_headers(self, url: str) -> Dict:
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            return dict(resp.headers)
        except Exception as e:
            return {"error": str(e)}
            
    def detect_technologies(self, headers: Dict, html_content: str) -> List[str]:
        tech = []
        
        server = headers.get('Server', '')
        if server:
            if 'nginx' in server.lower(): tech.append("Nginx")
            if 'apache' in server.lower(): tech.append("Apache")
            if 'iis' in server.lower(): tech.append("IIS")
            
        if 'cloudflare' in str(headers).lower():
            tech.append("Cloudflare")
            
        if 'wp-content' in html_content or 'wp-includes' in html_content:
            tech.append("WordPress")
            
        if 'React' in html_content:
            tech.append("React")
        if 'Vue' in html_content:
            tech.append("Vue.js")
        if '__NEXT' in html_content:
            tech.append("Next.js")
        if 'angular' in html_content.lower():
            tech.append("Angular")
        if 'Backbone' in html_content:
            tech.append("Backbone.js")
            
        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            tech.append(f"Powered-By: {x_powered}")
            
        return tech
        
    def find_subdomains(self, domain: str) -> List[Dict]:
        common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 
                    'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 
                    'autodiscover', 'autoconfig', 'm', 'imap', 'test', 
                    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 
                    'news', 'vpn', 'shop', 'git', 'staging', 'store', 
                    'app', 'api', 'cdn', 'static', 'assets', 'docs']
        found = []
        
        for sub in common_subs:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                found.append({"subdomain": hostname, "ip": ip})
            except:
                pass
                
        return found
        
    def scan_ports(self, host: str, ports: List[int] = None) -> List[int]:
        if ports is None:
            ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
        return open_ports
        
    def get_ssl_info(self, hostname: str, port: int = 443) -> Dict:
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, port))
                cert = sock.getpeercert()
                return {
                    "subject": dict(cert.get('subject', [])),
                    "issuer": dict(cert.get('issuer', [])),
                    "version": cert.get('version'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter')
                }
        except Exception as e:
            return {"error": str(e)}
            
    def extract_endpoints(self, html: str, base_url: str) -> List[str]:
        endpoints = set()
        
        href_pattern = r'href=["\']([^"\']+)["\']'
        src_pattern = r'src=["\']([^"\']+)["\']'
        action_pattern = r'action=["\']([^"\']+)["\']'
        
        for pattern in [href_pattern, src_pattern, action_pattern]:
            matches = re.findall(pattern, html)
            for match in matches:
                if match.startswith('/') or match.startswith(base_url):
                    endpoints.add(match)
                    
        return list(endpoints)
        
    def extract_emails(self, content: str) -> List[str]:
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, content)))
        
    def analyze_target(self, target: str) -> Dict:
        parsed = urlparse(target if '://' in target else f'https://{target}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        results = {
            "target": target,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "whois": self.get_whois(domain),
            "dns": self.resolve_dns(domain),
            "headers": None,
            "technologies": [],
            "subdomains": [],
            "ports": [],
            "ssl_info": None,
            "endpoints": [],
            "emails": []
        }
        
        if parsed.scheme:
            results["headers"] = self.get_headers(target)
            
            if results["headers"]:
                try:
                    html_content = self.session.get(target, timeout=self.timeout, verify=False).text
                    results["technologies"] = self.detect_technologies(results["headers"], html_content)
                    results["endpoints"] = self.extract_endpoints(html_content, target)
                    results["emails"] = self.extract_emails(html_content)
                except:
                    pass
                    
        ip = results.get("dns") or self.resolve_dns(domain)
        if ip:
            results["ports"] = self.scan_ports(ip)
            
        if domain:
            try:
                results["ssl_info"] = self.get_ssl_info(domain)
            except:
                pass
                
        results["subdomains"] = self.find_subdomains(domain)
        return results


recon_agent = ReconAgent()