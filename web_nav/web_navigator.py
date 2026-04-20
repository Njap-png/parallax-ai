import requests
import socket
import whois
import subprocess
import re
from urllib.parse import urlparse
import ssl
import OpenSSL
from datetime import datetime

class WebNavigator:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def analyze_target(self, target):
        results = {
            "target": target,
            "whois": None,
            "dns": None,
            "headers": None,
            "tech_stack": [],
            "subdomains": [],
            "ports": [],
            "ssl_info": None
        }
        return results
        
    def get_whois(self, domain):
        try:
            w = whois.whois(domain)
            return {
                " registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except:
            return None
            
    def resolve_dns(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except:
            return None
            
    def get_headers(self, url):
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            return dict(resp.headers)
        except Exception as e:
            return {"error": str(e)}
            
    def detect_technologies(self, headers, html):
        tech = []
        server = headers.get('Server', '')
        if 'nginx' in server.lower():
            tech.append("Nginx")
        if 'apache' in server.lower():
            tech.append("Apache")
        if 'cloudflare' in str(headers).lower():
            tech.append("Cloudflare")
        if 'wp-content' in html:
            tech.append("WordPress")
        if 'React' in html:
            tech.append("React")
        if 'Vue' in html:
            tech.append("Vue.js")
        if '__NEXT' in html:
            tech.append("Next.js")
        return tech
        
    def check_subdomain_enumeration(self, domain):
        common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 
                      'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
                      'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
                      'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns1',
                      'mail2', 'new', 'mysql', 'old', 'lists', 'support',
                      'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'svn',
                      'git', 'staging', 'store', 'app']
        found = []
        for sub in common_subs:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                found.append({sub: ip})
            except:
                pass
        return found
        
    def scan_ports(self, host, ports=[80, 443, 22, 21, 25, 53, 8080, 8443]):
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
        
    def get_ssl_info(self, hostname, port=443):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, port))
                cert = sock.getpeercert()
                return cert
        except:
            return None
            
    def fetch_page(self, url):
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            return {
                "status": resp.status_code,
                "html": resp.text,
                "headers": dict(resp.headers)
            }
        except Exception as e:
            return {"error": str(e)}
            
    def submit_form(self, url, data, method='POST'):
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            if method == 'POST':
                resp = self.session.post(url, data=data, timeout=self.timeout, verify=False)
            else:
                resp = self.session.get(url, params=data, timeout=self.timeout, verify=False)
            return {
                "status": resp.status_code,
                "response": resp.text
            }
        except Exception as e:
            return {"error": str(e)}

navigator = WebNavigator()