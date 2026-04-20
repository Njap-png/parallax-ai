#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.master_controller import master_controller
from core.auto_decoder import auto_decoder
from tools.exploitdb import exploit_db
from tools.ctf import ctf_engine

def initialize_system():
    print("[*] ParallaxForge System Initialization")
    print("=" * 50)
    
    print("\n[*] Initializing exploit database...")
    exploit_db.initialize()
    print("[+] Exploit database initialized with OWASP, MITRE ATT&CK, CWE")
    
    print("\n[*] Seeding CTF challenges...")
    ctf_engine.seed_challenges()
    print("[+] CTF challenges seeded")
    
    print("\n[*] Learning core security concepts...")
    concepts = [
        ("SQL Injection", "SQL injection allows attackers to execute arbitrary SQL queries through unsanitized user input. Mitigations: parameterized queries, input validation, least privilege."),
        ("XSS", "Cross-site scripting injects malicious scripts into web pages. Types: reflected, stored, DOM. Mitigations: output encoding, CSP, HttpOnly cookies."),
        ("CSRF", "Cross-site request forgery tricks users into submitting unintended requests. Mitigations: CSRF tokens, SameSite cookies, referer checks."),
        ("IDOR", "Insecure direct object references allow unauthorized access to resources. Mitigations: authorization checks, indirect object mapping."),
        ("SSRF", "Server-side request forgery makes the server attack other servers. Mitigations: URL validation, disable HTTP redirects."),
        ("XXE", "XML external entity injection parses malicious XML. Mitigations: disable entity parsing, DTD restrictions."),
        ("RCE", "Remote code execution allows arbitrary code on the system. Mitigations: input validation, sandboxing, least privilege."),
        ("Path Traversal", "Directory traversal accesses files outside web root. Mitigations: path validation, chroot, least privilege.")
    ]
    
    for topic, content in concepts:
        master_controller.learn(topic, content, "initialization")
        
    print(f"[+] Learned {len(concepts)} security concepts")
    
    print("\n[*] Learning vulnerability types...")
    vuln_types = [
        ("OWASP Top 10 2021", "A01:Broken Access Control, A02:Cryptographic Failures, A03:Injection, A04:Insecure Design, A05:Security Misconfiguration, A06:Vulnerable Components, A07:Authentication Failures, A08:Software/Data Integrity Failures, A09:Security Logging Failures, A10:Server-Side Request Forgery"),
        ("Authentication Bypass", "Methods: credential stuffing, default passwords, session fixation, JWT weak signing, JWT algorithm confusion"),
        ("File Upload Vulnerabilities", "Exploits: malware upload, path traversal in filename, double extensions, MIME type spoofing, null byte injection"),
        ("Deserialization Attacks", "Java deserialization, Python pickle, PHP unserialize, YAML deserialization - can lead to RCE"),
        ("Race Conditions", "TOCTOU (time-of-check-time-of-use), can lead to privilege escalation or data corruption")
    ]
    
    for topic, content in vuln_types:
        master_controller.learn(topic, content, "initialization")
        
    print(f"[+] Learned {len(vuln_types)} vulnerability types")
    
    print("\n[*] Learning remediation patterns...")
    remediations = [
        ("SQLi Fix", "Use parameterized queries (prepared statements): cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
        ("XSS Fix", "Use context-aware output encoding: escape HTML, JavaScript, URL, CSS. Use CSP header."),
        ("Auth Fix", "Use strong password hashing (bcrypt, argon2), implement MFA, rate limiting, account lockout."),
        ("Upload Fix", "Verify file type (magic bytes), rename files, store outside web root, random filenames."),
        ("RCE Fix", "Never use user input in eval/exec/popen, use sandboxing, least privilege."),
        ("Path Traversal Fix", "Use os.path.realpath(), validate path starts with intended directory, chroot jail.")
    ]
    
    for topic, content in remediations:
        master_controller.learn(topic, content, "initialization")
        
    print(f"[+] Learned {len(remediations)} remediation patterns")
    
    status = master_controller.status()
    print("\n" + "=" * 50)
    print("[+] System initialized successfully!")
    print(f"    Mode: {status['mode']}")
    print(f"    Knowledge: {status['knowledge']} concepts")
    print(f"    Techniques: {status['techniques']}")
    print(f"    CTF Challenges: {len(ctf_engine.get_challenges())}")
    print("=" * 50)
    
    return {
        "initialized": True,
        "mode": status["mode"]
    }

if __name__ == "__main__":
    initialize_system()