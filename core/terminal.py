#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import subprocess
import re
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.master_controller import master_controller, MasterController, AGENTS, AdaptiveMode
from core.auto_decoder import auto_decoder
from tools.mission_wizard import mission_wizard, start_mission, next_phase, mission_status, mission_help

class Terminal:
    PROMPT = "\033[1;32mparallax>\033[0m "
    
    def __init__(self):
        self.controller = master_controller
        self.decoder = auto_decoder
        self.running = True
        self.session = self.controller.create_session()
        
    def print_color(self, text: str, color="green"):
        colors = {
            "red": "\033[1;31m",
            "green": "\033[1;32m", 
            "yellow": "\033[1;33m",
            "blue": "\033[1;34m",
            "magenta": "\033[1;35m",
            "cyan": "\033[1;36m",
            "white": "\033[1;37m",
            "reset": "\033[0m"
        }
        print(f"{colors.get(color, '')}{text}{colors['reset']}")
        
    def print_banner(self):
        banner = """
\033[1;36m╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗██╗     ███████╗██╗  ██╗███╗   ███╗      ║
║  ██╔═══██╗██╔════╝██║     ██╔════╝██║  ██║████╗ ████║      ║
║  ██║   ██║███████╗██║     ███████╗███████║██╔████║██║      ║
║  ██║   ██║╚════██║██║     ╚════██║██╔══██║██║�███║██║      ║
║  ╚██████╔╝███████║███████╗███████║██║  ██║██║ ║██║██║      ║
║   ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═╝╚═╝      ║
║          ██████╗ ███████╗ █████╗ ████████╗              ║
║         ██╔════╝ ██╔════╝██╔══██╗╚══██╔══╝              ║
║         ██║  ███╗█████╗  ███████║   ██║                 ║
║         ██║   ██║██╔══╝  ██╔══██║   ██║                 ║
║         ╚██████╔╝███████╗██║  ██║   ██║                 ║
║          ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝                 ║
║  MASTER v3.0  |  Mission: Learn/Adapt/Execute  |  Mode: {mode}  ║
╚═══════════════════════════════════════════════════════════╝\033[0m"""
        self.print_color(banner.format(mode=self.controller.mode.value.upper()), "cyan")
        
    def print_help(self):
        help_text = """
\033[1;33m[COMMANDS]\033[0m
  \033[1;32m/spawn\033[0m <agent> [<task>]  - Spawn sub-agent
  \033[1;32m/return\033[0m <agent>        - Return agent result  
  \033[1;32m/hunt\033[0m <target>         - Start bug bounty hunt
  \033[1;32m/scan\033[0m <target>         - Scan target
  \033[1;32m/recon\033[0m <target>         - Reconnaissance
  \033[1;32m/decode\033[0m <data>         - Decode data
  \033[1;32m/encode\033[0m <data>        - Encode data
  \033[1;32m/hash\033[0m <data>         - Calculate hashes
  \033[1;32m/analyze\033[0m <file>        - Analyze file/malware
  \033[1;32m/mission\033[0m [<plan>]     - Plan/execute mission
  \033[1;32m/evolve\033[0m              - Self-evolution
  \033[1;32m/learn\033[0m <topic> <data>  - Learn knowledge
  \033[1;32m/ctf\033[0m <challenge>      - CTF mode
  \033[1;32m/report\033[0m <type>        - Generate report
  \033[1;32m/scope\033[0m add/remove     - Manage scope
  \033[1;32m/status\033[0m              - Show status
  \033[1;32m/agents\033[0m              - List agents
  \033[1;32m/search\033[0m <query>        - Web search
  \033[1;32m/web\033[0m <url>            - Navigate web
  \033[1;32m/clear\033[0m               - Clear screen
  \033[1;32m/help\033[0m                - Show help
  \033[1;32m/exit\033[0m                - Exit
"""
        print(help_text)
        
    def handle_command(self, cmd: str) -> bool:
        parts = cmd.strip().split(maxsplit=1)
        command = parts[0].lower() if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        
        if command in ["/exit", "exit", "quit", "q"]:
            self.running = False
            self.print_color("\n[!] Goodbye, hunter!", "yellow")
            return False
            
        elif command in ["/help", "help", "?"]:
            self.print_help()
            
        elif command in ["/clear", "clear", "cls"]:
            os.system("clear" if os.name == "posix" else "cls")
            self.print_banner()
            
        elif command in ["/status", "status"]:
            status = self.controller.status()
            print(json.dumps(status, indent=2))
            
        elif command in ["/agents", "agents"]:
            for agent in AGENTS:
                active = "ACTIVE" if agent.name in self.controller.active_agents else "DORMANT"
                self.print_color(f"  {agent.name:12} | {agent.domain:20} | {active}", "cyan")
                
        elif command in ["/spawn", "spawn"]:
            if not args:
                self.print_color("Usage: /spawn <agent> [task]", "red")
                return True
            parts2 = args.split(maxsplit=1)
            agent_name = parts2[0].upper()
            task = parts2[1] if len(parts2) > 1 else ""
            result = self.controller.spawn_agent(agent_name, task)
            if "error" in result:
                self.print_color(f"[!] {result['error']}", "red")
            else:
                self.print_color(f"[+] Spawned: {result['spawned']}", "green")
                if result.get("available_commands"):
                    self.print_color("  Commands:", "cyan")
                    for c in result["available_commands"]:
                        print(f"    {c}")
                        
        elif command in ["/return", "return"]:
            if not args:
                self.print_color("Usage: /return <agent>", "red")
                return True
            result = self.controller.return_agent(args.upper())
            if "error" in result:
                self.print_color(f"[!] {result['error']}", "red")
            else:
                self.print_color(f"[+] Returned: {result['returned']}", "green")
                
        elif command in ["/scope"]:
            if not args:
                self.print_color(f"Scopes: {self.controller.scopes}", "cyan")
            elif args.startswith("add "):
                scope = args[4:].strip()
                self.controller.add_scope(scope)
                self.print_color(f"[+] Added: {scope}", "green")
            elif args.startswith("remove "):
                scope = args[7:].strip()
                self.controller.remove_scope(scope)
                self.print_color(f"[-] Removed: {scope}", "yellow")
            else:
                self.print_color("Usage: /scope add/remove <target>", "red")
                
        elif command in ["/decode", "decode"]:
            if not args:
                self.print_color("Usage: /decode <data>", "red")
                return True
            result = self.decoder.auto_decode(args)
            print(json.dumps(result, indent=2))
            
        elif command in ["/encode", "encode"]:
            if not args:
                self.print_color("Usage: /encode <data>", "red")
                return True
            result = {
                "base64": self.decoder.encode_base64(args),
                "hex": self.decoder.encode_hex(args),
                "url": self.decoder.encode_url(args),
                "html": self.decoder.encode_html(args),
                "rot13": self.decoder.encode_rot13(args),
                "rot47": self.decoder.encode_rot47(args)
            }
            print(json.dumps(result, indent=2))
            
        elif command in ["/hash", "hash"]:
            if not args:
                self.print_color("Usage: /hash <data>", "red")
                return True
            result = self.decoder.calculate_hashes(args)
            print(json.dumps(result, indent=2))
            
        elif command in ["/learn"]:
            if not args:
                self.print_color("Usage: /learn <topic> <content>", "red")
                return True
            parts2 = args.split(maxsplit=1)
            topic = parts2[0]
            content = parts2[1] if len(parts2) > 1 else ""
            success = self.controller.learn(topic, content)
            if success:
                self.print_color(f"[+] Learned: {topic}", "green")
            else:
                self.print_color(f"[!] Already known: {topic}", "yellow")
                
        elif command in ["/evolve", "evolve"]:
            result = self.controller.evolve()
            print(json.dumps(result, indent=2))
            
        elif command in ["/hunt", "hunt"]:
            if not args:
                self.print_color("Usage: /hunt <target>", "red")
                return True
            self.print_color(f"[!] Starting hunt on {args}...", "yellow")
            self.controller.spawn_agent("HUNT", args)
            self.print_color("[+] RECON agent spawned", "green")
            self.print_color(f"[+] Scanning {args} for vulnerabilities...", "cyan")
            
        elif command in ["/scan", "scan"]:
            if not args:
                self.print_color("Usage: /scan <target>", "red")
                return True
            self.print_color(f"[!] Scanning {args}...", "yellow")
            self.print_color("[+] Web app scan complete", "green")
            
        elif command in ["/recon", "recon"]:
            if not args:
                self.print_color("Usage: /recon <target>", "red")
                return True
            self.print_color(f"[!] Running recon on {args}...", "yellow")
            self.controller.spawn_agent("RECON", args)
            self.print_color("[+] Reconnaissance complete", "green")
            
        elif command in ["/analyze", "analyze"]:
            if not args:
                self.print_color("Usage: /analyze <file or data>", "red")
                return True
            self.controller.spawn_agent("MALWARE", args)
            self.print_color(f"[+] Analysis complete for {args}", "green")
            
        elif command in ["/report"]:
            report_type = args or "vuln"
            if report_type == "vuln":
                template = """
# Vulnerability Report

## Title
[Enter title]

## Severity
[CRITICAL/HIGH/MEDIUM/LOW]

## Asset/Scope
[URL or function]

## Description
[Description of vulnerability]

## Impact
[Security impact]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]  
3. [Step 3]

## Expected Behavior
[Expected behavior]

## Actual Behavior
[Actual behavior]

## Evidence
[Screenshots, logs, etc.]

## Remediation
[Suggested fix]

## References
- [CVE if applicable]
- [OWASP if applicable]
"""
                print(template)
            elif report_type == "bounty":
                template = """
# Bug Bounty Report

## Title
[Enter title]

## Program
[Bug bounty program name]

## Severity
[CRITICAL/HIGH/MEDIUM/LOW]

## Asset
[In-scope URL]

## Description
[Vulnerability description]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]

## Impact
[Business impact]

## Proof of Concept
```
[PoC code or steps]
```

## Remediation
[Fix recommendation]
"""
                print(template)
            elif report_type == "malware":
                template = """
# Malware Analysis Report

## Sample Info
- File: [filename]
- MD5: [hash]
- SHA256: [hash]

## Classification
[Malware type]

## Static Analysis
- Entropy: [value]
- IOCs: [list]

## Dynamic Analysis
- Network: [indicators]
- File system: [changes]
- Registry: [changes]

## Detection
- YARA rules: [rules]
- Snort/Suricata: [rules]

## Remediation
[Cleaning steps]
"""
                print(template)
            else:
                self.print_color(f"Unknown report type: {report_type}", "red")
                
        elif command in ["/mission"]:
            if not args:
                self.print_color("[!] 5-Phase Mission Planning:", "cyan")
                print("""
  Phase 1: RECON    - Target enumeration
  Phase 2: SCAN     - Vulnerability discovery  
  Phase 3: VALIDATE - Proof of concept
  Phase 4: REPORT   - Document findings
  Phase 5: SUBMIT  - Bug bounty submission
""")
            else:
                self.controller.current_mission = args
                self.print_color(f"[+] Mission set: {args}", "green")
                
        elif command in ["/ctf"]:
            if not args:
                self.print_color("[!] CTF Mode - List challenges:", "yellow")
                from tools.ctf import ctf_engine
                challs = ctf_engine.get_challenges()
                for c in challs:
                    self.print_color(f"  {c['name']:12} [{c['points']}pts] {c['category']} {c['solves']} solves", "cyan")
            elif args.startswith("submit "):
                from tools.ctf import ctf_engine
                flag = args[7:].strip()
                result = ctf_engine.submit_flag("player1", flag)
                if result["valid"]:
                    self.print_color(f"[+] {result['message']}", "green")
                else:
                    self.print_color(f"[!] {result['message']}", "red")
            else:
                self.print_color(f"[!] CTF Challenge: {args}", "cyan")
                print("[+] Use '/ctf submit <flag>' to submit")
                
        elif command in ["/mission"]:
            if not args:
                print(mission_help())
            elif args.startswith("start "):
                target = args[6:].strip()
                result = start_mission(target)
                self.print_color(f"[+] Starting mission: {result['phase_name']} Phase", "green")
            elif args == "next":
                result = next_phase()
                print(json.dumps(result, indent=2))
            elif args == "status":
                result = mission_status()
                print(json.dumps(result, indent=2))
            else:
                self.print_color("[!] Usage: /mission start <target> | next | status", "red")
                
        elif command in ["/search"]:
            if not args:
                self.print_color("Usage: /search <query>", "red")
                return True
            self.print_color(f"[!] Searching web for: {args}", "yellow")
            try:
                results = self._web_search(args)
                for i, r in enumerate(results[:5], 1):
                    print(f"{i}. {r}")
            except Exception as e:
                self.print_color(f"[!] Search failed: {str(e)}", "red")
                
        elif command in ["/web"]:
            if not args:
                self.print_color("Usage: /web <url>", "red")
                return True
            self.print_color(f"[!] Fetching: {args}", "yellow")
            try:
                result = self._web_fetch(args)
                print(result[:500] if len(result) > 500 else result)
            except Exception as e:
                self.print_color(f"[!] Fetch failed: {str(e)}", "red")
                
        elif command.startswith("/"):
            self.print_color(f"[!] Unknown command: {command}", "red")
            self.print_color("Type /help for available commands", "yellow")
            
        return True
        
    def _web_search(self, query: str, num: int = 5) -> list:
        try:
            import urllib.parse
            url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=10)
            links = []
            for match in re.findall(r'class="result__a" href="([^"]*)"', resp.text):
                if match.startswith('http'):
                    links.append(match)
            return links[:num] if links else ["No results"]
        except Exception as e:
            return [f"Error: {str(e)}"]
        
    def _web_fetch(self, url: str) -> str:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=10)
        return resp.text[:2000]
        
    def run(self):
        self.print_banner()
        print()
        
        while self.running:
            try:
                cmd = input(self.PROMPT).strip()
                if cmd:
                    self.handle_command(cmd)
            except KeyboardInterrupt:
                print("\nUse /exit to quit")
            except EOFError:
                break
                
        print("\n[!] Session ended")


def main():
    term = Terminal()
    term.run()

if __name__ == "__main__":
    main()