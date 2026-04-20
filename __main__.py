#!/usr/bin/env python3
import sys
import json
import argparse
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.ai_model import ParallaxAI
from web_nav.web_navigator import WebNavigator
from scanners.vuln_scanner import VulnerabilityScanner
from malware.malware_analyzer import MalwareAnalyzer
from decoders.decoder import Decoder
from autonomous.self_learning import AutonomousLearning

class ParallaxCLI:
    def __init__(self):
        self.ai = ParallaxAI()
        self.navigator = WebNavigator()
        self.scanner = VulnerabilityScanner(self.navigator)
        self.malware = MalwareAnalyzer()
        self.decoder = Decoder()
        self.autonomous = AutonomousLearning()
        
    def cmd_scan(self, args):
        print(f"[+] Scanning {args.target}...")
        findings = self.scanner.full_scan(args.target)
        print(json.dumps(findings, indent=2))
        return findings
        
    def cmd_navigate(self, args):
        print(f"[+] Analyzing {args.target}...")
        result = self.navigator.analyze_target(args.target)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_decode(self, args):
        if args.decode_base64:
            result = self.decoder.decode_base64(args.data)
        elif args.decode_hex:
            result = self.decoder.decode_hex(args.data)
        elif args.decode_url:
            result = self.decoder.decode_url(args.data)
        elif args.decode_html:
            result = self.decoder.decode_html(args.data)
        else:
            result = self.decoder.decode_multibase(args.data)
        print(result)
        return result
        
    def cmd_malware(self, args):
        if args.analyze_file:
            result = self.malware.analyze_pe(args.analyze_file)
        else:
            print("[!] No file specified")
            return None
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_learn(self, args):
        print(f"[+] Learning from {args.source}...")
        result = self.autonomous.learn_from_web(args.source)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_status(self, args):
        status = self.ai.self_update()
        print(json.dumps(status, indent=2))
        return status
        
    def cmd_scope(self, args):
        if args.add:
            self.ai.add_scope(args.add)
            print(f"[+] Added scope: {args.add}")
        elif args.remove:
            self.ai.remove_scope(args.remove)
            print(f"[-] Removed scope: {args.remove}")
        else:
            print("Scopes:", self.ai.scopes)
        return None
        
    def cmd_tools(self, args):
        if args.add:
            parts = args.add.split(',')
            if len(parts) >= 3:
                self.ai.register_tool(parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else "")
                print(f"[+] Registered tool: {parts[1]}")
        else:
            print(json.dumps(self.ai.tools, indent=2))
        return None

def main():
    parser = argparse.ArgumentParser(prog='parallax-ai', description='Autonomous Bug Bounty & Pentest AI')
    subparsers = parser.add_subparsers(dest='command')
    
    scan_parser = subparsers.add_parser('scan', help='Scan target for vulnerabilities')
    scan_parser.add_argument('target', help='Target URL')
    scan_parser.set_defaults(func='scan')
    
    navigate_parser = subparsers.add_parser('navigate', help='Navigate/analyze target')
    navigate_parser.add_argument('target', help='Target URL or domain')
    navigate_parser.set_defaults(func='navigate')
    
    decode_parser = subparsers.add_parser('decode', help='Decode encoded data')
    decode_parser.add_argument('data', help='Data to decode')
    decode_parser.add_argument('--base64', dest='decode_base64', action='store_true')
    decode_parser.add_argument('--hex', dest='decode_hex', action='store_true')
    decode_parser.add_argument('--url', dest='decode_url', action='store_true')
    decode_parser.add_argument('--html', dest='decode_html', action='store_true')
    decode_parser.set_defaults(func='decode')
    
    malware_parser = subparsers.add_parser('malware', help='Analyze malware')
    malware_parser.add_argument('-f', '--file', dest='analyze_file')
    malware_parser.set_defaults(func='malware')
    
    learn_parser = subparsers.add_parser('learn', help='Learn from web source')
    learn_parser.add_argument('source', help='URL to learn from')
    learn_parser.set_defaults(func='learn')
    
    status_parser = subparsers.add_parser('status', help='Show AI status')
    status_parser.set_defaults(func='status')
    
    scope_parser = subparsers.add_parser('scope', help='Manage scopes')
    scope_parser.add_argument('--add', help='Add scope')
    scope_parser.add_argument('--remove', help='Remove scope')
    scope_parser.set_defaults(func='scope')
    
    tools_parser = subparsers.add_parser('tools', help='Manage tools')
    tools_parser.add_argument('--add', help='Add tool type,name,impl,capabilities')
    tools_parser.set_defaults(func='tools')
    
    args = parser.parse_args()
    
    cli = ParallaxCLI()
    func_name = args.func if hasattr(args, 'func') else 'status'
    
    if func_name == 'scan':
        cli.cmd_scan(args)
    elif func_name == 'navigate':
        cli.cmd_navigate(args)
    elif func_name == 'decode':
        cli.cmd_decode(args)
    elif func_name == 'malware':
        cli.cmd_malware(args)
    elif func_name == 'learn':
        cli.cmd_learn(args)
    elif func_name == 'status':
        cli.cmd_status(args)
    elif func_name == 'scope':
        cli.cmd_scope(args)
    elif func_name == 'tools':
        cli.cmd_tools(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()