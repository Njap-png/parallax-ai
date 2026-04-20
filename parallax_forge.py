#!/usr/bin/env python3
import sys
import json
import argparse
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.parallax_forge import ParallaxForge, SecurityFinding, TaskType
from agents.recon_agent import ReconAgent
from agents.webapp_agent import WebAppAgent
from agents.malware_agent import MalwareAnalysisAgent
from agents.detection_agent import DetectionAgent
from agents.reporting_agent import ReportingAgent
from agents.decoder_agent import DecoderAgent

class ParallaxForgeCLI:
    def __init__(self):
        self.ai = ParallaxForge()
        self.recon = ReconAgent()
        self.webapp = WebAppAgent()
        self.malware = MalwareAnalysisAgent()
        self.detection = DetectionAgent()
        self.reporting = ReportingAgent()
        self.decoder = DecoderAgent()
        
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
            print("Current scopes:", self.ai.scopes)
        return None
        
    def cmd_recon(self, args):
        authorized, msg = self.ai.verify_authorization(args.target, "read")
        if not authorized:
            print(f"[-] Authorization failed: {msg}")
            return None
            
        print(f"[+] Running recon on {args.target}...")
        result = self.recon.analyze_target(args.target)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_scan(self, args):
        authorized, msg = self.ai.verify_authorization(args.target, "scan")
        if not authorized:
            print(f"[-] Authorization failed: {msg}")
            return None
            
        print(f"[+] Scanning {args.target}...")
        result = self.webapp.scan_target(args.target)
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
        elif args.decode_rot13:
            result = self.decoder.decode_rot13(args.data)
        elif args.auto:
            result = self.decoder.auto_decode(args.data)
        else:
            result = self.decoder.decode_multibase(args.data)
            
        print(result if result else "[-] Failed to decode")
        return result
        
    def cmd_hash(self, args):
        result = self.decoder.calculate_hashes(args.data)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_malware(self, args):
        authorized, msg = self.ai.verify_authorization(args.file, "analyze")
        if not authorized:
            print(f"[-] Authorization failed: {msg}")
            return None
            
        if not args.file or not Path(args.file).exists():
            print("[-] File not found")
            return None
            
        print(f"[+] Analyzing malware: {args.file}")
        result = self.malware.analyze_sample(args.file)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_detect(self, args):
        if args.malware:
            result = self.malware.analyze_sample(args.malware)
            rules = self.detection.create_detection_for_malware(result)
        else:
            rules = {"error": "No sample provided"}
            
        print(json.dumps(rules, indent=2))
        return rules
        
    def cmd_report(self, args):
        if args.list:
            findings = self.ai.get_findings()
            report = self.reporting.create_report_from_findings(findings)
            print(report)
        else:
            print("Use --list to view all findings")
        return None
        
    def cmd_session(self, args):
        if args.create:
            session_id = self.ai.create_session(args.create, args.auth or "authorized_safe")
            print(f"[+] Created session: {session_id}")
            return session_id
        else:
            print(f"Current session: {self.ai.current_session}")
        return None
        
    def cmd_agents(self, args):
        if args.spawn:
            task_type = TaskType(args.spawn)
            agent_info = self.ai.spawn_agent(task_type, args.task or "general task")
            print(json.dumps(agent_info, indent=2))
            return agent_info
        else:
            print("Available agents: recon, webapp, malware, detection, reporting, decoder")
        return None
        
    def cmd_safe(self, args):
        result = self.ai.validate_safe_operation(args.action, args.target)
        print(json.dumps(result, indent=2))
        return result
        
    def cmd_audit(self, args):
        log = self.ai.get_audit_log(args.limit or 20)
        print(json.dumps(log, indent=2))
        return log


def main():
    parser = argparse.ArgumentParser(
        prog='parallax-forge',
        description='ParallaxForge - Cybersecurity AI Assistant'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    status_parser = subparsers.add_parser('status', help='Show AI status')
    status_parser.set_defaults(func='status')
    
    scope_parser = subparsers.add_parser('scope', help='Manage scopes')
    scope_parser.add_argument('--add', help='Add scope')
    scope_parser.add_argument('--remove', help='Remove scope')
    scope_parser.set_defaults(func='scope')
    
    recon_parser = subparsers.add_parser('recon', help='Run reconnaissance')
    recon_parser.add_argument('target', help='Target URL/domain')
    recon_parser.set_defaults(func='recon')
    
    scan_parser = subparsers.add_parser('scan', help='Scan web application')
    scan_parser.add_argument('target', help='Target URL')
    scan_parser.set_defaults(func='scan')
    
    decode_parser = subparsers.add_parser('decode', help='Decode data')
    decode_parser.add_argument('data', help='Data to decode')
    decode_parser.add_argument('--base64', dest='decode_base64', action='store_true')
    decode_parser.add_argument('--hex', dest='decode_hex', action='store_true')
    decode_parser.add_argument('--url', dest='decode_url', action='store_true')
    decode_parser.add_argument('--html', dest='decode_html', action='store_true')
    decode_parser.add_argument('--rot13', dest='decode_rot13', action='store_true')
    decode_parser.add_argument('--auto', dest='auto', action='store_true')
    decode_parser.set_defaults(func='decode')
    
    hash_parser = subparsers.add_parser('hash', help='Calculate hashes')
    hash_parser.add_argument('data', help='Data to hash')
    hash_parser.set_defaults(func='hash')
    
    malware_parser = subparsers.add_parser('malware', help='Analyze malware')
    malware_parser.add_argument('-f', '--file', required=True, help='Malware sample path')
    malware_parser.set_defaults(func='malware')
    
    detect_parser = subparsers.add_parser('detect', help='Generate detection rules')
    detect_parser.add_argument('--malware', help='Malware sample for detection')
    detect_parser.set_defaults(func='detect')
    
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--list', action='store_true', help='List findings')
    report_parser.set_defaults(func='report')
    
    session_parser = subparsers.add_parser('session', help='Manage sessions')
    session_parser.add_argument('--create', help='Create session with scope')
    session_parser.add_argument('--auth', help='Authorization level')
    session_parser.set_defaults(func='session')
    
    agents_parser = subparsers.add_parser('agents', help='Spawn agents')
    agents_parser.add_argument('--spawn', help='Agent type to spawn')
    agents_parser.add_argument('--task', help='Task description')
    agents_parser.set_defaults(func='agents')
    
    safe_parser = subparsers.add_parser('safe', help='Check safe operation')
    safe_parser.add_argument('--action', required=True, help='Action to check')
    safe_parser.add_argument('--target', required=True, help='Target')
    safe_parser.set_defaults(func='safe')
    
    audit_parser = subparsers.add_parser('audit', help='View audit log')
    audit_parser.add_argument('--limit', type=int, help='Limit entries')
    audit_parser.set_defaults(func='audit')
    
    args = parser.parse_args()
    
    cli = ParallaxForgeCLI()
    func_name = args.func if hasattr(args, 'func') else 'status'
    
    func_map = {
        'status': cli.cmd_status,
        'scope': cli.cmd_scope,
        'recon': cli.cmd_recon,
        'scan': cli.cmd_scan,
        'decode': cli.cmd_decode,
        'hash': cli.cmd_hash,
        'malware': cli.cmd_malware,
        'detect': cli.cmd_detect,
        'report': cli.cmd_report,
        'session': cli.cmd_session,
        'agents': cli.cmd_agents,
        'safe': cli.cmd_safe,
        'audit': cli.cmd_audit
    }
    
    if func_name in func_map:
        func_map[func_name](args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()