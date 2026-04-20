#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import hashlib
import re
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Any
from threading import Thread
import socketserver

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.master_controller import master_controller, AGENTS
from core.auto_decoder import auto_decoder

class APIHandler(BaseHTTPRequestHandler):
    version = "ParallaxForge API v3.0"
    
    def log_message(self, format, *args):
        print(f"[API] {args[0]}")
        
    def send_json(self, data: Dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
        
    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        
        if path == "/status":
            self.send_json(master_controller.status())
            
        elif path == "/agents":
            self.send_json({
                "active": list(master_controller.active_agents.keys()),
                "available": [a.name for a in AGENTS]
            })
            
        elif path == "/decode":
            data = query.get("data", [None])[0]
            if data:
                result = auto_decoder.auto_decode(data)
                self.send_json(result)
            else:
                self.send_json({"error": "Missing data parameter"}, 400)
                
        elif path == "/hash":
            data = query.get("data", [None])[0]
            if data:
                result = auto_decoder.calculate_hashes(data)
                self.send_json(result)
            else:
                self.send_json({"error": "Missing data parameter"}, 400)
                
        elif path == "/findings":
            domain = query.get("domain", [None])[0]
            findings = master_controller.get_findings(domain)
            self.send_json({"findings": findings, "count": len(findings)})
            
        elif path == "/scopes":
            self.send_json({"scopes": master_controller.scopes})
            
        elif path == "/mission":
            self.send_json({
                "current": master_controller.current_mission,
                "history": master_controller.history[-10:]
            })
            
        elif path == "/evolve":
            result = master_controller.evolve()
            self.send_json(result)
            
        elif path == "/scan":
            target = query.get("target", [None])[0]
            if target:
                self.send_json({"target": target, "status": "scanning"})
            else:
                self.send_json({"error": "Missing target parameter"}, 400)
                
        else:
            self.send_json({"error": "Not found", "path": path}, 404)
            
    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
            
        if path == "/spawn":
            agent = data.get("agent", "").upper()
            task = data.get("task", "")
            
            if not agent:
                self.send_json({"error": "Missing agent parameter"}, 400)
                return
                
            result = master_controller.spawn_agent(agent, task)
            self.send_json(result)
            
        elif path == "/return":
            agent = data.get("agent", "").upper()
            
            if not agent:
                self.send_json({"error": "Missing agent parameter"}, 400)
                return
                
            result = master_controller.return_agent(agent)
            self.send_json(result)
            
        elif path == "/scope/add":
            scope = data.get("scope", "")
            if scope:
                master_controller.add_scope(scope)
                self.send_json({"added": scope})
            else:
                self.send_json({"error": "Missing scope parameter"}, 400)
                
        elif path == "/scope/remove":
            scope = data.get("scope", "")
            if scope:
                master_controller.remove_scope(scope)
                self.send_json({"removed": scope})
            else:
                self.send_json({"error": "Missing scope parameter"}, 400)
                
        elif path == "/learn":
            topic = data.get("topic", "")
            content = data.get("content", "")
            source = data.get("source", "api")
            
            if topic and content:
                master_controller.learn(topic, content, source)
                self.send_json({"learned": topic})
            else:
                self.send_json({"error": "Missing topic or content"}, 400)
                
        elif path == "/decode":
            encoded = data.get("encoded", "")
            encoding = data.get("encoding", "auto")
            
            if not encoded:
                self.send_json({"error": "Missing encoded parameter"}, 400)
                return
                
            if encoding == "auto":
                result = auto_decoder.auto_decode(encoded)
            else:
                result = getattr(auto_decoder, f'decode_{encoding}', lambda x: None)(encoded)
                result = {"decoded": result}
                
            self.send_json(result)
                
        elif path == "/encode":
            plaintext = data.get("plaintext", "")
            encoding = data.get("encoding", "base64")
            
            if not plaintext:
                self.send_json({"error": "Missing plaintext parameter"}, 400)
                return
                
            result = getattr(auto_decoder, f'encode_{encoding}', lambda x: None)(plaintext)
            if result is None:
                result = {"error": f"Unknown encoding: {encoding}"}
                
            self.send_json({"encoded": result})
                
        elif path == "/finding/add":
            title = data.get("title", "")
            severity = data.get("severity", "MEDIUM")
            domain = data.get("domain", "web")
            description = data.get("description", "")
            evidence = data.get("evidence", "")
            remediation = data.get("remediation", "")
            
            if title:
                fid = master_controller.add_finding(title, severity, domain, 
                                                 description, evidence, remediation)
                self.send_json({"finding_id": fid})
            else:
                self.send_json({"error": "Missing title"}, 400)
                
        elif path == "/report":
            report_type = data.get("type", "vuln")
            findings = master_controller.get_findings()
            self.send_json({
                "type": report_type,
                "findings": findings,
                "count": len(findings)
            })
            
        else:
            self.send_json({"error": "Not found", "path": path}, 404)
            
    def do_PUT(self):
        self.do_POST()
        
    def do_DELETE(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        
        if path == "/scope":
            scope = query.get("scope", [None])[0]
            if scope:
                master_controller.remove_scope(scope)
                self.send_json({"removed": scope})
            else:
                self.send_json({"error": "Missing scope parameter"}, 400)
                
        else:
            self.send_json({"error": "Not found"}, 404)
            
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-API-Version", self.version)
        self.end_headers()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    
    def server_bind(self):
        self.socket.setsockopt(socketserver.SOL_SOCKET, 
                            socketserver.SO_REUSEADDR, 1)
        super().server_bind()


def start_api_server(host: str = "0.0.0.0", port: int = 8080, 
                   background: bool = False) -> Dict:
    server = ThreadedHTTPServer((host, port), APIHandler)
    
    url = f"http://{host}:{port}"
    
    def run():
        print(f"[API] ParallaxForge API starting on {url}")
        print(f"[API] Endpoints:")
        print(f"  GET  /status      - System status")
        print(f"  GET  /agents     - List agents")
        print(f"  GET  /decode?data=<> - Auto-decode")
        print(f"  GET  /hash?data=<>   - Calculate hashes")
        print(f"  GET  /findings    - List findings")
        print(f"  GET  /scopes     - List scopes")
        print(f"  POST /spawn      - Spawn agent")
        print(f"  POST /return     - Return agent")
        print(f"  POST /decode     - Decode data")
        print(f"  POST /encode     - Encode data")
        print(f"  POST /learn     - Learn knowledge")
        print(f"  POST /finding/add - Add finding")
        print(f"  POST /report     - Generate report")
        server.serve_forever()
        
    if background:
        thread = Thread(target=run, daemon=True)
        thread.start()
        return {"started": True, "url": url, "background": True}
    else:
        run()


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    start_api_server(host, port)