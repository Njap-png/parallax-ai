#!/usr/bin/env python3
import base64
import binascii
import urllib.parse
import html
import json
import re
import codecs
import zlib
import hashlib
import gzip
from typing import Dict, List, Optional, Any
from datetime import datetime

class DecoderAgent:
    """Decoder Agent - Decodes/encodes various formats for analysis"""
    
    NAME = "Decoder Agent"
    VERSION = "2.0.0"
    
    ENCODINGS = ['base64', 'hex', 'url', 'html', 'rot13', 'binary', 'octal', 'unicode', 'json']
    
    def __init__(self):
        self.encodings = self.ENCODINGS
        
    def decode_base64(self, data: str) -> Optional[str]:
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None
            
    def encode_base64(self, data: str) -> str:
        return base64.b64encode(data.encode()).decode()
        
    def decode_hex(self, data: str) -> Optional[str]:
        try:
            return bytes.fromhex(data).decode('utf-8')
        except:
            return None
            
    def encode_hex(self, data: str) -> str:
        return data.encode().hex()
        
    def decode_url(self, data: str) -> str:
        return urllib.parse.unquote(data)
        
    def encode_url(self, data: str) -> str:
        return urllib.parse.quote(data)
        
    def decode_html(self, data: str) -> str:
        return html.unescape(data)
        
    def encode_html(self, data: str) -> str:
        return html.escape(data)
        
    def decode_rot13(self, data: str) -> str:
        return codecs.decode(data, 'rot13')
        
    def encode_rot13(self, data: str) -> str:
        return codecs.encode(data, 'rot13')
        
    def decode_binary(self, data: str) -> Optional[str]:
        try:
            binary = data.replace(' ', '').replace('0b', '')
            return chr(int(binary, 2))
        except:
            return None
            
    def encode_binary(self, data: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in data)
        
    def decode_octal(self, data: str) -> Optional[str]:
        try:
            return oct(int(data, 8))
        except:
            return None
            
    def encode_octal(self, data: Any) -> str:
        return oct(data) if isinstance(data, int) else oct(int(data, 16))
        
    def decode_json(self, data: str) -> Optional[Dict]:
        try:
            return json.loads(data)
        except:
            return None
            
    def encode_json(self, data: Any) -> str:
        return json.dumps(data, indent=2)
        
    def decode_unicode(self, data: str) -> List[str]:
        results = []
        for enc in ['utf-16-le', 'utf-16-be', 'utf-16']:
            try:
                decoded = data.encode(enc).decode(enc.replace('-le', '').replace('-be', ''))
                if decoded:
                    results.append(decoded)
            except:
                pass
        return results
        
    def decode_multibase(self, data: str) -> Dict:
        results = {}
        for enc in self.encodings:
            try:
                decoded = getattr(self, f'decode_{enc}')(data)
                if decoded and decoded != data:
                    results[enc] = decoded
            except:
                pass
        return results
        
    def deflate_compress(self, data: str) -> bytes:
        return zlib.compress(data.encode())
        
    def deflate_decompress(self, data: bytes) -> str:
        return zlib.decompress(data).decode()
        
    def gzip_compress(self, data: str) -> bytes:
        return gzip.compress(data.encode())
        
    def gzip_decompress(self, data: bytes) -> str:
        return gzip.decompress(data).decode()
        
    def calculate_hashes(self, data: str) -> Dict:
        data_bytes = data.encode() if isinstance(data, str) else data
        return {
            "md5": hashlib.md5(data_bytes).hexdigest(),
            "sha1": hashlib.sha1(data_bytes).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
            "sha512": hashlib.sha512(data_bytes).hexdigest()
        }
        
    def parse_powershell(self, script: str) -> Dict:
        results = {
            "encoded_commands": [],
            "cmdlets": [],
            "aliases": [],
            "downloaders": [],
            "obfuscation_detected": False
        }
        
        encoded = re.findall(r'-enc\s+([A-Za-z0-9+/=]+)', script)
        results["encoded_commands"] = encoded
        
        cmdlets = re.findall(r'([A-Z][a-z]+)-[A-Z][a-zA-Z]+', script)
        results["cmdlets"] = list(set(cmdlets))
        
        aliases = re.findall(r'set-alias\s+(\w+)', script)
        results["aliases"] = aliases
        
        downloads = re.findall(r'(Invoke-WebRequest|Invoke-RestMethod|wget|curl|Start-BitsTransfer)', script, re.IGNORECASE)
        results["downloaders"] = list(set(downloads))
        
        if encoded or len(aliases) > 2:
            results["obfuscation_detected"] = True
            
        return results
        
    def decode_jwt(self, token: str) -> Optional[Dict]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
                
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2]
            }
        except:
            return None
            
    def decode_ntlm(self, hash: str) -> Optional[Dict]:
        pattern = r'([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):([a-fA-F0-9]{48})'
        match = re.match(pattern, hash)
        
        if match:
            return {
                "lm_hash": match.group(1),
                "nt_hash": match.group(2),
                "nt_proof": match.group(3)
            }
        return None
        
    def decode_ssh_key(self, key_data: str) -> Optional[Dict]:
        results = {
            "type": None,
            "key": None
        }
        
        if "BEGIN RSA PRIVATE KEY" in key_data:
            results["type"] = "RSA"
        elif "BEGIN DSA PRIVATE KEY" in key_data:
            results["type"] = "DSA"
        elif "BEGIN EC PRIVATE KEY" in key_data:
            results["type"] = "EC"
        elif "BEGIN OPENSSH PRIVATE KEY" in key_data:
            results["type"] = "OpenSSH"
            
        return results if results["type"] else None
        
    def decode_sensitive_files(self, content: str) -> Dict:
        results = {
            "credentials": [],
            "api_keys": [],
            "tokens": [],
            "private_keys": [],
            "aws_keys": [],
            "secrets_found": []
        }
        
        patterns = {
            "aws_access": r'(A3T[A-Z0-9]|AKIA|ABIA|ACCA)[A-Z0-9]{16}',
            "aws_secret": r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}',
            "api_key": r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{32,}',
            "private_key": r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            "token": r'(?i)bearer\s+[A-Za-z0-9\-_.~]+',
            "password": r'(?i)password["\']?\s*[:=]\s*["\']?[^\s"\'<]{8,}'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if pattern_name == "credentials":
                results["credentials"] = matches
            elif pattern_name == "api_key":
                results["api_keys"] = matches
            elif pattern_name == "token":
                results["tokens"] = matches
            elif pattern_name == "private_key":
                results["private_keys"] = matches
            elif pattern_name == "aws_access":
                results["aws_keys"] = matches
                
        results["secrets_found"] = len(results["credentials"]) + len(results["api_keys"]) + \
                             len(results["tokens"]) + len(results["private_keys"]) + \
                             len(results["aws_keys"])
                             
        return results
        
    def analyze_obfuscation(self, data: str) -> Dict:
        results = {
            "entropy": 0,
            "char_frequency": {},
            "unique_chars": 0,
            "suspicious_patterns": [],
            "likely_obfuscated": False
        }
        
        for char in data:
            results["char_frequency"][char] = results["char_frequency"].get(char, 0) + 1
            
        results["unique_chars"] = len(results["char_frequency"])
        data_len = len(data)
        
        if data_len > 0:
            results["entropy"] = -sum(
                (c / data_len) * (c.bit_length() / data_len) 
                for c in results["char_frequency"].values() 
                if c > 0
            )
            
        if results["unique_chars"] < data_len * 0.3 and data_len > 10:
            results["suspicious_patterns"].append("Low character diversity")
            results["likely_obfuscated"] = True
            
        if data.count('/') > data_len * 0.1:
            results["suspicious_patterns"].append("High slash frequency")
            results["likely_obfuscated"] = True
            
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', data):
            results["suspicious_patterns"].append("Possible Base64")
            
        return results
        
    def auto_decode(self, data: str) -> Dict:
        results = {
            "input": data,
            "detected": [],
            "decoded": {}
        }
        
        if len(data) < 3:
            results["error"] = "Input too short"
            return results
            
        results["decoded"] = self.decode_multibase(data)
        
        for enc, decoded in results["decoded"].items():
            if decoded and decoded != data:
                results["detected"].append(enc)
                
        if results["decoded"].get("base64"):
            results["detected"].append("base64_nested")
            nested = self.decode_multibase(results["decoded"]["base64"])
            if nested:
                results["decoded"]["nested"] = nested
                
        return results


decoder_agent = DecoderAgent()