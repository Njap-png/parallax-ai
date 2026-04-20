#!/usr/bin/env python3
import base64
import binascii
import urllib.parse
import html
import json
import re
import codecs
import zlib
import gzip
import hashlib
import struct
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class AutoDecoder:
    def __init__(self):
        self.encodings = [
            "base64", "base32", "hex", "url", "html", "rot13", 
            "rot47", "binary", "octal", "unicode", "gzip", "deflate", "jwt", "xor"
        ]
        self.results = {}
        
    def decode_base64(self, data: str) -> Optional[str]:
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None
            
    def encode_base64(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(data).decode()
        
    def decode_base32(self, data: str) -> Optional[str]:
        try:
            return base64.b32decode(data).decode('utf-8', errors='ignore')
        except:
            return None
            
    def encode_base32(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.b32encode(data).decode()
        
    def decode_hex(self, data: str) -> Optional[str]:
        try:
            if data.startswith('0x'):
                data = data[2:]
            return bytes.fromhex(data).decode('utf-8')
        except:
            return None
            
    def encode_hex(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode()
        return data.hex()
        
    def decode_url(self, data: str) -> str:
        try:
            return urllib.parse.unquote(data)
        except:
            return data
            
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
        
    def decode_rot47(self, data: str) -> str:
        result = []
        for char in data:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                result.append(char)
        return ''.join(result)
        
    def encode_rot47(self, data: str) -> str:
        result = []
        for char in data:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                result.append(char)
        return ''.join(result)
        
    def decode_binary(self, data: str) -> Optional[str]:
        try:
            data = data.replace(' ', '').replace('0b', '')
            return chr(int(data, 2))
        except:
            return None
            
    def encode_binary(self, data: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in data)
        
    def decode_octal(self, data: str) -> Optional[str]:
        try:
            return oct(int(data, 8))
        except:
            return None
            
    def encode_octal(self, data: Union[str, int]) -> str:
        if isinstance(data, str):
            data = int(data, 16) if 'x' in data else int(data)
        return oct(data)
        
    def decode_gzip(self, data: Union[str, bytes]) -> Optional[str]:
        try:
            if isinstance(data, str):
                data = base64.b64decode(data)
            return gzip.decompress(data).decode('utf-8')
        except:
            return None
            
    def encode_gzip(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(gzip.compress(data)).decode()
        
    def decode_deflate(self, data: Union[str, bytes]) -> Optional[str]:
        try:
            if isinstance(data, str):
                data = base64.b64decode(data)
            return zlib.decompress(data).decode('utf-8')
        except:
            return None
            
    def encode_deflate(self, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.b64encode(zlib.compress(data)).decode()
        
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
            
    def encode_jwt(self, payload: Dict, secret: str = "", header: Dict = None) -> str:
        if header is None:
            header = {"alg": "HS256", "typ": "JWT"}
            
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        import hmac
        signature = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
        
    def decode_xor(self, data: str, key: str = "0xAA") -> Optional[str]:
        try:
            if key.startswith('0x'):
                key = int(key, 16)
            else:
                key = int(key)
                
            if data.startswith('0x'):
                data = data[2:]
                
            data_bytes = bytes.fromhex(data) if len(data) % 2 == 0 else data.encode()
            
            result = bytes(b ^ key for b in data_bytes)
            return result.decode('utf-8', errors='ignore')
        except:
            return None
            
    def encode_xor(self, data: str, key: str = "0xAA") -> str:
        if key.startswith('0x'):
            key = int(key, 16)
        else:
            key = int(key)
            
        data_bytes = data.encode() if isinstance(data, str) else data
        result = bytes(b ^ key for b in data_bytes)
        return result.hex()
        
    def decode_multibase(self, data: str, max_depth: int = 2) -> Dict:
        results = {
            "input": data,
            "detected": [],
            "decoded": {},
            "nested": {},
            "confidence": {}
        }
        
        if not data or len(data) < 2:
            results["error"] = "Input too short"
            return results
            
        if len(data) > 200 and not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in data):
            return results
            
        for enc in self.encodings:
            try:
                decoded = getattr(self, f'decode_{enc}')(data)
                if decoded and decoded != data and len(decoded) > 2:
                    conf = self.calculate_confidence(data, decoded, enc)
                    if conf > 0.3:
                        results["detected"].append(enc)
                        results["decoded"][enc] = decoded[:200] if len(decoded) > 200 else decoded
                        results["confidence"][enc] = conf
            except:
                pass
                
        return results
        
    def calculate_confidence(self, original: str, decoded: str, encoding: str) -> float:
        score = 0.0
        
        if encoding in ["base64", "base32"]:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', decoded):
                score = 0.9
            elif re.match(r'^[A-Za-z0-9]+$', decoded):
                score = 0.7
        elif encoding == "hex":
            if re.match(r'^[0-9a-fA-F]+$', decoded):
                score = 0.9
        elif encoding == "url":
            if '%' in original and '%' in decoded:
                score = 0.9
            elif decoded != original:
                score = 0.6
        elif encoding == "html":
            if '&' in original:
                score = 0.8
        elif encoding == "rot13":
            if decoded != original:
                score = 0.7
        elif encoding == "xor":
            if len(decoded) > 0:
                score = 0.5
                
        return score
        
    def calculate_hashes(self, data: str) -> Dict:
        data_bytes = data.encode() if isinstance(data, str) else data
        return {
            "md5": hashlib.md5(data_bytes).hexdigest(),
            "sha1": hashlib.sha1(data_bytes).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
            "sha512": hashlib.sha512(data_bytes).hexdigest()
        }
        
    def auto_decode(self, data: str) -> Dict:
        results = self.decode_multibase(data)
        
        if not results.get("detected"):
            results = self.analyze_encoding(data)
            
        return results
        
    def analyze_encoding(self, data: str) -> Dict:
        results = {
            "input": data,
            "analysis": {},
            "likely": None,
            "confidence": 0.0
        }
        
        is_hex = bool(re.match(r'^[0-9a-fA-F]+$', data))
        is_base64 = bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', data))
        is_url_encoded = '%' in data
        is_html_encoded = '&' in data or '<' in data or '>' in data
        
        candidates = []
        if is_hex: candidates.append("hex")
        if is_base64: candidates.append("base64")
        if is_url_encoded: candidates.append("url")
        if is_html_encoded: candidates.append("html")
        
        if candidates:
            results["likely"] = candidates[0]
            results["confidence"] = 0.8
            results["analysis"]["candidates"] = candidates
            
        return results


auto_decoder = AutoDecoder()