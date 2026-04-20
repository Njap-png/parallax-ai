import base64
import binascii
import urllib.parse
import html
import json
import re
import codecs
import zlib
import struct
import hashlib

class Decoder:
    def __init__(self):
        self.encodings = ['base64', 'hex', 'url', 'html', 'rot13', 'binary', 'octal']
        
    def decode_base64(self, data):
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None
            
    def encode_base64(self, data):
        return base64.b64encode(data.encode() if isinstance(data, str) else data)
        
    def decode_hex(self, data):
        try:
            return bytes.fromhex(data).decode('utf-8')
        except:
            return None
            
    def encode_hex(self, data):
        return data.encode().hex()
        
    def decode_url(self, data):
        return urllib.parse.unquote(data)
        
    def encode_url(self, data):
        return urllib.parse.quote(data)
        
    def decode_html(self, data):
        return html.unescape(data)
        
    def encode_html(self, data):
        return html.escape(data)
        
    def decode_rot13(self, data):
        return codecs.decode(data, 'rot13')
        
    def encode_rot13(self, data):
        return codecs.encode(data, 'rot13')
        
    def decode_binary(self, data):
        try:
            binary = data.replace(' ', '').replace('0b', '')
            return chr(int(binary, 2))
        except:
            return None
            
    def encode_binary(self, data):
        return ' '.join(format(ord(c), '08b') for c in data)
        
    def decode_octal(self, data):
        try:
            return oct(int(data, 8))
        except:
            return None
            
    def encode_octal(self, data):
        return oct(data) if isinstance(data, int) else oct(int(data, 16))
        
    def decode_json(self, data):
        try:
            return json.loads(data)
        except:
            return None
            
    def encode_json(self, data):
        return json.dumps(data, indent=2)
        
    def decode_multibase(self, data):
        results = {}
        for enc in self.encodings:
            try:
                decoded = getattr(self, f'decode_{enc}')(data)
                if decoded:
                    results[enc] = decoded
            except:
                pass
        return results
        
    def deflate_compress(self, data):
        return zlib.compress(data.encode())
        
    def deflate_decompress(self, data):
        return zlib.decompress(data).decode()
        
    def gzip_compress(self, data):
        import gzip
        return gzip.compress(data.encode())
        
    def gzip_decompress(self, data):
        import gzip
        return gzip.decompress(data).decode()
        
    def unicode_decode(self, data):
        results = []
        for i in range(2, 5):
            try:
                results.append(data.encode('utf-16-le').decode('utf-16-le'))
            except:
                pass
        return results
        
    def detect_encoding(self, sample):
        encodings_to_try = ['utf-8', 'utf-16', 'utf-16le', 'utf-16be', 
                         'latin-1', 'cp1252', 'iso-8859-1']
        for enc in encodings_to_try:
            try:
                sample.encode(enc)
                return enc
            except:
                continue
        return 'unknown'
        
    def calculate_hashes(self, data):
        return {
            "md5": hashlib.md5(data.encode()).hexdigest(),
            "sha1": hashlib.sha1(data.encode()).hexdigest(),
            "sha256": hashlib.sha256(data.encode()).hexdigest(),
            "sha512": hashlib.sha512(data.encode()).hexdigest()
        }
        
    def parse_powershell(self, script):
        results = {
            "encoded_commands": [],
            "cmdlets": [],
            "aliases": [],
            "downloaders": []
        }
        encoded = re.findall(r'-enc\s+([A-Za-z0-9+/=]+)', script)
        results["encoded_commands"] = encoded
        
        cmdlets = re.findall(r'([A-Za-z]+)-[A-Za-z]+', script)
        results["cmdlets"] = list(set(cmdlets))
        
        downloads = re.findall(r'(Invoke-WebRequest|Invoke-RestMethod|wget|curl)', script)
        results["downloaders"] = downloads
        
        return results
        
    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            return {"header": header, "payload": payload}
        except:
            return None
            
    def analyze_obfuscation(self, data):
        results = {
            "char_frequency": {},
            "entropy": 0,
            "suspicious_patterns": [],
            "likely_obfuscated": False
        }
        for char in data:
            results["char_frequency"][char] = results["char_frequency"].get(char, 0) + 1
        if len(set(data)) < len(data) * 0.3:
            results["suspicious_patterns"].append("Low character diversity")
            results["likely_obfuscated"] = True
        return results

decoder = Decoder()