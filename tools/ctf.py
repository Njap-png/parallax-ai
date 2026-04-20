#!/usr/bin/env python3
import os
import json
import sqlite3
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

class ChallengeType(Enum):
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    OSINT = "osint"
    recon = "recon"
    MIXED = "mixed"

class Difficulty(Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"

@dataclass
class Challenge:
    name: str
    category: ChallengeType
    difficulty: Difficulty
    points: int
    flag: str
    description: str
    hints: List[str]
    files: List[str]
    solve_count: int = 0

class CTFEngine:
    def __init__(self, db_path="ctf.db"):
        self.db_path = db_path
        self.categories = [c.value for c in ChallengeType]
        self.difficulties = [d.value for d in Difficulty]
        self.init_db()
        self.session_score = 0
        self.session_solves = []
        
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS challenges
                     (id INTEGER PRIMARY KEY, name TEXT UNIQUE,
                      category TEXT, difficulty TEXT, points INTEGER,
                      flag TEXT, description TEXT, hints TEXT,
                      files TEXT, solve_count INTEGER DEFAULT 0)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS solves
                     (id INTEGER PRIMARY KEY, team TEXT,
                      challenge_id INTEGER, time_taken REAL,
                      timestamp TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS hints
                     (id INTEGER PRIMARY KEY, challenge_id INTEGER,
                      hint TEXT, cost INTEGER, revealed INTEGER)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS flags
                     (id INTEGER PRIMARY KEY, challenge_id INTEGER,
                      flag TEXT, used INTEGER DEFAULT 0)''')
        
        conn.commit()
        conn.close()
        
    def add_challenge(self, name: str, category: str, difficulty: str,
                   points: int, flag: str, description: str,
                   hints: List[str] = None, files: List[str] = None) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO challenges
                         (name, category, difficulty, points, flag,
                          description, hints, files, solve_count)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)''',
                      (name, category, difficulty, points, flag,
                       description, json.dumps(hints or []), 
                       json.dumps(files or [])))
            conn.commit()
            conn.close()
            return True
        except:
            conn.close()
            return False
            
    def remove_challenge(self, name: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("DELETE FROM challenges WHERE name = ?", (name,))
        deleted = c.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
        
    def submit_flag(self, team: str, flag: str) -> Dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT id, name, points FROM challenges WHERE flag = ?", (flag,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return {"valid": False, "message": "Invalid flag"}
            
        challenge_id, name, points = row
        
        c.execute("SELECT id FROM solves WHERE team = ? AND challenge_id = ?",
                 (team, challenge_id))
        if c.fetchone():
            conn.close()
            return {"valid": False, "message": "Already solved"}
            
        timestamp = datetime.now().isoformat()
        c.execute('''INSERT INTO solves (team, challenge_id, timestamp)
                     VALUES (?, ?, ?)''',
                  (team, challenge_id, timestamp))
        c.execute('''UPDATE challenges SET solve_count = solve_count + 1
                     WHERE id = ?''',
                  (challenge_id,))
        
        conn.commit()
        conn.close()
        
        self.session_score += points
        self.session_solves.append(name)
        
        return {
            "valid": True,
            "challenge": name,
            "points": points,
            "total_score": self.session_score,
            "message": f"Correct! +{points} points"
        }
        
    def get_challenges(self, category: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        if category:
            c.execute("SELECT * FROM challenges WHERE category = ?", (category,))
        else:
            c.execute("SELECT * FROM challenges")
            
        rows = c.fetchall()
        conn.close()
        
        return [
            {"id": r[0], "name": r[1], "category": r[2],
             "difficulty": r[3], "points": r[4],
             "description": r[6], "solves": r[8]}
            for r in rows
        ]
        
    def get_scoreboard(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT team, SUM(c.points) as score, COUNT(s.id) as solves
                     FROM solves s
                     JOIN challenges c ON s.challenge_id = c.id
                     GROUP BY team
                     ORDER BY score DESC''')
        rows = c.fetchall()
        conn.close()
        
        return [
            {"team": r[0], "score": r[1], "solves": r[2]}
            for r in rows
        ]
        
    def reveal_hint(self, challenge_id: int) -> Optional[str]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT hint FROM hints WHERE challenge_id = ? AND revealed = 0",
                 (challenge_id,))
        row = c.fetchone()
        
        if row:
            c.execute("UPDATE hints SET revealed = 1 WHERE challenge_id = ?",
                      (challenge_id,))
            conn.commit()
            conn.close()
            return row[0]
            
        conn.close()
        return None
        
    def seed_challenges(self):
        challenges = [
            ("SQLi Basic", "web", "easy", 100, "flag{sql1_f1r3d}",
             "Simple SQL injection challenge. Find the hidden admin password.",
             ["Try ' OR '1'='1", "Check the login query"], []),
            ("XSS Cookie", "web", "easy", 150, "flag{x55_c00k13}",
             "Steal the administrator's cookie via XSS.",
             ["Try alert(document.cookie)"], []),
            ("JWT Secret", "crypto", "medium", 200, "flag{jwt_n0n3}",
             "Forge a JWT token with admin privileges.",
             ["Check the algorithm"], []),
            ("Base64 Madness", "crypto", "easy", 100, "flag{b64_m4573r}",
             "Decode this: ZmxhZ3tiNjRfbTF0M3J9",
             ["Multiple layers of encoding"], []),
            ("Hidden Directory", "recon", "easy", 100, "flag{h1dd3n_d1r}",
             "Find the hidden admin panel.",
             ["Check common paths", "Look for .git"], []),
            ("Buffer Overflow", "pwn", "hard", 300, "flag{buff3r_0v3rfl0w}",
             "Overflow the buffer and get shell.",
             ["Use pattern create", "Check offset"], []),
            ("Forensic Image", "forensics", "medium", 200, "flag{f0r3n51c5_1m4g3}",
             "Find the hidden data in the image.",
             ["Check image metadata", "Use binwalk"], []),
            ("OSINT Target", "osint", "medium", 250, "flag{05n7_f1nd}",
             "Find the real name of this person.",
             ["Search public records"], [])
        ]
        
        for name, cat, diff, pts, flag, desc, hints, files in challenges:
            self.add_challenge(name, cat, diff, pts, flag, desc, hints, files)
            
        return {"challenges_added": len(challenges)}
        
    def reset(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM solves")
        c.execute("UPDATE challenges SET solve_count = 0")
        conn.commit()
        conn.close()
        self.session_score = 0
        self.session_solves = []
        return {"reset": True}


ctf_engine = CTFEngine()

def solve_challenge(team: str, flag: str) -> Dict:
    return ctf_engine.submit_flag(team, flag)

def list_challenges(category: str = None) -> List[Dict]:
    return ctf_engine.get_challenges(category)

def get_scoreboard() -> List[Dict]:
    return ctf_engine.get_scoreboard()

def add_new_challenge(name: str, category: str, difficulty: str,
                  points: int, flag: str, description: str) -> bool:
    return ctf_engine.add_challenge(name, category, difficulty, points, flag, description)

def delete_challenge(name: str) -> bool:
    return ctf_engine.remove_challenge(name)