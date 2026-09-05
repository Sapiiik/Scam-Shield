#!/usr/bin/env python3
"""
Scam Shield — Database Setup & Seed Data Import
Jalankan sekali saat pertama kali deploy: python3 setup_db.py
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.expanduser("~/scam-shield/data/scamshield.db")
SEED_PATH = os.path.expanduser("~/scam-shield/data/seed_patterns.json")

def setup_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tabel pola scam (keyword, domain, nomor rekening)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scam_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,          -- 'keyword', 'domain', 'phone', 'account'
            pattern TEXT NOT NULL,
            modus TEXT,                  -- jenis modus scam
            source TEXT DEFAULT 'seed',  -- 'seed', 'community', 'admin'
            confidence REAL DEFAULT 0.8,
            report_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(type, pattern)
        )
    """)

    # Tabel log pengecekan
    c.execute("""
        CREATE TABLE IF NOT EXISTS check_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            message_preview TEXT,        -- 50 karakter pertama (privasi)
            verdict TEXT NOT NULL,        -- 'aman', 'meragukan', 'scam'
            confidence REAL,
            modus TEXT,
            layers_triggered TEXT,        -- JSON array: ["layer1", "layer2", "layer3"]
            checked_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Tabel laporan komunitas
    c.execute("""
        CREATE TABLE IF NOT EXISTS community_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            reported_text TEXT,
            reported_url TEXT,
            reported_phone TEXT,
            reported_account TEXT,
            modus TEXT,
            status TEXT DEFAULT 'pending',  -- 'pending', 'verified', 'rejected'
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Index untuk performa
    c.execute("CREATE INDEX IF NOT EXISTS idx_patterns_type ON scam_patterns(type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_patterns_pattern ON scam_patterns(pattern)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_verdict ON check_logs(verdict)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON check_logs(checked_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON community_reports(status)")

    conn.commit()
    print("[OK] Database tables created")
    return conn

def import_seed_data(conn):
    c = conn.cursor()

    with open(SEED_PATH, "r") as f:
        data = json.load(f)

    count = 0

    # Import keyword scam
    for kw in data.get("keywords_scam", []):
        # Tentukan modus berdasarkan keyword
        modus = detect_modus_from_keyword(kw, data.get("modus_types", {}))
        try:
            c.execute(
                "INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source) VALUES (?, ?, ?, ?)",
                ("keyword", kw.lower(), modus, "seed")
            )
            count += c.rowcount
        except sqlite3.IntegrityError:
            pass

    # Import suspicious domains
    for domain in data.get("suspicious_domains", []):
        try:
            c.execute(
                "INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source, confidence) VALUES (?, ?, ?, ?, ?)",
                ("domain_suspicious", domain.lower(), None, "seed", 0.5)
            )
            count += c.rowcount
        except sqlite3.IntegrityError:
            pass

    # Import known scam domains
    for domain in data.get("known_scam_domains", []):
        try:
            c.execute(
                "INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source, confidence) VALUES (?, ?, ?, ?, ?)",
                ("domain_scam", domain.lower(), "phishing", "seed", 0.95)
            )
            count += c.rowcount
        except sqlite3.IntegrityError:
            pass

    # Import bank account patterns
    for pattern in data.get("bank_account_patterns", []):
        try:
            c.execute(
                "INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source) VALUES (?, ?, ?, ?)",
                ("account_indicator", pattern.lower(), None, "seed")
            )
            count += c.rowcount
        except sqlite3.IntegrityError:
            pass

    # Import suspicious phone prefixes
    for prefix in data.get("scam_phone_prefixes", []):
        try:
            c.execute(
                "INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source) VALUES (?, ?, ?, ?)",
                ("phone_prefix", prefix, None, "seed")
            )
            count += c.rowcount
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    print(f"[OK] Imported {count} seed patterns")

def detect_modus_from_keyword(keyword, modus_types):
    kw_lower = keyword.lower()
    for modus_id, modus_info in modus_types.items():
        for mk in modus_info.get("keywords", []):
            if mk.lower() in kw_lower:
                return modus_id
    return None

if __name__ == "__main__":
    print("=== Scam Shield Database Setup ===")
    print(f"Database: {DB_PATH}")
    conn = setup_database()
    import_seed_data(conn)

    # Tampilkan statistik
    c = conn.cursor()
    c.execute("SELECT type, COUNT(*) FROM scam_patterns GROUP BY type")
    print("\nSeed data summary:")
    for row in c.fetchall():
        print(f"  {row[0]}: {row[1]} patterns")

    conn.close()
    print("\n[DONE] Database ready!")
