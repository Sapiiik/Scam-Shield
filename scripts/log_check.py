#!/usr/bin/env python3
"""
Scam Shield — Log a scam check result to database
Usage: python3 log_check.py "<user_id>" "<message_preview>" "<verdict>" "<confidence>" "<modus>" "<layers>"
"""

import sqlite3
import json
import sys
import os

DB_PATH = os.path.expanduser("~/scam-shield/data/scamshield.db")

def log_check(user_id, message_preview, verdict, confidence, modus, layers_triggered):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO check_logs (user_id, message_preview, verdict, confidence, modus, layers_triggered)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        message_preview[:50],  # Privasi: simpan max 50 karakter
        verdict,
        float(confidence),
        modus,
        layers_triggered  # JSON string
    ))
    conn.commit()
    log_id = c.lastrowid
    conn.close()
    print(json.dumps({"status": "ok", "log_id": log_id}))

if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Usage: python3 log_check.py <user_id> <msg_preview> <verdict> <confidence> <modus> <layers_json>")
        sys.exit(1)

    log_check(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
