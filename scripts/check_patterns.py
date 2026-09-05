#!/usr/bin/env python3
"""
Scam Shield — Layer 1: Pattern Matching (Regex + Database)
Usage: python3 check_patterns.py "<message_text>"

Returns JSON with matched patterns, suspected modus, and confidence score.
"""

import sqlite3
import json
import re
import sys
import os

DB_PATH = os.path.expanduser("~/scam-shield/data/scamshield.db")

def extract_urls(text):
    """Ekstrak semua URL dari teks."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def extract_phones(text):
    """Ekstrak nomor telepon dari teks."""
    phone_pattern = r'(?:\+62|62|0)[\s-]?(?:\d[\s-]?){8,12}'
    return re.findall(phone_pattern, text)

def extract_domains_from_urls(urls):
    """Ekstrak domain dari list URL."""
    domains = []
    for url in urls:
        match = re.search(r'https?://([^/\s:]+)', url)
        if match:
            domains.append(match.group(1).lower())
    return domains

def check_message(message):
    """Jalankan Layer 1 pattern matching terhadap pesan."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    msg_lower = message.lower()

    result = {
        "layer": 1,
        "matches": [],
        "urls_found": [],
        "phones_found": [],
        "suspected_modus": [],
        "confidence": 0.0,
        "verdict_hint": "aman"
    }

    # 1. Cek keyword scam
    c.execute("SELECT pattern, modus, confidence FROM scam_patterns WHERE type = 'keyword'")
    keyword_hits = 0
    for row in c.fetchall():
        pattern, modus, conf = row
        if pattern.lower() in msg_lower:
            keyword_hits += 1
            result["matches"].append({
                "type": "keyword",
                "pattern": pattern,
                "modus": modus
            })
            if modus and modus not in result["suspected_modus"]:
                result["suspected_modus"].append(modus)

    # 2. Cek URL
    urls = extract_urls(message)
    result["urls_found"] = urls
    domains = extract_domains_from_urls(urls)

    for domain in domains:
        # Cek known scam domains
        c.execute("SELECT pattern, modus FROM scam_patterns WHERE type = 'domain_scam' AND ? LIKE '%' || pattern || '%'", (domain,))
        for row in c.fetchall():
            result["matches"].append({
                "type": "domain_scam",
                "pattern": row[0],
                "modus": row[1]
            })

        # Cek suspicious TLD / shortener
        c.execute("SELECT pattern FROM scam_patterns WHERE type = 'domain_suspicious'")
        for row in c.fetchall():
            sus_pattern = row[0]
            if domain.endswith(sus_pattern) or domain == sus_pattern:
                result["matches"].append({
                    "type": "domain_suspicious",
                    "pattern": sus_pattern,
                    "modus": None
                })

    # 3. Cek nomor telepon
    phones = extract_phones(message)
    result["phones_found"] = phones

    for phone in phones:
        clean_phone = re.sub(r'[\s-]', '', phone)
        c.execute("SELECT pattern FROM scam_patterns WHERE type = 'phone_prefix'")
        for row in c.fetchall():
            if clean_phone.startswith(row[0]):
                result["matches"].append({
                    "type": "phone_suspicious",
                    "pattern": row[0],
                    "modus": None
                })

    # 4. Cek indikator nomor rekening
    c.execute("SELECT pattern FROM scam_patterns WHERE type = 'account_indicator'")
    for row in c.fetchall():
        if row[0].lower() in msg_lower:
            result["matches"].append({
                "type": "account_indicator",
                "pattern": row[0],
                "modus": None
            })

    # 5. Cek pola urgency / tekanan
    urgency_patterns = [
        r'segera\b', r'sekarang juga', r'batas waktu', r'hari ini saja',
        r'sebelum hangus', r'jangan sampai', r'terbatas',
        r'hanya untuk \d+ orang', r'sisa \d+ slot', r'buruan',
        r'last chance', r'limited', r'act now', r'urgent'
    ]
    for up in urgency_patterns:
        if re.search(up, msg_lower):
            result["matches"].append({
                "type": "urgency",
                "pattern": up,
                "modus": None
            })
            break  # satu cukup

    # Hitung confidence
    total_matches = len(result["matches"])
    has_scam_domain = any(m["type"] == "domain_scam" for m in result["matches"])
    has_keywords = keyword_hits > 0
    has_urgency = any(m["type"] == "urgency" for m in result["matches"])
    has_account = any(m["type"] == "account_indicator" for m in result["matches"])

    if has_scam_domain:
        result["confidence"] = 0.95
        result["verdict_hint"] = "scam"
    elif total_matches >= 4:
        result["confidence"] = 0.85
        result["verdict_hint"] = "scam"
    elif total_matches >= 2:
        result["confidence"] = 0.65
        result["verdict_hint"] = "meragukan"
    elif total_matches >= 1:
        result["confidence"] = 0.40
        result["verdict_hint"] = "meragukan"
    else:
        result["confidence"] = 0.1
        result["verdict_hint"] = "aman"

    # Boost confidence kalau ada kombinasi keyword + urgency + account
    if has_keywords and has_urgency and has_account:
        result["confidence"] = min(result["confidence"] + 0.15, 0.95)
        result["verdict_hint"] = "scam"

    conn.close()
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_patterns.py \"<message>\"")
        sys.exit(1)

    message = sys.argv[1]
    result = check_message(message)
    print(json.dumps(result, indent=2, ensure_ascii=False))
