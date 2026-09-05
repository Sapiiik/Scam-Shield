#!/usr/bin/env python3
"""
Scam Shield - Community Report: submit & promote reports to patterns

Usage:
  python3 report_scam.py submit <user_id> <text> [url] [phone] [account] [modus]
  python3 report_scam.py verify <report_id>
  python3 report_scam.py reject <report_id>
  python3 report_scam.py list [pending|verified|rejected]
  python3 report_scam.py groups
"""

import sqlite3
import json
import sys
import os
import re
import difflib
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(PROJECT_DIR, "data", "scamshield.db")

SIMILARITY_THRESHOLD = 0.55
PROMOTE_AFTER = 3
MIN_PHRASE_WORDS = 3


def normalize(text):
    """Samakan bentuk teks agar variasi kecil tidak dianggap pesan berbeda."""
    if not text:
        return ""
    t = text.lower()
    t = re.sub(r'https?://\S+', ' ', t)
    t = re.sub(r'\d+', '#', t)
    t = re.sub(r'[^a-z0-9#\s]', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def is_similar(a, b, threshold=SIMILARITY_THRESHOLD):
    """Bandingkan dua laporan lewat irisan kata dan kemiripan urutan karakter."""
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return False
    wa, wb = set(na.split()), set(nb.split())
    jaccard = len(wa & wb) / len(wa | wb) if (wa | wb) else 0
    sequence = difflib.SequenceMatcher(None, na, nb).ratio()
    return max(jaccard, sequence) >= threshold


def common_phrase(texts, min_words=MIN_PHRASE_WORDS):
    """Ambil rangkaian kata terpanjang yang muncul di semua laporan sekelompok."""
    word_lists = [normalize(t).split() for t in texts if normalize(t)]
    if not word_lists:
        return None
    common = word_lists[0]
    for words in word_lists[1:]:
        matcher = difflib.SequenceMatcher(None, common, words)
        blocks = [b for b in matcher.get_matching_blocks() if b.size > 0]
        if not blocks:
            return None
        best = max(blocks, key=lambda b: b.size)
        common = common[best.a: best.a + best.size]
        if len(common) < min_words:
            return None
    return " ".join(common) if len(common) >= min_words else None


def find_similar_group(cursor, text):
    """Kumpulkan laporan yang mirip dengan teks ini, termasuk yang sudah verified."""
    cursor.execute("""
        SELECT id, reported_text, reported_url, modus
        FROM community_reports
        WHERE status IN ('pending', 'verified')
        ORDER BY id DESC LIMIT 500
    """)
    group = []
    for row in cursor.fetchall():
        if row[1] and is_similar(text, row[1]):
            group.append({"id": row[0], "text": row[1], "url": row[2], "modus": row[3]})
    return group


def add_pattern(cursor, ptype, pattern, modus, confidence, report_count=None):
    if not pattern:
        return
    if report_count is None:
        cursor.execute("""
            INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source, confidence)
            VALUES (?, ?, ?, 'community', ?)
        """, (ptype, pattern, modus, confidence))
    else:
        cursor.execute("""
            INSERT OR IGNORE INTO scam_patterns (type, pattern, modus, source, confidence, report_count)
            VALUES (?, ?, ?, 'community', ?, ?)
        """, (ptype, pattern, modus, confidence, report_count))


def submit_report(user_id, text, url=None, phone=None, account=None, modus=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO community_reports (user_id, reported_text, reported_url, reported_phone, reported_account, modus)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, text, url, phone, account, modus))
    conn.commit()
    report_id = c.lastrowid

    group = find_similar_group(c, text)

    if len(group) < PROMOTE_AFTER:
        conn.close()
        print(json.dumps({
            "status": "submitted",
            "report_id": report_id,
            "similar_reports": len(group),
            "needed_for_promotion": PROMOTE_AFTER,
            "message": f"Laporan diterima (ID: {report_id}). Sudah ada {len(group)} laporan serupa; "
                       f"butuh {PROMOTE_AFTER} untuk otomatis masuk database pola."
        }, ensure_ascii=False))
        return

    phrase = common_phrase([g["text"] for g in group])
    if not phrase:
        phrase = normalize(text)[:120]

    group_modus = modus or next((g["modus"] for g in group if g["modus"]), None)

    ids = [g["id"] for g in group]
    c.execute(
        f"UPDATE community_reports SET status = 'verified' WHERE id IN ({','.join('?' * len(ids))})",
        ids
    )

    add_pattern(c, 'keyword', phrase, group_modus, 0.7, len(group))

    domains = []
    for g in group:
        if g["url"]:
            try:
                d = urlparse(g["url"]).netloc.lower()
                if d and d not in domains:
                    domains.append(d)
                    add_pattern(c, 'domain_scam', d, group_modus, 0.8)
            except Exception:
                pass

    conn.commit()
    conn.close()

    print(json.dumps({
        "status": "auto_verified",
        "report_id": report_id,
        "similar_reports": len(group),
        "promoted_pattern": phrase,
        "promoted_domains": domains,
        "modus": group_modus,
        "message": f"Laporan ke-{len(group)} untuk pola ini. Otomatis terverifikasi. "
                   f"Pola baru '{phrase}' kini aktif di Layer 1."
    }, ensure_ascii=False))


def verify_report(report_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, user_id, reported_text, reported_url, reported_phone, reported_account, modus FROM community_reports WHERE id = ?", (report_id,))
    report = c.fetchone()
    if not report:
        conn.close()
        print(json.dumps({"error": f"Report {report_id} not found"}))
        return

    c.execute("UPDATE community_reports SET status = 'verified' WHERE id = ?", (report_id,))

    reported_text, reported_url, modus = report[2], report[3], report[6]

    group = find_similar_group(c, reported_text) if reported_text else []
    phrase = common_phrase([g["text"] for g in group]) if len(group) > 1 else None
    if not phrase and reported_text:
        phrase = normalize(reported_text)[:120]

    add_pattern(c, 'keyword', phrase, modus, 0.75)

    if reported_url:
        try:
            add_pattern(c, 'domain_scam', urlparse(reported_url).netloc.lower(), modus, 0.85)
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(json.dumps({"status": "verified", "report_id": report_id, "promoted_pattern": phrase}, ensure_ascii=False))


def reject_report(report_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE community_reports SET status = 'rejected' WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()
    print(json.dumps({"status": "rejected", "report_id": report_id}))


def list_reports(status_filter=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    base = "SELECT id, user_id, reported_text, reported_url, modus, status, created_at FROM community_reports"
    if status_filter:
        c.execute(base + " WHERE status = ? ORDER BY created_at DESC LIMIT 20", (status_filter,))
    else:
        c.execute(base + " ORDER BY created_at DESC LIMIT 20")

    reports = [{
        "id": r[0], "user_id": r[1], "text": r[2][:100] if r[2] else None,
        "url": r[3], "modus": r[4], "status": r[5], "created_at": r[6]
    } for r in c.fetchall()]
    conn.close()
    print(json.dumps({"reports": reports, "count": len(reports)}, ensure_ascii=False))


def show_groups():
    """Tampilkan kelompok laporan serupa - berguna untuk demo dan moderasi."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, reported_text, modus, status FROM community_reports ORDER BY id")
    rows = c.fetchall()
    conn.close()

    groups, used = [], set()
    for i, row in enumerate(rows):
        if row[0] in used or not row[1]:
            continue
        members = [row]
        used.add(row[0])
        for other in rows[i + 1:]:
            if other[0] not in used and other[1] and is_similar(row[1], other[1]):
                members.append(other)
                used.add(other[0])
        groups.append({
            "size": len(members),
            "common_phrase": common_phrase([m[1] for m in members]) if len(members) > 1 else None,
            "modus": next((m[2] for m in members if m[2]), None),
            "report_ids": [m[0] for m in members],
            "sample": members[0][1][:80],
        })

    groups.sort(key=lambda g: -g["size"])
    print(json.dumps({"groups": groups, "count": len(groups)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 report_scam.py <submit|verify|reject|list|groups> [args...]")
        sys.exit(1)

    action = sys.argv[1]
    if action == "submit" and len(sys.argv) >= 4:
        submit_report(
            user_id=sys.argv[2],
            text=sys.argv[3],
            url=sys.argv[4] if len(sys.argv) > 4 else None,
            phone=sys.argv[5] if len(sys.argv) > 5 else None,
            account=sys.argv[6] if len(sys.argv) > 6 else None,
            modus=sys.argv[7] if len(sys.argv) > 7 else None,
        )
    elif action == "verify" and len(sys.argv) >= 3:
        verify_report(int(sys.argv[2]))
    elif action == "reject" and len(sys.argv) >= 3:
        reject_report(int(sys.argv[2]))
    elif action == "list":
        list_reports(sys.argv[2] if len(sys.argv) > 2 else None)
    elif action == "groups":
        show_groups()
    else:
        print("Invalid action. Use: submit, verify, reject, list, groups")
