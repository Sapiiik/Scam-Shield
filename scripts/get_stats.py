#!/usr/bin/env python3
"""
Scam Shield — Statistics Query
Usage: python3 get_stats.py [summary|modus|daily|weekly]
"""

import sqlite3
import json
import sys
import os

DB_PATH = os.path.expanduser("~/scam-shield/data/scamshield.db")

def get_summary():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    stats = {}

    # Total checks
    c.execute("SELECT COUNT(*) FROM check_logs")
    stats["total_checks"] = c.fetchone()[0]

    # Verdicts breakdown
    c.execute("SELECT verdict, COUNT(*) FROM check_logs GROUP BY verdict")
    stats["verdicts"] = {row[0]: row[1] for row in c.fetchall()}

    # Total patterns
    c.execute("SELECT COUNT(*) FROM scam_patterns")
    stats["total_patterns"] = c.fetchone()[0]

    # Patterns by source
    c.execute("SELECT source, COUNT(*) FROM scam_patterns GROUP BY source")
    stats["patterns_by_source"] = {row[0]: row[1] for row in c.fetchall()}

    # Community reports
    c.execute("SELECT status, COUNT(*) FROM community_reports GROUP BY status")
    stats["reports"] = {row[0]: row[1] for row in c.fetchall()}

    # Unique users
    c.execute("SELECT COUNT(DISTINCT user_id) FROM check_logs")
    stats["unique_users"] = c.fetchone()[0]

    # Today's checks
    c.execute("SELECT COUNT(*) FROM check_logs WHERE date(checked_at) = date('now')")
    stats["today_checks"] = c.fetchone()[0]

    conn.close()
    return stats

def get_modus_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT modus, COUNT(*) as cnt FROM check_logs
        WHERE modus IS NOT NULL AND verdict IN ('scam', 'meragukan')
        GROUP BY modus ORDER BY cnt DESC LIMIT 10
    """)
    result = [{"modus": row[0], "count": row[1]} for row in c.fetchall()]
    conn.close()
    return result

def get_daily_stats(days=7):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(f"""
        SELECT date(checked_at) as day, verdict, COUNT(*) as cnt
        FROM check_logs
        WHERE checked_at >= datetime('now', '-{days} days')
        GROUP BY day, verdict
        ORDER BY day
    """)
    result = {}
    for row in c.fetchall():
        if row[0] not in result:
            result[row[0]] = {"date": row[0], "total": 0, "scam": 0, "meragukan": 0, "aman": 0}
        result[row[0]][row[1]] = row[2]
        result[row[0]]["total"] += row[2]
    conn.close()
    return list(result.values())

def get_weekly_report():
    """Generate weekly trend report data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    report = {"period": "7 hari terakhir"}

    # Total checks this week
    c.execute("SELECT COUNT(*) FROM check_logs WHERE checked_at >= datetime('now', '-7 days')")
    report["total_checks"] = c.fetchone()[0]

    # Scam detected
    c.execute("SELECT COUNT(*) FROM check_logs WHERE checked_at >= datetime('now', '-7 days') AND verdict = 'scam'")
    report["scam_detected"] = c.fetchone()[0]

    # Top modus this week
    c.execute("""
        SELECT modus, COUNT(*) as cnt FROM check_logs
        WHERE checked_at >= datetime('now', '-7 days')
        AND modus IS NOT NULL AND verdict IN ('scam', 'meragukan')
        GROUP BY modus ORDER BY cnt DESC LIMIT 5
    """)
    report["top_modus"] = [{"modus": row[0], "count": row[1]} for row in c.fetchall()]

    # New community reports
    c.execute("SELECT COUNT(*) FROM community_reports WHERE created_at >= datetime('now', '-7 days')")
    report["new_reports"] = c.fetchone()[0]

    # New patterns from community
    c.execute("SELECT COUNT(*) FROM scam_patterns WHERE source = 'community' AND created_at >= datetime('now', '-7 days')")
    report["new_patterns_from_community"] = c.fetchone()[0]

    conn.close()
    return report

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "summary"

    if mode == "summary":
        print(json.dumps(get_summary(), indent=2, ensure_ascii=False))
    elif mode == "modus":
        print(json.dumps(get_modus_stats(), indent=2, ensure_ascii=False))
    elif mode == "daily":
        print(json.dumps(get_daily_stats(), indent=2, ensure_ascii=False))
    elif mode == "weekly":
        print(json.dumps(get_weekly_report(), indent=2, ensure_ascii=False))
    else:
        print("Usage: python3 get_stats.py [summary|modus|daily|weekly]")
