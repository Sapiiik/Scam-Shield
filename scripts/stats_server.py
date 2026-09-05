#!/usr/bin/env python3
"""
Scam Shield — Statistics Web Page Server
Halaman web sederhana yang menampilkan statistik pengecekan scam.
Usage: python3 stats_server.py [port]
Default port: 8080
"""

import sqlite3
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

DB_PATH = os.path.expanduser("~/scam-shield/data/scamshield.db")
PORT = 8080

MODUS_LABELS = {
    "investasi_bodong": "Investasi Bodong",
    "phishing": "Phishing",
    "kurir_palsu": "Kurir/Paket Palsu",
    "hadiah_palsu": "Hadiah/Undian Palsu",
    "pinjaman_ilegal": "Pinjaman Online Ilegal",
    "lowongan_palsu": "Lowongan Kerja Palsu",
    "impersonasi": "Impersonasi",
    "ewallet_palsu": "E-Wallet/Voucher Palsu",
    "bantuan_pemerintah_palsu": "Bantuan Pemerintah Palsu",
}

def get_db_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    stats = {}

    c.execute("SELECT COUNT(*) FROM check_logs")
    stats["total"] = c.fetchone()[0]

    c.execute("SELECT verdict, COUNT(*) FROM check_logs GROUP BY verdict")
    stats["verdicts"] = dict(c.fetchall())

    c.execute("SELECT COUNT(*) FROM check_logs WHERE date(checked_at) = date('now')")
    stats["today"] = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT user_id) FROM check_logs")
    stats["users"] = c.fetchone()[0]

    c.execute("""
        SELECT modus, COUNT(*) as cnt FROM check_logs
        WHERE modus IS NOT NULL AND verdict IN ('scam', 'meragukan')
        GROUP BY modus ORDER BY cnt DESC LIMIT 5
    """)
    stats["top_modus"] = c.fetchall()

    c.execute("SELECT COUNT(*) FROM scam_patterns")
    stats["total_patterns"] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scam_patterns WHERE source = 'community'")
    stats["community_patterns"] = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM community_reports")
    stats["total_reports"] = c.fetchone()[0]

    c.execute("""
        SELECT date(checked_at) as day, COUNT(*) FROM check_logs
        WHERE checked_at >= datetime('now', '-7 days')
        GROUP BY day ORDER BY day
    """)
    stats["daily"] = c.fetchall()

    conn.close()
    return stats

def build_html():
    stats = get_db_stats()
    scam_count = stats["verdicts"].get("scam", 0)
    meragukan_count = stats["verdicts"].get("meragukan", 0)
    aman_count = stats["verdicts"].get("aman", 0)

    modus_rows = ""
    for i, (modus, count) in enumerate(stats["top_modus"], 1):
        label = MODUS_LABELS.get(modus, modus or "Tidak teridentifikasi")
        modus_rows += f'<tr><td>{i}</td><td>{label}</td><td>{count}</td></tr>'

    daily_labels = json.dumps([d[0][-5:] for d in stats["daily"]])  # MM-DD
    daily_values = json.dumps([d[1] for d in stats["daily"]])

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scam Shield — Dashboard Statistik</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }}
  .header {{ background: linear-gradient(135deg, #1e40af, #7c3aed); padding: 2rem; text-align: center; }}
  .header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
  .header p {{ opacity: 0.8; font-size: 0.9rem; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 1.5rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; text-align: center; border: 1px solid #334155; }}
  .card .number {{ font-size: 2.5rem; font-weight: 700; }}
  .card .label {{ font-size: 0.85rem; opacity: 0.7; margin-top: 0.3rem; }}
  .card.scam .number {{ color: #ef4444; }}
  .card.meragukan .number {{ color: #f59e0b; }}
  .card.aman .number {{ color: #22c55e; }}
  .card.total .number {{ color: #3b82f6; }}
  .section {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
  .section h2 {{ font-size: 1.2rem; margin-bottom: 1rem; color: #93c5fd; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.7rem; text-align: left; border-bottom: 1px solid #334155; }}
  th {{ color: #93c5fd; font-weight: 600; }}
  .footer {{ text-align: center; padding: 2rem; opacity: 0.5; font-size: 0.8rem; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }}
  .badge-community {{ background: #7c3aed33; color: #a78bfa; }}
  .bar-chart {{ display: flex; align-items: flex-end; gap: 8px; height: 120px; margin-top: 1rem; }}
  .bar-col {{ flex: 1; display: flex; flex-direction: column; align-items: center; }}
  .bar {{ width: 100%; background: linear-gradient(to top, #3b82f6, #60a5fa); border-radius: 4px 4px 0 0; min-height: 4px; transition: height 0.3s; }}
  .bar-label {{ font-size: 0.7rem; margin-top: 0.3rem; opacity: 0.6; }}
  .bar-value {{ font-size: 0.75rem; margin-bottom: 0.2rem; color: #93c5fd; }}
  .stat-row {{ display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #334155; }}
  .stat-row:last-child {{ border-bottom: none; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Scam Shield</h1>
  <p>AI Agent Deteksi Penipuan Digital — Dashboard Statistik</p>
</div>
<div class="container">
  <div class="cards">
    <div class="card total">
      <div class="number">{stats['total']}</div>
      <div class="label">Total Pengecekan</div>
    </div>
    <div class="card scam">
      <div class="number">{scam_count}</div>
      <div class="label">🔴 Scam Terdeteksi</div>
    </div>
    <div class="card meragukan">
      <div class="number">{meragukan_count}</div>
      <div class="label">🟡 Meragukan</div>
    </div>
    <div class="card aman">
      <div class="number">{aman_count}</div>
      <div class="label">🟢 Aman</div>
    </div>
  </div>

  <div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));">
    <div class="card">
      <div class="number" style="color: #a78bfa;">{stats['users']}</div>
      <div class="label">Pengguna Unik</div>
    </div>
    <div class="card">
      <div class="number" style="color: #38bdf8;">{stats['today']}</div>
      <div class="label">Cek Hari Ini</div>
    </div>
    <div class="card">
      <div class="number" style="color: #fb923c;">{stats['total_patterns']}</div>
      <div class="label">Pola di Database</div>
    </div>
    <div class="card">
      <div class="number" style="color: #4ade80;">{stats['total_reports']}</div>
      <div class="label">Laporan Komunitas</div>
    </div>
  </div>

  <div class="section">
    <h2>📊 Pengecekan 7 Hari Terakhir</h2>
    <div class="bar-chart" id="chart"></div>
  </div>

  <div class="section">
    <h2>🏆 Modus Scam Terbanyak</h2>
    <table>
      <thead><tr><th>#</th><th>Jenis Modus</th><th>Jumlah</th></tr></thead>
      <tbody>{modus_rows if modus_rows else '<tr><td colspan="3" style="text-align:center;opacity:0.5;">Belum ada data</td></tr>'}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>🤝 Kontribusi Komunitas</h2>
    <div class="stat-row">
      <span>Total laporan masuk</span>
      <span>{stats['total_reports']}</span>
    </div>
    <div class="stat-row">
      <span>Pola dari komunitas <span class="badge badge-community">community-sourced</span></span>
      <span>{stats['community_patterns']}</span>
    </div>
  </div>
</div>
<div class="footer">
  Scam Shield &mdash; AI Agent untuk Deteksi Penipuan Digital<br>
  Dibangun dengan AI Hosting IDwebhost &times; Cloud VPS CloudBaik<br>
  Powered by Hermes Agent &mdash; AI HackFest 2026<br>
  Terakhir diperbarui: {datetime.now().strftime('%d %B %Y, %H:%M WIB')}
</div>
<script>
  const labels = {daily_labels};
  const values = {daily_values};
  const maxVal = Math.max(...values, 1);
  const chart = document.getElementById('chart');
  labels.forEach((label, i) => {{
    const col = document.createElement('div');
    col.className = 'bar-col';
    const val = document.createElement('div');
    val.className = 'bar-value';
    val.textContent = values[i];
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.height = Math.max((values[i] / maxVal) * 100, 4) + 'px';
    const lbl = document.createElement('div');
    lbl.className = 'bar-label';
    lbl.textContent = label;
    col.appendChild(val);
    col.appendChild(bar);
    col.appendChild(lbl);
    chart.appendChild(col);
  }});
</script>
</body>
</html>"""


class StatsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = build_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif self.path == "/api/stats":
            stats = get_db_stats()
            # Convert tuples to serializable format
            stats["top_modus"] = [{"modus": m, "count": c} for m, c in stats["top_modus"]]
            stats["daily"] = [{"date": d, "count": c} for d, c in stats["daily"]]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(stats, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        print(f"[StatsServer] {args[0]}")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = HTTPServer(("0.0.0.0", port), StatsHandler)
    print(f"[Scam Shield Stats] Running on http://0.0.0.0:{port}")
    print(f"[Scam Shield Stats] Database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Scam Shield Stats] Stopped")
        server.server_close()
