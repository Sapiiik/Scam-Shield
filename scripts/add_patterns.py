#!/usr/bin/env python3
"""
Scam Shield - menambal celah Layer 1 hasil analisis test set.

  python3 add_patterns.py           # tampilkan apa yang akan ditambahkan
  python3 add_patterns.py --apply   # tambahkan ke database

Aman dijalankan berulang: pola yang sudah ada tidak diduplikasi.
"""
import os
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(PROJECT_DIR, "data", "scamshield.db")

PATTERNS = [
    ("kode otp",                    "phishing", 0.85),
    ("otp anda",                    "phishing", 0.85),
    ("kode verifikasi",             "phishing", 0.8),
    ("kirimkan kode",               "phishing", 0.85),
    ("minta kode",                  "phishing", 0.8),
    ("validasi data nasabah",       "phishing", 0.85),
    ("verifikasi data nasabah",     "phishing", 0.85),
    ("6 digit",                     "phishing", 0.6),

    (".apk",                        "malware",  0.9),
    ("aplikasi ini untuk cek",      "malware",  0.7),

    ("tanpa bi checking",           "pinjol_ilegal", 0.85),
    ("tanpa jaminan langsung cair", "pinjol_ilegal", 0.8),
    ("langsung cair tanpa",         "pinjol_ilegal", 0.75),
    ("kirim foto ktp",              "pinjol_ilegal", 0.7),
    ("foto ktp dan swafoto",        "pinjol_ilegal", 0.8),

    ("isi saldo",                   "penipuan_kerja", 0.75),
    ("tugas berbayar",              "penipuan_kerja", 0.75),
    ("dibayar per tugas",           "penipuan_kerja", 0.75),
    ("cukup like video",            "penipuan_kerja", 0.8),
    ("hanya like video",            "penipuan_kerja", 0.8),
    ("kerja dari rumah gaji harian","penipuan_kerja", 0.7),

    ("hp ku hilang",                "impersonasi", 0.8),
    ("hp saya hilang",              "impersonasi", 0.8),
    ("hp aku hilang",               "impersonasi", 0.8),
    ("ini nomor baruku",            "impersonasi", 0.7),
    ("ini nomor baru saya",         "impersonasi", 0.65),
    ("tolong transfer sekarang",    "impersonasi", 0.75),

    ("saya dari kepolisian",        "impersonasi", 0.8),
    ("dari pihak kepolisian",       "impersonasi", 0.8),
    ("penyelesaian damai",          "impersonasi", 0.85),
    ("anak anda terlibat",          "impersonasi", 0.85),
    ("keluarga anda terlibat",      "impersonasi", 0.85),

    ("tertahan bea cukai",          "love_scam", 0.85),
    ("tertahan di bea cukai",       "love_scam", 0.85),
    ("kiriman dari luar negeri",    "love_scam", 0.7),
    ("hadiah dari luar negeri",     "love_scam", 0.75),

    ("sinyal akurat",               "investasi_bodong", 0.8),
    ("profit dijamin",              "investasi_bodong", 0.85),
    ("dijamin profit",              "investasi_bodong", 0.85),
    ("grup vip",                    "investasi_bodong", 0.65),
    ("setor minimal",               "investasi_bodong", 0.7),
    ("balik modal",                 "investasi_bodong", 0.6),
    ("robot trading",               "investasi_bodong", 0.8),
]


def main():
    apply = "--apply" in sys.argv

    if not os.path.exists(DB_PATH):
        print(f"Database tidak ditemukan: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("PRAGMA table_info(scam_patterns)")
    cols = [r[1] for r in c.fetchall()]
    if not cols:
        print("Tabel scam_patterns tidak ditemukan.")
        sys.exit(1)

    use = [col for col in ("type", "pattern", "modus", "source", "confidence") if col in cols]
    placeholders = ", ".join("?" * len(use))
    sql = f"INSERT OR IGNORE INTO scam_patterns ({', '.join(use)}) VALUES ({placeholders})"

    c.execute("SELECT COUNT(*) FROM scam_patterns")
    before = c.fetchone()[0]

    c.execute("SELECT LOWER(pattern) FROM scam_patterns")
    existing = {r[0] for r in c.fetchall()}

    to_add = [p for p in PATTERNS if p[0].lower() not in existing]

    print(f"Pola di database saat ini : {before}")
    print(f"Kandidat pola baru        : {len(PATTERNS)}")
    print(f"Belum ada, akan ditambah  : {len(to_add)}\n")

    by_modus = {}
    for pat, modus, conf in to_add:
        by_modus.setdefault(modus, []).append(pat)
    for modus in sorted(by_modus):
        print(f"  {modus}")
        for pat in by_modus[modus]:
            print(f"    - {pat}")

    if not apply:
        print("\nBelum ada yang diubah. Jalankan dengan --apply untuk menambahkan.")
        conn.close()
        return

    values = {"type": "keyword", "source": "curated"}
    for pat, modus, conf in to_add:
        values["pattern"] = pat
        values["modus"] = modus
        values["confidence"] = conf
        c.execute(sql, tuple(values[col] for col in use))

    conn.commit()
    c.execute("SELECT COUNT(*) FROM scam_patterns")
    after = c.fetchone()[0]
    conn.close()

    print(f"\nSelesai. Pola bertambah dari {before} menjadi {after}.")


if __name__ == "__main__":
    main()
