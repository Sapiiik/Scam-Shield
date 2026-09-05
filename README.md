<p align="center">
  <img src="bot-avatar.png" width="150" alt="Scam Shield Logo">
</p>

<h1 align="center">Scam Shield</h1>

<p align="center">
  <b>AI Agent Telegram untuk Deteksi Penipuan Digital Indonesia</b><br>
  <i>Dibangun dengan Hermes Agent + Gemini 3.6 Flash</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/LLM-Gemini_3.6_Flash-orange?logo=google&logoColor=white" alt="Gemini">
  <img src="https://img.shields.io/badge/Platform-Telegram-26A5E4?logo=telegram&logoColor=white" alt="Telegram">
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

---

## Tentang

**Scam Shield** adalah AI Agent berbasis *agentic AI* pada Telegram yang mendeteksi penipuan digital secara real-time. Cukup forward pesan mencurigakan ke bot — tanpa perlu memahami teknis keamanan siber — dan dapatkan analisis lengkap dalam hitungan detik.

Dibangun untuk kompetisi **AI HackFest 2026** (IDwebhost × PANDI), kategori *Digital Safety & Public Good*.

## Fitur Utama

- **Deteksi 3-Layer Pipeline**
  - Layer 1: Pattern matching (regex + SQLite) — < 0,1 detik
  - Layer 2: Analisis semantik via LLM (Gemini 3.6 Flash)
  - Layer 3: Inspeksi URL (domain, redirect, brand similarity)
- **Verdict Lengkap** — 🔴 Scam / 🟡 Meragukan / 🟢 Aman dengan alasan, tips, dan confidence
- **Laporan Komunitas** — `/laporkan` untuk melaporkan pesan scam
- **Auto-Promote Pattern** — 3+ laporan serupa → pola baru otomatis masuk database deteksi
- **Dashboard Statistik** — halaman web untuk melihat data pengecekan
- **7 Modus Terdeteksi** — hadiah palsu, phishing, investasi bodong, pinjol ilegal, kurir palsu, penipuan kerja, impersonasi

## Arsitektur

```
User (Telegram)
    │
    ▼
┌─────────────────────────────────────┐
│         Scam Shield System          │
│                                     │
│  ┌───────────┐   Pattern cocok?     │
│  │  Layer 1  │──── Ya ──→ SCAM      │
│  │  Pattern  │                      │
│  │  Matching │──── Tidak            │
│  └───────────┘      │               │
│                     ▼               │
│  ┌───────────┐                      │
│  │  Layer 2  │  Analisis semantik   │
│  │  LLM      │  (Gemini 3.6 Flash) │
│  └───────────┘                      │
│        │                            │
│        ▼                            │
│  ┌───────────┐                      │
│  │  Layer 3  │  URL Inspection      │
│  │  URL      │  (Domain + Redirect) │
│  └───────────┘                      │
│        │                            │
│        ▼                            │
│  ┌───────────┐                      │
│  │  Verdict  │──→ Output + Log      │
│  │  Engine   │                      │
│  └───────────┘                      │
└─────────────────────────────────────┘
```

## Struktur Proyek

```
scam-shield/
├── SOUL.md                    # Kepribadian dan instruksi bot
├── skills/
│   ├── scam-shield/
│   │   └── SKILL.md           # Skill utama (analisis pesan)
│   └── laporkan.md            # Skill /laporkan
├── scripts/
│   ├── analyze.py             # Pipeline analisis Layer 1 + Layer 3
│   ├── inspect_url.py         # Inspeksi URL (Layer 3)
│   ├── report_scam.py         # Sistem laporan komunitas + fuzzy grouping
│   ├── setup_db.py            # Inisialisasi database SQLite
│   ├── add_patterns.py        # Tambah pola deteksi ke database
│   ├── get_stats.py           # Ambil statistik pengecekan
│   ├── stats_server.py        # Flask dashboard statistik
│   ├── run_testset.py         # Runner test set otomatis
│   ├── testset.json           # 32 test case (7 modus + 8 normal)
│   └── log_check.py           # Logger pengecekan
├── data/
│   └── seed_patterns.json     # Pola awal database deteksi
└── .gitignore
```

## Tech Stack

| Komponen | Teknologi |
|---|---|
| Framework AI | [Hermes Agent](https://github.com/NousResearch) (MIT License) |
| LLM | Google Gemini 3.6 Flash |
| Bahasa | Python 3.11 |
| Database | SQLite |
| Bot Platform | Telegram Bot API |
| Dashboard | Flask |
| Hosting | [Cloud VPS](https://cloudbaik.com/) CloudBaik via [AI Hosting](https://idwebhost.com/ai-hosting/) IDwebhost |

## Setup

### Prasyarat

- VPS dengan Python 3.11+
- [Hermes Agent](https://github.com/NousResearch) terinstall
- Telegram Bot Token (dari [@BotFather](https://t.me/BotFather))
- Google Gemini API Key

### Instalasi

```bash
# Clone repo
git clone https://github.com/Sapiiik/scam-shield.git
cd scam-shield

# Setup database
python3 scripts/setup_db.py

# Tambahkan pola deteksi awal
python3 scripts/add_patterns.py --apply

# Copy skills ke Hermes
mkdir -p ~/.hermes/skills/scam-shield
cp skills/scam-shield/SKILL.md ~/.hermes/skills/scam-shield/
mkdir -p ~/.hermes/skills/laporkan
cp skills/laporkan.md ~/.hermes/skills/laporkan/SKILL.md

# Copy SOUL.md
cp SOUL.md ~/.hermes/SOUL.md

# Restart Hermes Gateway
hermes gateway restart
```

### Menjalankan Dashboard

```bash
python3 scripts/stats_server.py
# Akses di http://localhost:5000
```

## Hasil Pengujian

| Metrik | Nilai |
|---|---|
| Total test case | 32 |
| Modus diuji | 7 kategori |
| Pesan normal (kontrol) | 8 |
| Deteksi scam (Layer 1) | **96%** |
| False positive | **0%** |
| Waktu respons | **10–25 detik** |

## Cara Pakai

1. Cari **@ScamShieldBot** di Telegram (atau bot yang kamu deploy)
2. Forward pesan mencurigakan ke bot
3. Tunggu verdict (10–25 detik)
4. Untuk melaporkan scam: `/laporkan <isi pesan scam>`

## Artikel

Baca artikel lengkap: [Deteksi Penipuan Digital Menggunakan Agentic AI](https://medium.com/@absyfq/deteksi-penipuan-digital-menggunakan-agentic-ai-implementasi-scam-shield-pada-platform-telegram-9c5a69a807da)

## Lisensi

MIT License — bebas digunakan, dimodifikasi, dan didistribusikan.

---

<p align="center">
  Dibangun untuk <b>AI HackFest 2026</b> (IDwebhost × PANDI)<br>
  Kategori: Digital Safety & Public Good
</p>
