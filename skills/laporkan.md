---
name: laporkan
description: Laporkan pesan scam ke database komunitas
trigger: /laporkan
---

## Instruksi

Ketika user mengirim `/laporkan <pesan>`, simpan pesan tersebut ke database sebagai laporan scam dari komunitas. 

Langkah:
1. Ambil teks setelah "/laporkan " sebagai isi laporan
2. Simpan ke tabel reports di SQLite dengan timestamp dan user_id
3. Jalankan fuzzy grouping — jika sudah ada ≥3 laporan serupa, ekstrak frasa bersama dan promosikan ke Layer 1
4. Balas ke user dengan konfirmasi laporan diterima
