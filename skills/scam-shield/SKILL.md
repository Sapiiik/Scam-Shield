---
name: scam-shield
description: Analyze forwarded messages and links for scam detection
version: 1.0.0
platforms: [linux]
metadata:
  hermes:
    tags: [security, scam-detection, indonesia, telegram]
    category: security
---

# Scam Shield — Deteksi Pesan Scam

## When to Use

Gunakan skill ini ketika:
- User mengirim atau forward pesan dan bertanya apakah itu scam
- User mengirim link mencurigakan untuk dicek
- User bertanya tentang modus penipuan tertentu
- User ingin melaporkan scam (gunakan alur laporan komunitas)
- User mengetik /cek, /check, /periksa, atau /laporkan

## Procedure

### Langkah 1: Analisis Gabungan (Layer 1 + Layer 3)

Jalankan SATU perintah ini. Script sudah menangani pencocokan pola dan inspeksi
URL sekaligus, jadi JANGAN memanggil check_patterns.py atau inspect_url.py terpisah.

```bash
python3 ~/scam-shield/scripts/analyze.py "<PESAN_USER>"
```

Baca output JSON-nya:
- `layer1.matches` - pola yang cocok di database
- `layer1.suspected_modus` - jenis modus terdeteksi
- `layer3` - hasil inspeksi tiap URL: `redirect_chain`, `page_title`,
  `suspicious_signals`, `ssl_valid`, `confidence`
- `preliminary_confidence` - confidence tertinggi dari Layer 1 dan Layer 3
- `errors` - kalau ada, sebutkan keterbatasannya di respons

### Langkah 2: Layer 2 - Analisis Konten LLM

Analisis sendiri isi pesan tersebut. Pertimbangkan:
- Apakah ada janji keuntungan yang tidak realistis?
- Apakah ada tekanan waktu / urgency palsu?
- Apakah ada permintaan data pribadi, OTP, atau transfer uang?
- Apakah bahasa/format pesan mirip pola scam yang umum?
- Apakah pengirim mengatasnamakan institusi resmi tapi cara komunikasinya tidak profesional?
- Apakah ada inkonsistensi dalam pesan (nama berbeda, nomor aneh, dll)?

Berikan assessment independen, jangan sekadar mengikuti angka dari Langkah 1.
Banyak scam tidak memakai kata kunci yang ada di database - di situlah Layer 2
menjadi penentu.

### Langkah 3: Tentukan Verdict

Gabungkan `preliminary_confidence` dengan penilaianmu sendiri:
- Salah satu sumber >= 0.85 -> **🔴 Scam**
- Rata-rata >= 0.60 -> **🔴 Scam**
- Rata-rata >= 0.35 -> **🟡 Meragukan**
- Semua < 0.35 -> **🟢 Aman**

### Langkah 4: Log Hasil

```bash
python3 ~/scam-shield/scripts/log_check.py "<USER_ID>" "<50_CHAR_PREVIEW>" "<verdict>" "<confidence>" "<modus>" '["layer1","layer2","layer3"]'
```

### Langkah 5: Format Respons### Langkah 6: Format Respons

Kirim respons dengan format ini:

```
🛡️ SCAM SHIELD — Hasil Analisis

[EMOJI_VERDICT] Verdict: [VERDICT]
📊 Tingkat keyakinan: [CONFIDENCE]%

📋 Jenis modus: [MODUS_LABEL]

💡 Alasan:
[PENJELASAN_BAHASA_AWAM]

🔒 Tips perlindungan:
- [TIP_1]
- [TIP_2]
- [TIP_3]

⚠️ Disclaimer: Ini adalah alat bantu analisis otomatis, bukan putusan hukum. Jika ragu, jangan klik link atau transfer uang, dan hubungi pihak resmi terkait.

💬 Mau laporkan pesan ini sebagai scam? Ketik: /laporkan
```

## Alur Laporan Komunitas

Ketika user mengetik /laporkan atau ingin melaporkan scam:

1. Tanyakan: "Apa isi pesan scam yang ingin dilaporkan?"
2. Tanyakan: "Apakah ada link, nomor telepon, atau nomor rekening yang terlibat?"
3. Jalankan:
   ```bash
   python3 ~/scam-shield/scripts/report_scam.py submit "<USER_ID>" "<TEXT>" "<URL>" "<PHONE>" "<ACCOUNT>" "<MODUS>"
   ```
4. Informasikan ke user bahwa laporan diterima dan akan membantu melindungi pengguna lain.

## Alur Statistik

Ketika user bertanya tentang statistik atau mengetik /stats:

```bash
python3 ~/scam-shield/scripts/get_stats.py summary
```

Format hasilnya secara ringkas dan menarik.

## Tips Per Modus

### Investasi Bodong
- Tidak ada investasi yang menjamin profit 100%
- Cek legalitas di OJK sebelum investasi
- Jangan transfer ke rekening pribadi

### Phishing
- Jangan pernah bagikan OTP ke siapa pun
- Bank resmi tidak pernah minta data via chat
- Cek URL dengan teliti sebelum login

### Kurir Palsu
- Kurir resmi tidak pernah minta transfer untuk paket
- Cek resi di website resmi jasa pengiriman
- Jangan klik link dari nomor tidak dikenal

### Hadiah Palsu
- Undian resmi tidak minta biaya admin
- Cek langsung ke penyelenggara resmi
- Jangan bagikan data pribadi

### Pinjaman Ilegal
- Cek legalitas di OJK
- Pinjaman resmi tidak menawarkan lewat SMS/WA
- Waspadai bunga yang tidak wajar

### Impersonasi
- Verifikasi langsung ke orang yang bersangkutan lewat nomor lama
- Jangan langsung transfer tanpa konfirmasi suara/video call
- Waspadai permintaan darurat yang memaksa

## Pitfalls
- Jangan pernah mengklik URL yang diforward user dari browser agent — selalu gunakan inspect_url.py
- Jangan simpan pesan lengkap user di log — hanya 50 karakter pertama untuk privasi
- Jangan terlalu percaya diri: selalu tunjukkan confidence level
- Jangan menuduh pengirim pesan — fokus pada konten pesan saja

## Verification
- Cek bahwa verdict diberikan (🟢🟡🔴)
- Cek bahwa alasan ditulis dalam bahasa awam
- Cek bahwa disclaimer ada di respons
- Cek bahwa log_check.py berhasil dijalankan
