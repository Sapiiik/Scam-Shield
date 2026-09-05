#!/usr/bin/env python3
"""Penambal inspect_url.py - dua perbaikan Layer 3. Jalankan sekali."""
import re, sys, shutil

NEW_SCORING = '''        # Calculate confidence (berbobot: tiap sinyal tidak sama bahayanya)
        signals = result["suspicious_signals"]

        # Sinyal yang tidak berbahaya bila berdiri sendiri.
        # Hampir semua situs sah punya form login: bank, marketplace, hosting.
        CREDENTIAL_SIGNALS = ("login_form_detected", "password_input_field")

        # Bobot risiko per sinyal (dicocokkan sebagai substring).
        WEIGHTS = (
            ("impersonation", 0.55),
            ("ip_address", 0.35),
            ("punycode", 0.30),
            ("ssl_invalid", 0.25),
            ("invalid_ssl", 0.25),
            ("suspicious_tld", 0.20),
            ("many_redirect", 0.20),
            ("no_https", 0.15),
            ("shortener", 0.15),
            ("redirect", 0.10),
        )
        DEFAULT_WEIGHT = 0.12

        risk = 0.0
        for s in signals:
            if s in CREDENTIAL_SIGNALS:
                continue
            for key, weight in WEIGHTS:
                if key in s:
                    risk += weight
                    break
            else:
                risk += DEFAULT_WEIGHT

        has_credential_form = any(s in CREDENTIAL_SIGNALS for s in signals)
        has_impersonation = any("impersonation" in s for s in signals)

        # Form login baru berbahaya bila halamannya memang sudah mencurigakan:
        # meniru merek, domain aneh, atau tanpa HTTPS. Sendirian, ia netral.
        if has_credential_form:
            if has_impersonation:
                risk = max(risk, 0.95)
            elif risk >= 0.20:
                risk += 0.25

        # Domain mati dalam pesan scam patut diwaspadai, tapi bukan bukti.
        if result.get("error") and result.get("status_code") is None:
            risk = max(risk, 0.40)

        result["confidence"] = round(min(risk, 0.99), 2)

        if result["confidence"] >= 0.75:
            result["verdict_hint"] = "scam"
        elif result["confidence"] >= 0.35:
            result["verdict_hint"] = "meragukan"
        else:
            result["verdict_hint"] = "aman"
'''

OLD_LOGIN = r'r"login|masuk|sign.?in"'
NEW_LOGIN = (r'r"\blogin\b|\bsign.?in\b'
             r'|\bmasuk\s+(ke\s+)?(akun|rekening|internet\s?banking|m.?banking)\b'
             r'|\bkata\s+sandi\b|\bpassword\b"')

path = sys.argv[1] if len(sys.argv) > 1 else "inspect_url.py"
src = open(path, encoding="utf-8").read()
shutil.copy(path, path + ".bak")

done = []

scoring_re = re.compile(r'^[ \t]*# Calculate confidence.*?result\["verdict_hint"\] = "aman"\n', re.S | re.M)
if scoring_re.search(src):
    src = scoring_re.sub(NEW_SCORING, src, count=1)
    done.append("skor berbobot")
else:
    print("! blok skor tidak ditemukan - dilewati")

if OLD_LOGIN in src:
    src = src.replace(OLD_LOGIN, NEW_LOGIN, 1)
    done.append("regex login diperketat")
else:
    print("! pola login tidak ditemukan - dilewati")

open(path, "w", encoding="utf-8").write(src)
print("PATCHED:", ", ".join(done) if done else "tidak ada perubahan")
