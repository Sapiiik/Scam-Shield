#!/usr/bin/env python3
"""
Scam Shield — Layer 3: URL Inspector
Usage: python3 inspect_url.py "<url>"

Fetches URL safely from VPS (not user device), analyzes redirect chain,
page title, and domain reputation. Returns JSON analysis.
"""

import json
import re
import sys
import os
import ssl
import socket
from urllib.request import urlopen, Request
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError
from http.client import HTTPException

# Safety limits
MAX_REDIRECTS = 5
TIMEOUT = 10  # seconds
MAX_CONTENT = 50000  # bytes to read

def inspect_url(url):
    """Inspect URL safely: check redirects, page content, domain info."""
    result = {
        "layer": 3,
        "original_url": url,
        "final_url": None,
        "redirect_chain": [],
        "redirect_count": 0,
        "domain": None,
        "tld": None,
        "page_title": None,
        "status_code": None,
        "is_https": False,
        "ssl_valid": False,
        "suspicious_signals": [],
        "confidence": 0.0,
        "verdict_hint": "aman",
        "error": None
    }

    try:
        parsed = urlparse(url)
        result["domain"] = parsed.netloc.lower()
        result["tld"] = parsed.netloc.split(".")[-1].lower() if "." in parsed.netloc else ""
        result["is_https"] = parsed.scheme.lower() == "https"

        # Follow redirects manually to track chain
        current_url = url
        visited = set()

        for i in range(MAX_REDIRECTS + 1):
            if current_url in visited:
                result["suspicious_signals"].append("redirect_loop")
                break
            visited.add(current_url)

            try:
                req = Request(current_url, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; ScamShield/1.0; security-check)",
                    "Accept": "text/html,application/xhtml+xml",
                })

                # Disable auto-redirect to track chain
                import urllib.request
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)
                response = opener.open(req, timeout=TIMEOUT)
                result["status_code"] = response.status
                result["final_url"] = current_url
                break

            except HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    new_url = e.headers.get("Location", "")
                    if new_url:
                        # Handle relative redirects
                        if new_url.startswith("/"):
                            p = urlparse(current_url)
                            new_url = f"{p.scheme}://{p.netloc}{new_url}"
                        result["redirect_chain"].append({
                            "from": current_url,
                            "to": new_url,
                            "code": e.code
                        })
                        current_url = new_url
                        continue
                result["status_code"] = e.code
                result["final_url"] = current_url
                break
            except (URLError, HTTPException, socket.timeout, ssl.SSLError) as e:
                result["error"] = str(e)[:200]
                break

        result["redirect_count"] = len(result["redirect_chain"])

        # Fetch page content for title
        if result["final_url"] and not result["error"]:
            try:
                req = Request(result["final_url"], headers={
                    "User-Agent": "Mozilla/5.0 (compatible; ScamShield/1.0; security-check)",
                })
                ctx = ssl.create_default_context()
                try:
                    response = urlopen(req, timeout=TIMEOUT, context=ctx)
                    result["ssl_valid"] = True
                except ssl.SSLCertVerificationError:
                    result["ssl_valid"] = False
                    result["suspicious_signals"].append("invalid_ssl_cert")
                    ctx = ssl._create_unverified_context()
                    response = urlopen(req, timeout=TIMEOUT, context=ctx)

                content = response.read(MAX_CONTENT).decode("utf-8", errors="ignore")

                # Extract title
                title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["page_title"] = title_match.group(1).strip()[:200]

                # Check for suspicious content
                suspicious_content_patterns = [
                    (r"\blogin\b|\bsign.?in\b|\bmasuk\s+(ke\s+)?(akun|rekening|internet\s?banking|m.?banking)\b|\bkata\s+sandi\b|\bpassword\b", "login_form_detected"),
                    (r"password|kata.?sandi", "password_field_detected"),
                    (r"kartu.?kredit|credit.?card|CVV|CVC", "credit_card_form"),
                    (r"OTP|kode.?verifikasi|verification.?code", "otp_request"),
                    (r"transfer|kirim.?uang|bayar.?sekarang", "payment_request"),
                    (r"<input[^>]*type=[\"']password[\"']", "password_input_field"),
                ]
                for pattern, signal in suspicious_content_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result["suspicious_signals"].append(signal)

            except Exception as e:
                if not result["error"]:
                    result["error"] = f"Content fetch: {str(e)[:100]}"

        # Check SSL
        if result["is_https"] and result["domain"]:
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=result["domain"]) as s:
                    s.settimeout(5)
                    s.connect((result["domain"], 443))
                    result["ssl_valid"] = True
            except (ssl.SSLError, socket.error, OSError):
                result["ssl_valid"] = False
                if "invalid_ssl_cert" not in result["suspicious_signals"]:
                    result["suspicious_signals"].append("ssl_connection_failed")

        # Analyze suspicious signals
        suspicious_tlds = ["xyz", "top", "club", "buzz", "tk", "ml", "ga", "cf", "gq",
                          "pw", "cc", "click", "link", "win", "loan", "racing"]
        if result["tld"] in suspicious_tlds:
            result["suspicious_signals"].append(f"suspicious_tld_{result['tld']}")

        if result["redirect_count"] >= 3:
            result["suspicious_signals"].append("excessive_redirects")

        if not result["is_https"]:
            result["suspicious_signals"].append("no_https")

        # Check if domain tries to impersonate known brands
        brand_impersonation = [
            "bri", "bca", "mandiri", "bni", "dana", "gopay", "ovo",
            "shopee", "tokopedia", "lazada", "bukalapak", "grab",
            "gojek", "telkomsel", "indosat", "xl"
        ]
        if result["domain"]:
            for brand in brand_impersonation:
                if brand in result["domain"] and not result["domain"].endswith(f".{brand}.co.id") and not result["domain"].endswith(f".{brand}.com") and not result["domain"].endswith(f".{brand}.id"):
                    result["suspicious_signals"].append(f"possible_brand_impersonation_{brand}")

        # Calculate confidence (berbobot: tiap sinyal tidak sama bahayanya)
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

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 inspect_url.py \"<url>\"")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = "https://" + url

    result = inspect_url(url)
    print(json.dumps(result, indent=2, ensure_ascii=False))
