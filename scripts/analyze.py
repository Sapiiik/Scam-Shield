#!/usr/bin/env python3
"""
Scam Shield - analisis gabungan Layer 1 + Layer 3 dalam satu panggilan.

  python3 analyze.py "<pesan user>"

Menggabungkan dua panggilan script jadi satu memangkas jumlah panggilan API
kira-kira setengah - lebih cepat, dan jauh lebih kecil kemungkinannya menabrak
batas kuota provider. Layer 2 tetap dikerjakan agent sendiri dari hasil ini.
"""
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(SCRIPT_DIR, "check_patterns.py")
INSPECT = os.path.join(SCRIPT_DIR, "inspect_url.py")

MAX_URLS = 2
URL_TIMEOUT = 25
URL_RE = re.compile(r'https?://[^\s<>"\')]+', re.I)


def run_json(cmd, timeout):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if proc.returncode != 0:
        return None, (proc.stderr.strip()[:200] or f"exit {proc.returncode}")
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, "keluaran bukan JSON: " + proc.stdout.strip()[:120]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": 'Usage: python3 analyze.py "<pesan>"'}))
        sys.exit(1)

    text = sys.argv[1]
    out = {
        "message_preview": text[:80],
        "layer1": None,
        "layer3": [],
        "urls_checked": 0,
        "preliminary_confidence": 0.0,
        "preliminary_verdict": "aman",
        "errors": [],
        "note": "Layer 2 (analisis isi oleh LLM) belum dihitung di sini - lakukan sendiri.",
    }

    layer1, err = run_json([sys.executable, CHECK, text], 60)
    if err:
        out["errors"].append(f"layer1: {err}")
    else:
        out["layer1"] = layer1

    urls = []
    if layer1:
        urls = list(layer1.get("urls_found") or [])
    if not urls:
        urls = URL_RE.findall(text)

    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
    urls = seen[:MAX_URLS]

    for url in urls:
        result, err = run_json([sys.executable, INSPECT, url], URL_TIMEOUT + 10)
        if err:
            out["errors"].append(f"layer3 {url}: {err}")
            continue
        out["layer3"].append(result)

    out["urls_checked"] = len(out["layer3"])

    confidences = []
    if layer1:
        confidences.append(float(layer1.get("confidence") or 0))
    for r in out["layer3"]:
        confidences.append(float(r.get("confidence") or 0))

    if confidences:
        out["preliminary_confidence"] = round(max(confidences), 2)

    conf = out["preliminary_confidence"]
    out["preliminary_verdict"] = "scam" if conf >= 0.75 else ("meragukan" if conf >= 0.35 else "aman")

    if layer1 and layer1.get("suspected_modus"):
        out["suspected_modus"] = layer1["suspected_modus"]

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
