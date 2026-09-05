#!/usr/bin/env python3
"""
Scam Shield - penguji test set Layer 1.

  python3 run_testset.py           # uji saja, database tidak disentuh
  python3 run_testset.py --log     # uji dan catat hasilnya ke database

Ini mengukur Layer 1 (pencocokan pola) saja. Layer 1 adalah penyaring awal,
jadi verdict "meragukan" sudah dihitung berhasil menandai. Keputusan akhir
tetap gabungan tiga layer di agent.
"""
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(SCRIPT_DIR, "check_patterns.py")
LOGGER = os.path.join(SCRIPT_DIR, "log_check.py")
TESTSET = os.path.join(SCRIPT_DIR, "testset.json")

FLAGGED = ("scam", "meragukan")
TEST_USER = "testset"


def run_check(text):
    proc = subprocess.run(
        [sys.executable, CHECK, text],
        capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:200]
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, "keluaran bukan JSON: " + proc.stdout.strip()[:120]


def log_result(case, result):
    modus_list = result.get("suspected_modus") or []
    modus = modus_list[0] if modus_list else (case.get("modus") or "lainnya")
    subprocess.run([
        sys.executable, LOGGER,
        TEST_USER,
        case["text"][:50],
        result.get("verdict_hint", "aman"),
        str(result.get("confidence", 0.0)),
        modus,
        '["layer1"]',
    ], capture_output=True, text=True, timeout=60)


def main():
    do_log = "--log" in sys.argv
    cases = json.load(open(TESTSET, encoding="utf-8"))["cases"]

    hits = misses = false_pos = true_neg = errors = 0
    miss_list, fp_list = [], []

    print(f"{'ID':>3}  {'HARAP':<6} {'HASIL':<10} {'CONF':>5}  PESAN")
    print("-" * 78)

    for case in cases:
        result, err = run_check(case["text"])
        if err:
            errors += 1
            print(f"{case['id']:>3}  {case['expect']:<6} {'ERROR':<10} {'--':>5}  {err}")
            continue

        verdict = result.get("verdict_hint", "aman")
        conf = result.get("confidence", 0.0)
        flagged = verdict in FLAGGED

        if case["expect"] == "scam":
            if flagged:
                hits += 1
                mark = "ok"
            else:
                misses += 1
                mark = "LOLOS"
                miss_list.append(case)
        else:
            if flagged:
                false_pos += 1
                mark = "SALAH TUDUH"
                fp_list.append(case)
            else:
                true_neg += 1
                mark = "ok"

        print(f"{case['id']:>3}  {case['expect']:<6} {verdict:<10} {conf:>5}  {mark:<12} {case['text'][:38]}")

        if do_log:
            log_result(case, result)

    total_scam = hits + misses
    total_aman = false_pos + true_neg

    print("\n" + "=" * 78)
    print("RINGKASAN LAYER 1")
    print("=" * 78)
    if total_scam:
        print(f"  Pesan scam ditandai      : {hits}/{total_scam}  ({hits/total_scam*100:.0f}%)")
    if total_aman:
        print(f"  Pesan sah tidak diganggu : {true_neg}/{total_aman}  ({true_neg/total_aman*100:.0f}%)")
    if errors:
        print(f"  Error                    : {errors}")

    if miss_list:
        print("\n  Lolos Layer 1 (diserahkan ke Layer 2 LLM):")
        for c in miss_list:
            print(f"    #{c['id']} [{c['modus']}] {c['text'][:60]}")

    if fp_list:
        print("\n  SALAH TUDUH - perlu diperbaiki:")
        for c in fp_list:
            print(f"    #{c['id']} {c['text'][:60]}")

    if do_log:
        print(f"\n  {len(cases)} hasil dicatat ke database. Dashboard sudah terisi.")
    else:
        print("\n  Database tidak disentuh. Tambahkan --log untuk mencatat hasilnya.")


if __name__ == "__main__":
    main()
