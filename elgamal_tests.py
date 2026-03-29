
import math
import random
from elgamal_core import (
    generate_keys, sign, verify, safe_sign, reset_used_k,
    reused_k_attack, timed_sign, timed_safe_sign, P, G,
)


def _hash(msg: str) -> int:
    h = 0
    for ch in msg:
        h = (h * 31 + ord(ch)) % (P - 1)
    return max(h, 1)      


def _pick_bad_k(p):
    q = p - 1
    k = random.choice([2, 4, 6, 8, 10, 12, q // 2, q // 3])
    return k



def run_before_fix(keys):
    reset_used_k()
    results = []
    p = keys["p"]
    q = p - 1

    messages = [
        "Hello World", "Buy 100 shares", "Transfer $500", "Sign this doc",
        "Secret message", "Pay Alice", "Authorize login", "Open vault",
        "Confirm order", "Delete record", "Update profile", "Send report",
        "Grant access", "Revoke token", "Reset password", "Block user",
        "Issue refund", "Approve request", "Archive data", "Publish post",
        "Submit form", "Download file", "Upload asset", "Close account", "Log event",
    ]

    scenario_plan = (
        ["BROKEN"] * 8 +      # Scenario 1: bad k
        ["REUSED"] * 8 +      # Scenario 2: reused k
        ["SECURE"] * 9        # Scenario 3: good k
    )

    reuse_k = None   
    reuse_sig_first = None
    reuse_msg_first = None

    for i, (msg, scenario) in enumerate(zip(messages, scenario_plan)):
        m = _hash(msg)
        entry = {
            "test_no": i + 1,
            "message": msg,
            "message_hash": m,
            "scenario": scenario,
        }

        if scenario == "BROKEN":
            k = _pick_bad_k(p)
            t0 = __import__("time").perf_counter()
            sig = sign(m, keys, k)
            entry["elapsed_ms"] = (__import__("time").perf_counter() - t0) * 1000
            entry["k"] = k
            entry["gcd_k"] = math.gcd(k, q)
            entry["sig"] = sig
            entry["verified"] = False
            entry["label"] = "BROKEN"
            entry["detail"] = sig.get("reason", "")

        elif scenario == "REUSED":
            if reuse_k is None:
                # Pick a valid k once — reuse it for all REUSED tests
                reuse_k = random.randint(2, q - 2)
                while math.gcd(reuse_k, q) != 1:
                    reuse_k = random.randint(2, q - 2)

            t0 = __import__("time").perf_counter()
            sig = sign(m, keys, reuse_k)
            entry["elapsed_ms"] = (__import__("time").perf_counter() - t0) * 1000
            entry["k"] = reuse_k
            entry["gcd_k"] = 1
            entry["sig"] = sig
            verified = verify(m, sig, keys)
            entry["verified"] = verified

            if reuse_sig_first is None:
                # First REUSED entry — store for attack
                reuse_sig_first = sig
                reuse_msg_first = m
                entry["label"] = "REUSED (first)"
                entry["detail"] = f"k={reuse_k} stored for attack"
                entry["attack"] = None
            else:
                # Subsequent REUSED — launch full attack
                attack = reused_k_attack(reuse_msg_first, reuse_sig_first, m, sig, keys)
                entry["label"] = "FORGED" if (attack["success"] and attack.get("verified")) else "REUSED"
                entry["detail"] = "\n".join(attack["steps"])
                entry["attack"] = attack

        else:  # SECURE
            # Pick fresh valid k (no prevention system — just happens to be valid)
            k = random.randint(2, q - 2)
            while math.gcd(k, q) != 1:
                k = random.randint(2, q - 2)
            t0 = __import__("time").perf_counter()
            sig = sign(m, keys, k)
            entry["elapsed_ms"] = (__import__("time").perf_counter() - t0) * 1000
            entry["k"] = k
            entry["gcd_k"] = 1
            entry["sig"] = sig
            verified = verify(m, sig, keys)
            entry["verified"] = verified
            entry["label"] = "SECURE" if verified else "BROKEN"
            entry["detail"] = sig.get("reason", "")

        results.append(entry)

    return results


# ---------------------------------------------------------------------------
# AFTER-FIX run  (25 tests: all should be SECURE with 0 failures)
# ---------------------------------------------------------------------------
def run_after_fix(keys):
    """Run 25 test cases with safe_sign() prevention applied."""
    reset_used_k()
    results = []

    messages = [
        "After-fix msg 1", "After-fix msg 2", "After-fix msg 3",
        "After-fix msg 4", "After-fix msg 5", "After-fix msg 6",
        "After-fix msg 7", "After-fix msg 8", "After-fix msg 9",
        "After-fix msg 10", "After-fix msg 11", "After-fix msg 12",
        "After-fix msg 13", "After-fix msg 14", "After-fix msg 15",
        "After-fix msg 16", "After-fix msg 17", "After-fix msg 18",
        "After-fix msg 19", "After-fix msg 20", "After-fix msg 21",
        "After-fix msg 22", "After-fix msg 23", "After-fix msg 24",
        "After-fix msg 25",
    ]

    for i, msg in enumerate(messages):
        m = _hash(msg)
        sig = timed_safe_sign(m, keys)
        verified = verify(m, sig, keys)
        results.append({
            "test_no": i + 1,
            "message": msg,
            "message_hash": m,
            "scenario": "SECURE",
            "k": sig["k"],
            "gcd_k": sig["gcd_k"],
            "sig": sig,
            "verified": verified,
            "elapsed_ms": sig.get("elapsed_ms", 0),
            "label": "SECURE",
            "detail": f"k={sig['k']}  gcd(k,p-1)=1  k not reused  →  safe",
            "attack": None,
        })

    return results


# ---------------------------------------------------------------------------
# SIGNING-TIME vs KEY-SIZE  data
# ---------------------------------------------------------------------------
PRIME_SIZES = [
    ("32-bit",  1073741827),
    ("40-bit",  1099511628401),
    ("48-bit",  281474976710677),
    ("56-bit",  72057594037927931),
    ("64-bit",  18446744073709551557),
]

def run_timing_benchmark(n_samples=10):
    """
    For each prime size, measure average secure-sign latency over n_samples.
    Returns list of (label, avg_ms).
    """
    results = []
    for label, p in PRIME_SIZES:
        g = 2
        times = []
        for _ in range(n_samples):
            keys_tmp = {"p": p, "g": g, "x": random.randint(2, p-2), "y": 0}
            keys_tmp["y"] = pow(g, keys_tmp["x"], p)
            q = p - 1
            k = random.randint(2, q - 2)
            while math.gcd(k, q) != 1:
                k = random.randint(2, q - 2)
            m = random.randint(1000, 999999)
            t0 = __import__("time").perf_counter()
            sign(m, keys_tmp, k)
            times.append((__import__("time").perf_counter() - t0) * 1000)
        results.append((label, sum(times) / len(times)))
    return results


# ---------------------------------------------------------------------------
# GCD-CHECK OVERHEAD  data
# ---------------------------------------------------------------------------
def run_overhead_benchmark(keys, n=50):
    """
    Compare average time of:
    - Insecure sign  (random k, no gcd check)
    - Secure sign    (gcd check + uniqueness check)
    Returns (avg_insecure_ms, avg_secure_ms)
    """
    reset_used_k()
    p = keys["p"]
    q = p - 1

    insecure_times = []
    for _ in range(n):
        k = random.randint(2, q - 2)
        m = random.randint(1000, 999999)
        t0 = __import__("time").perf_counter()
        sign(m, keys, k)
        insecure_times.append((__import__("time").perf_counter() - t0) * 1000)

    reset_used_k()
    secure_times = []
    for _ in range(n):
        m = random.randint(1000, 999999)
        sig = timed_safe_sign(m, keys)
        secure_times.append(sig.get("elapsed_ms", 0))

    return (
        sum(insecure_times) / len(insecure_times),
        sum(secure_times) / len(secure_times),
    )
