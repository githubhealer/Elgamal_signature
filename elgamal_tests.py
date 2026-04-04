
import math
import random
from elgamal_core import (
    generate_keys, sign, verify, safe_sign, reset_used_k,
    reused_k_attack, timed_sign, timed_safe_sign, P, Q, G,
)


def _hash(msg: str):
    h = 0
    for ch in msg:
        h = (h * 31 + ord(ch)) % Q
    return max(h, 1)


def _pick_bad_k(_p=None):
    choices = [Q, 2 * Q, 3 * Q, Q + Q // 2]
    return random.choice(choices)



def run_before_fix(keys):
    reset_used_k()
    results = []
    p = keys["p"]
    q = Q

    messages = [
        "Hello World", "Buy 100 shares", "Transfer $500", "Sign this doc",
        "Secret message", "Pay Alice", "Authorize login", "Open vault",
        "Confirm order", "Delete record", "Update profile", "Send report",
        "Grant access", "Revoke token", "Reset password", "Block user",
        "Issue refund", "Approve request", "Archive data", "Publish post",
        "Submit form", "Download file", "Upload asset", "Close account", "Log event",
        "Hello World", "Buy 100 shares", "Transfer $500", "Sign this doc",
        "Secret message", "Pay Alice", "Authorize login", "Open vault",
        "Confirm order", "Delete record", "Update profile", "Send report",
        "Grant access", "Revoke token", "Reset password", "Block user",
        "Issue refund", "Approve request", "Archive data", "Publish post",
        "Submit form", "Download file", "Upload asset", "Close account", "Log event",
    ]

    scenario_plan = (
        ["BROKEN"] * 25 +
        ["REUSED"] * 25
    )
    random.shuffle(scenario_plan)
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
                reuse_k = random.randint(2, Q - 2)
                while math.gcd(reuse_k, Q) != 1:
                    reuse_k = random.randint(2, Q - 2)

            t0 = __import__("time").perf_counter()
            sig = sign(m, keys, reuse_k)
            entry["elapsed_ms"] = (__import__("time").perf_counter() - t0) * 1000
            entry["k"] = reuse_k
            entry["gcd_k"] = 1
            entry["sig"] = sig
            verified = verify(m, sig, keys)
            entry["verified"] = verified

            if reuse_sig_first is None:
                reuse_sig_first = sig
                reuse_msg_first = m
                entry["label"] = "REUSED (first)"
                entry["detail"] = f"k={reuse_k} stored for attack"
                entry["attack"] = None
            else:
                attack = reused_k_attack(reuse_msg_first, reuse_sig_first, m, sig, keys)
                entry["label"] = "FORGED" if (attack["success"] and attack.get("verified")) else "REUSED"
                entry["detail"] = "\n".join(attack["steps"])
                entry["attack"] = attack

        else:
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


def run_after_fix(keys):
    reset_used_k()
    results = []

    messages = [
        "Hello World", "Buy 100 shares", "Transfer $500", "Sign this doc",
        "Secret message", "Pay Alice", "Authorize login", "Open vault",
        "Confirm order", "Delete record", "Update profile", "Send report",
        "Grant access", "Revoke token", "Reset password", "Block user",
        "Issue refund", "Approve request", "Archive data", "Publish post",
        "Submit form", "Download file", "Upload asset", "Close account", "Log event",
        "Hello World", "Buy 100 shares", "Transfer $500", "Sign this doc",
        "Secret message", "Pay Alice", "Authorize login", "Open vault",
        "Confirm order", "Delete record", "Update profile", "Send report",
        "Grant access", "Revoke token", "Reset password", "Block user",
        "Issue refund", "Approve request", "Archive data", "Publish post",
        "Submit form", "Download file", "Upload asset", "Close account", "Log event",
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
            "detail": f"k={sig['k']}  gcd(k,Q)=1  k not reused  →  safe",
            "attack": None,
        })

    return results


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
