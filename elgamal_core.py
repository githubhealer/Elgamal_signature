import math
import random
import time
from sympy import mod_inverse

P = 1073741827  # prime no used as group modulus
G = 2           # generator


def generate_keys(p=P, g=G):
    x = random.randint(2, p - 2)       # private key (1<=x<=p-2)
    y = pow(g, x, p)                   # public key: g^x mod p
    return {"p": p, "g": g, "x": x, "y": y}


def sign(message_hash, keys, k):
    p = keys["p"]
    g = keys["g"]
    x = keys["x"]
    q = p - 1
    gcd_k = math.gcd(k, q)

    if gcd_k != 1:  # k inverse does not exist, signature undefined
        return {
            "r": None, "s": None, "k": k, "gcd_k": gcd_k,
            "valid": False, "scenario": "BROKEN",
            "reason": f"gcd(k={k}, p-1={q}) = {gcd_k}, not 1. k inverse mod (p-1) does not exist.",
        }

    r = pow(g, k, p)
    k_inv = mod_inverse(k, q)
    s = (message_hash - x * r) * k_inv % q

    return {
        "r": r, "s": s, "k": k, "gcd_k": gcd_k,
        "valid": True, "scenario": "SECURE",
        "reason": "gcd(k, p-1) = 1. Valid signature produced.",
    }


def verify(message_hash, signature, keys):
    if not signature.get("valid"):
        return False
    p = keys["p"]
    g = keys["g"]
    y = keys["y"]
    r = signature["r"]
    s = signature["s"]
    lhs = pow(g, message_hash, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


def reused_k_attack(m1, sig1, m2, sig2, keys):
    p  = keys["p"]
    g  = keys["g"]
    y  = keys["y"]
    q  = p - 1
    r1, s1 = sig1["r"], sig1["s"]
    r2, s2 = sig2["r"], sig2["s"]

    steps = []
    steps.append(f"  Given: m1={m1}, s1={s1}, r1={r1}")
    steps.append(f"  Given: m2={m2}, s2={s2}, r2={r2}")

    diff_s  = (s1 - s2) % q
    gcd_diff = math.gcd(diff_s, q)
    steps.append(f"\n  Step 1: Recover k")
    steps.append(f"    (s1 - s2) mod (p-1) = {diff_s}")
    steps.append(f"    gcd(s1-s2, p-1)     = {gcd_diff}")

    if gcd_diff != 1:
        steps.append("    Cannot invert (s1-s2). Attack indeterminate for this pair.")
        return {"success": False, "steps": steps}

    diff_s_inv  = mod_inverse(diff_s, q)
    k_recovered = ((m1 - m2) * diff_s_inv) % q
    steps.append(f"    k = (m1-m2) * (s1-s2) inverse mod (p-1) = {k_recovered}")

    steps.append(f"\n  Step 2: Recover private key x")
    gcd_r1 = math.gcd(r1, q)
    if gcd_r1 != 1:
        steps.append("    r1 not invertible mod (p-1). Attack indeterminate.")
        return {"success": False, "steps": steps}

    r1_inv      = mod_inverse(r1, q)
    x_recovered = ((m1 - k_recovered * s1) * r1_inv) % q
    steps.append(f"    x = (m1 - k*s1) * r1 inverse mod (p-1) = {x_recovered}")

    y_check   = pow(g, x_recovered, p)
    x_correct = (y_check == y)
    steps.append(f"    Check: g^x_recovered mod p = {y_check}")
    steps.append(f"    Actual public key y        = {y}")
    steps.append(f"    Private key correctly recovered: {x_correct}")

    m3 = random.randint(10000, 99999)
    steps.append(f"\n  Step 3: Forge signature on new message m3={m3}")
    forged_keys = {**keys, "x": x_recovered}

    k_forge = random.randint(2, q - 2)
    while math.gcd(k_forge, q) != 1:
        k_forge = random.randint(2, q - 2)

    forged_sig = sign(m3, forged_keys, k_forge)
    steps.append(f"    Forged signature: r={forged_sig['r']}, s={forged_sig['s']}")

    verified = verify(m3, forged_sig, {**keys, "y": y})
    steps.append(f"\n  Step 4: Verify forged signature")
    steps.append(f"    g^m3 mod p         = {pow(g, m3, p)}")
    steps.append(f"    y^r * r^s mod p    = {(pow(y, forged_sig['r'], p) * pow(forged_sig['r'], forged_sig['s'], p)) % p}")
    steps.append(f"    Verification result: {'PASSED - Forged signature accepted' if verified else 'FAILED'}")

    return {
        "success": True, "k_recovered": k_recovered,
        "x_recovered": x_recovered, "x_correct": x_correct,
        "m3": m3, "forged_sig": forged_sig, "verified": verified,
        "steps": steps,
    }


_used_k_set = set()

def reset_used_k():
    _used_k_set.clear()

def safe_sign(message_hash, keys):
    p = keys["p"]
    q = p - 1
    attempts = 0
    while True:
        k = random.randint(2, q - 2)
        attempts += 1
        if math.gcd(k, q) == 1 and k not in _used_k_set:
            _used_k_set.add(k)
            sig = sign(message_hash, keys, k)
            sig["attempts"] = attempts
            return sig


def timed_sign(message_hash, keys, k):
    t0  = time.perf_counter()
    sig = sign(message_hash, keys, k)
    sig["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return sig

def timed_safe_sign(message_hash, keys):
    t0  = time.perf_counter()
    sig = safe_sign(message_hash, keys)
    sig["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return sig
