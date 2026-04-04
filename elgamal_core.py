import math
import random
import time
from sympy import isprime, mod_inverse


def generate_params(bit_length: int = 29):
    while True:
        q_candidate = random.getrandbits(bit_length) | (1 << (bit_length - 1)) | 1
        if not isprime(q_candidate):
            continue
        p_candidate = 2 * q_candidate + 1
        if not isprime(p_candidate):
            continue
        while True:
            h = random.randint(2, p_candidate - 2)
            g_candidate = pow(h, 2, p_candidate)
            if g_candidate != 1:
                return q_candidate, p_candidate, g_candidate


Q, P, G = generate_params()


def generate_keys(p=None, g=None):
    if p is None:
        p = P
    if g is None:
        g = G
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}


def sign(message_hash, keys, k):
    p = keys["p"]
    g = keys["g"]
    x = keys["x"]
    q = Q
    gcd_k = math.gcd(k, q)

    if gcd_k != 1:
        return {
            "r": None, "s": None, "k": k, "gcd_k": gcd_k,
            "valid": False, "scenario": "BROKEN",
            "reason": f"gcd(k={k}, Q={q}) = {gcd_k}, not 1. k inverse mod Q does not exist.",
        }

    r = pow(g, k, p)
    k_inv = mod_inverse(k, q)
    s = (message_hash - x * r) * k_inv % q

    return {
        "r": r, "s": s, "k": k, "gcd_k": gcd_k,
        "valid": True, "scenario": "SECURE",
        "reason": "gcd(k, Q) = 1. Valid signature produced.",
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
    q  = Q
    r, s1 = sig1["r"], sig1["s"]
    s2    = sig2["s"]

    steps = []
    steps.append(f"  ElGamal signing equation: s = k_inv * (m - x*r) mod Q")
    steps.append(f"  Both messages signed with the same k, so r is identical: r = {r}")
    steps.append(f"  sig1: m1={m1}, s1={s1}")
    steps.append(f"  sig2: m2={m2}, s2={s2}")

    diff_s   = (s1 - s2) % q
    gcd_diff = math.gcd(diff_s, q)
    steps.append(f"\n  Step 1: Recover k")
    steps.append(f"    s1 - s2 = k_inv*(m1-m2) mod Q  =>  k = (m1-m2)*(s1-s2)_inv mod Q")
    steps.append(f"    (s1 - s2) mod Q = {diff_s}")
    steps.append(f"    gcd(s1-s2, Q)   = {gcd_diff}")

    if gcd_diff != 1:
        steps.append("    (s1-s2) not invertible mod Q. Attack indeterminate for this pair.")
        return {"success": False, "steps": steps}

    diff_s_inv  = mod_inverse(diff_s, q)
    k_recovered = ((m1 - m2) * diff_s_inv) % q
    steps.append(f"    k = (m1-m2) * (s1-s2)_inv mod Q = {k_recovered}")
    steps.append(f"    Verify: g^k mod p = {pow(g, k_recovered, p)}, r = {r}, match: {pow(g, k_recovered, p) == r}")

    steps.append(f"\n  Step 2: Recover private key x")
    steps.append(f"    From s1 = k_inv*(m1 - x*r): rearranging gives x = (m1 - k*s1) * r_inv mod Q")
    gcd_r = math.gcd(r, q)
    if gcd_r != 1:
        steps.append("    r not invertible mod Q. Attack indeterminate.")
        return {"success": False, "steps": steps}

    r_inv       = mod_inverse(r, q)
    x_recovered = ((m1 - k_recovered * s1) * r_inv) % q
    steps.append(f"    x = (m1 - k*s1) * r_inv mod Q = {x_recovered}")

    y_check   = pow(g, x_recovered, p)
    x_correct = (y_check == y)
    steps.append(f"    Verify: g^x_recovered mod p = {y_check}")
    steps.append(f"    Original public key y       = {y}")
    steps.append(f"    Private key correctly recovered: {x_correct}")

    m3 = random.randint(10000, 99999)
    steps.append(f"\n  Step 3: Forge signature on new message m3={m3}")
    steps.append(f"    Using recovered x={x_recovered} to sign m3 (attacker acts as legitimate signer)")
    forged_keys = {**keys, "x": x_recovered}

    k_forge = random.randint(2, q - 2)
    while math.gcd(k_forge, q) != 1:
        k_forge = random.randint(2, q - 2)

    forged_sig = sign(m3, forged_keys, k_forge)
    steps.append(f"    Forged sig: r_f={forged_sig['r']}, s_f={forged_sig['s']}")

    verified = verify(m3, forged_sig, {**keys, "y": y})
    rf, sf   = forged_sig["r"], forged_sig["s"]
    steps.append(f"\n  Step 4: Verify forged signature against original public key y={y}")
    steps.append(f"    ElGamal check: g^m3 mod p  ==  y^r_f * r_f^s_f mod p")
    steps.append(f"    LHS = g^m3 mod p           = {pow(g, m3, p)}")
    steps.append(f"    RHS = y^r_f * r_f^s_f mod p= {(pow(y, rf, p) * pow(rf, sf, p)) % p}")
    steps.append(f"    Verification result: {'PASSED - forged signature accepted by verifier' if verified else 'FAILED'}")

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
    q = Q
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
