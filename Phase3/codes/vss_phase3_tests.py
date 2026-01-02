# vss_phase3_tests.py
# Phase-3 security tests for Feldman & Pedersen VSS
# Python 3.8+, standard library only
#
# Usage:
#   python vss_phase3_tests.py
#
# The module exposes test functions; run the file to execute a demo batch.

import random
import math
import time
from collections import Counter
from typing import List, Tuple, Dict, Optional

# -----------------------
# Number theory helpers
# -----------------------
def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a: int, m: int) -> Optional[int]:
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def is_prime(n: int) -> bool:
    if n < 2: return False
    if n % 2 == 0:
        return n == 2
    r = int(n**0.5)
    f = 3
    while f <= r:
        if n % f == 0:
            return False
        f += 2
    return True

def next_prime(n: int) -> int:
    x = max(2, n + 1)
    while not is_prime(x):
        x += 1
    return x

def find_generator_of_order(p: int, q: int) -> int:
    """
    find g with order q modulo p (i.e., g^q % p == 1, and for any proper divisor d of q, g^d != 1)
    Assumes q divides p-1.
    """
    assert (p - 1) % q == 0
    for g in range(2, p):
        if pow(g, q, p) != 1:
            continue
        # ensure order exactly q: for each prime factor r of q, pow(g, q//r, p) != 1
        ok = True
        qq = q
        f = 2
        while f * f <= qq:
            if qq % f == 0:
                if pow(g, q // f, p) == 1:
                    ok = False; break
                while qq % f == 0: qq //= f
            f += 1
        if ok and qq > 1:
            if pow(g, q // qq, p) == 1:
                ok = False
        if ok:
            return g
    raise ValueError("generator not found")

# -----------------------
# Polynomial helpers (mod q)
# -----------------------
def poly_eval(coeffs: List[int], x: int, mod: int) -> int:
    res = 0
    pow_x = 1
    for a in coeffs:
        res = (res + a * pow_x) % mod
        pow_x = (pow_x * x) % mod
    return res

def random_polynomial(secret: int, t: int, q: int) -> List[int]:
    """Return degree-(t-1) polynomial coeffs with constant term = secret."""
    coeffs = [secret] + [random.randrange(0, q) for _ in range(t - 1)]
    return coeffs

def lagrange_interpolate(xs: List[int], ys: List[int], qmod: int) -> int:
    """
    Reconstruct f(0) (the secret) using Lagrange interpolation in Z_q.
    xs, ys are lists of length t (1-indexed sample points typically).
    """
    assert len(xs) == len(ys)
    k = len(xs)
    secret = 0
    for j in range(k):
        num = 1
        den = 1
        xj = xs[j]
        for m in range(k):
            if m == j: continue
            xm = xs[m]
            num = (num * (-xm)) % qmod
            den = (den * (xj - xm)) % qmod
        inv_den = inv_mod(den, qmod)
        if inv_den is None:
            return None
        lj0 = (num * inv_den) % qmod
        secret = (secret + ys[j] * lj0) % qmod
    return secret

# -----------------------
# Group parameter helper (small-demo)
# -----------------------
def demo_group_small():
    """
    Provide small demo group (p, q, g) where q | p-1 and g has order q.
    Small groups are for demonstration only (do not use in production).
    Returns (p, q, g).
    """
    # choose a small q prime and set p = 2*q + 1 if that p is prime (safe prime)
    # fallback: find p and q with q | p-1
    for q in [11, 13, 17, 19, 23, 29]:
        p_candidate = 2 * q + 1
        if is_prime(p_candidate):
            p = p_candidate
            g = find_generator_of_order(p, q)
            return (p, q, g)
    # fallback: brute force small p
    p = 23; q = 11
    g = find_generator_of_order(p, q)
    return (p, q, g)

# -----------------------
# Feldman VSS
# -----------------------
def feldman_commitments(coeffs: List[int], p: int, g: int) -> List[int]:
    """
    Commitments C_j = g^{a_j} mod p for polynomial coefficients a_j.
    coeffs length = t
    """
    return [pow(g, a, p) for a in coeffs]

def feldman_generate_shares(secret: int, t: int, n: int, q: int) -> Tuple[List[int], List[int]]:
    """Return coeffs and shares (1-indexed x points) modulo q."""
    coeffs = random_polynomial(secret, t, q)
    shares = [poly_eval(coeffs, i, q) for i in range(1, n + 1)]
    return coeffs, shares

def feldman_verify_share(share_i: int, i_index: int, commitments: List[int], p: int, g: int) -> bool:
    """
    Verify g^{share_i} ?= prod_j C_j^{i^j} mod p
    """
    left = pow(g, share_i, p)
    right = 1
    exp = 1
    for C in commitments:
        right = (right * pow(C, exp, p)) % p
        exp = (exp * i_index)  # exponent i^j
    right %= p
    return left == right

# -----------------------
# Pedersen VSS
# -----------------------
def pedersen_commitments(coeffs_a: List[int], coeffs_b: List[int], p: int, g: int, h: int) -> List[int]:
    """
    Commitments C_j = g^{a_j} * h^{b_j} mod p
    """
    return [ (pow(g, a, p) * pow(h, b, p)) % p for a, b in zip(coeffs_a, coeffs_b) ]

def pedersen_generate_shares(secret: int, t: int, n: int, q: int) -> Tuple[List[int], List[int], List[int], List[int]]:
    """
    Returns: coeffs_a, coeffs_b, shares_s (a(i)), shares_t (b(i))
    """
    coeffs_a = random_polynomial(secret, t, q)
    coeffs_b = [random.randrange(0, q) for _ in range(t)]
    shares_s = [poly_eval(coeffs_a, i, q) for i in range(1, n + 1)]
    shares_t = [poly_eval(coeffs_b, i, q) for i in range(1, n + 1)]
    return coeffs_a, coeffs_b, shares_s, shares_t

def pedersen_verify_share(share_s: int, share_t: int, i_index: int, commitments: List[int], p: int, g: int, h: int) -> bool:
    """
    Verify g^{s_i} * h^{t_i} ?= prod_j C_j^{i^j} mod p
    """
    left = (pow(g, share_s, p) * pow(h, share_t, p)) % p
    right = 1
    exp = 1
    for C in commitments:
        right = (right * pow(C, exp, p)) % p
        exp = (exp * i_index)
    right %= p
    return left == right

# -----------------------
# Test routines
# -----------------------
def test_dealer_cheating_feldman(p: int, q: int, g: int, t: int, n: int, trials: int=200) -> Dict:
    """
    Dealer generates commitments for a polynomial but then distributes some incorrect shares
    (i.e., cheating). Measure fraction of honest participants that detect inconsistency.
    """
    detect_counts = []
    for _ in range(trials):
        secret = random.randrange(0, q)
        coeffs, shares = feldman_generate_shares(secret, t, n, q)
        commitments = feldman_commitments(coeffs, p, g)
        # corrupt some shares (flip random 10%)
        corrupted = set(random.sample(range(n), max(1, n//10)))
        verified = []
        for idx in range(n):
            i = idx + 1
            s = shares[idx]
            if idx in corrupted:
                s = random.randrange(0, q)  # bogus
            ok = feldman_verify_share(s, i, commitments, p, g)
            verified.append(ok)
        # detection = fraction of corrupted shares that failed verification among corrupted set
        detected = sum(1 for idx in corrupted if not verified[idx])
        detect_counts.append(detected / len(corrupted))
    return {"avg_detection_rate": sum(detect_counts)/len(detect_counts), "trials": trials}

def test_participant_forgery_feldman(p: int, q: int, g: int, t: int, n: int, trials: int=200) -> Dict:
    """
    Adversary forges a share (without changing commitments) and tries to pass verification.
    Measure fraction of forged shares that pass verification (should be ~0 unless small params).
    """
    pass_counts = []
    for _ in range(trials):
        secret = random.randrange(0, q)
        coeffs, shares = feldman_generate_shares(secret, t, n, q)
        commitments = feldman_commitments(coeffs, p, g)
        # choose random participant to forge for
        victim = random.randrange(n)
        i = victim + 1
        forged = 0
        # attempt random forgeries (bounded attempts)
        attempts = 50
        passed = 0
        for _ in range(attempts):
            fake_share = random.randrange(0, q)
            if feldman_verify_share(fake_share, i, commitments, p, g):
                passed += 1
        pass_counts.append(passed / attempts)
    return {"avg_forge_pass_rate": sum(pass_counts)/len(pass_counts), "trials": trials, "attempts": attempts}

def test_dealer_cheating_pedersen(p: int, q: int, g: int, h: int, t: int, n: int, trials: int=200) -> Dict:
    """
    Same as Feldman version but with Pedersen commitments (which are information-theoretically hiding).
    """
    detect_counts = []
    for _ in range(trials):
        secret = random.randrange(0, q)
        coeffs_a, coeffs_b, shares_s, shares_t = pedersen_generate_shares(secret, t, n, q)
        commitments = pedersen_commitments(coeffs_a, coeffs_b, p, g, h)
        corrupted = set(random.sample(range(n), max(1, n//10)))
        verified = []
        for idx in range(n):
            i = idx + 1
            s = shares_s[idx]; tval = shares_t[idx]
            if idx in corrupted:
                s = random.randrange(0, q); tval = random.randrange(0, q)
            ok = pedersen_verify_share(s, tval, i, commitments, p, g, h)
            verified.append(ok)
        detected = sum(1 for idx in corrupted if not verified[idx])
        detect_counts.append(detected / len(corrupted))
    return {"avg_detection_rate": sum(detect_counts)/len(detect_counts), "trials": trials}

def test_participant_forgery_pedersen(p: int, q: int, g: int, h: int, t: int, n: int, trials: int=200) -> Dict:
    """
    Participant attempts to forge a share (s_i, t_i) that matches commitments.
    For Pedersen, forging should be infeasible without discrete-log or knowledge of coeffs.
    """
    pass_counts = []
    for _ in range(trials):
        secret = random.randrange(0, q)
        coeffs_a, coeffs_b, shares_s, shares_t = pedersen_generate_shares(secret, t, n, q)
        commitments = pedersen_commitments(coeffs_a, coeffs_b, p, g, h)
        victim = random.randrange(n)
        i = victim + 1
        attempts = 50
        passed = 0
        for _ in range(attempts):
            fake_s = random.randrange(0, q)
            fake_t = random.randrange(0, q)
            if pedersen_verify_share(fake_s, fake_t, i, commitments, p, g, h):
                passed += 1
        pass_counts.append(passed / attempts)
    return {"avg_forge_pass_rate": sum(pass_counts)/len(pass_counts), "trials": trials, "attempts": attempts}

def test_randomness_reuse_pedersen_recoverable(p: int, q: int, g: int, h: int, t: int, n: int, trials: int=200) -> Dict:
    """
    Demonstrate that reusing the same coeffs_b across two secrets results in commitments
    whose ratio eliminates h^{b_j}, leaving g^{(a'_j - a_j)}. If discrete-log is feasible (small group),
    the attacker can recover coefficient differences and potentially derive secret relations.
    This test attempts brute-force discrete log for small q to show the danger.
    """
    success_count = 0
    recovered_details = []
    for _ in range(trials):
        # same random b coefficients reused
        coeffs_b = [random.randrange(0, q) for _ in range(t)]
        s1 = random.randrange(0, q); s2 = random.randrange(0, q)
        coeffs_a1 = random_polynomial(s1, t, q)
        coeffs_a2 = random_polynomial(s2, t, q)
        C1 = pedersen_commitments(coeffs_a1, coeffs_b, p, g, h)
        C2 = pedersen_commitments(coeffs_a2, coeffs_b, p, g, h)
        # ratio_j = C2_j * inv(C1_j) = g^{a2_j - a1_j} mod p
        ratios = [ (C2[j] * inv_mod(C1[j], p)) % p for j in range(t) ]
        # attempt to recover delta = a2_j - a1_j by brute-forcing exponent e such that g^e == ratio
        recovered = True
        deltas = []
        for r in ratios:
            found = False
            # only feasible for small q; limit brute force attempts to q
            for e in range(q):
                if pow(g, e, p) == r:
                    deltas.append(e)
                    found = True
                    break
            if not found:
                recovered = False
                break
        if recovered:
            success_count += 1
            recovered_details.append({"s1": s1, "s2": s2, "deltas": deltas})
    return {"recovery_success_fraction": success_count / trials, "recovered_examples": recovered_details[:5]}

def test_timing_commit_verify(p: int, q: int, g: int, h: int, t_values: List[int], n: int, trials: int=50) -> List[Dict]:
    """
    Measure time to compute commitments and verify shares across different t.
    Returns list of timing dicts.
    """
    results = []
    for t in t_values:
        commit_time_f = 0.0; verify_time_f = 0.0
        commit_time_p = 0.0; verify_time_p = 0.0
        for _ in range(trials):
            secret = random.randrange(0, q)
            # Feldman
            coeffs_f, shares_f = feldman_generate_shares(secret, t, n, q)
            t0 = time.perf_counter()
            commits_f = feldman_commitments(coeffs_f, p, g)
            t1 = time.perf_counter()
            # verify all shares timing
            for i_idx, s in enumerate(shares_f):
                _ = feldman_verify_share(s, i_idx+1, commits_f, p, g)
            t2 = time.perf_counter()
            commit_time_f += (t1 - t0); verify_time_f += (t2 - t1)
            # Pedersen
            coeffs_a, coeffs_b, shares_s, shares_t = pedersen_generate_shares(secret, t, n, q)
            t0 = time.perf_counter()
            commits_p = pedersen_commitments(coeffs_a, coeffs_b, p, g, h)
            t1 = time.perf_counter()
            for i_idx, (s, tt) in enumerate(zip(shares_s, shares_t)):
                _ = pedersen_verify_share(s, tt, i_idx+1, commits_p, p, g, h)
            t2 = time.perf_counter()
            commit_time_p += (t1 - t0); verify_time_p += (t2 - t1)
        results.append({
            "t": t,
            "feldman_commit_avg_s": commit_time_f / trials,
            "feldman_verify_all_avg_s": verify_time_f / trials,
            "pedersen_commit_avg_s": commit_time_p / trials,
            "pedersen_verify_all_avg_s": verify_time_p / trials,
            "n": n
        })
    return results

# -----------------------
# Demo runner
# -----------------------
if __name__ == "__main__":
    random.seed(0)

    # use small demo group (FOR TESTING/DEMO ONLY)
    p, q, g = demo_group_small()
    # pick h distinct from g within subgroup (generator of same order)
    # find h such that pow(h, q, p) == 1 and h != g
    h_candidate = 2
    while h_candidate == g or pow(h_candidate, q, p) != 1:
        h_candidate += 1
        if h_candidate >= p:
            raise RuntimeError("failed to find h")
    h = h_candidate

    print("Using demo group p,q,g,h:", p, q, g, h)
    t = 3; n = 6

    print("\n=== Feldman: dealer cheating detection ===")
    out_feldman = test_dealer_cheating_feldman(p, q, g, t, n, trials=400)
    print(out_feldman)

    print("\n=== Feldman: participant forgery pass rate (approx) ===")
    out_forge_f = test_participant_forgery_feldman(p, q, g, t, n, trials=200)
    print(out_forge_f)

    print("\n=== Pedersen: dealer cheating detection ===")
    out_ped = test_dealer_cheating_pedersen(p, q, g, h, t, n, trials=400)
    print(out_ped)

    print("\n=== Pedersen: participant forgery pass rate (approx) ===")
    out_forge_p = test_participant_forgery_pedersen(p, q, g, h, t, n, trials=200)
    print(out_forge_p)

    print("\n=== Pedersen randomness reuse (small-group recoverability demo) ===")
    out_reuse = test_randomness_reuse_pedersen_recoverable(p, q, g, h, t, n, trials=200)
    print(out_reuse["recovery_success_fraction"], "examples:", out_reuse["recovered_examples"])

    print("\n=== Timing commit+verify vs t ===")
    timing = test_timing_commit_verify(p, q, g, h, t_values=[2,3,4,5,6], n=n, trials=60)
    for r in timing:
        print(r)
