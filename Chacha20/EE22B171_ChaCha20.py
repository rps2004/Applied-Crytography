#!/usr/bin/env python3
"""
ChaCha20 CLI tool with logging and optional parallel quarter-rounds
- Modes: enc, dec, diff, keystream
- Default key/nonce/counter = all zeros (key=32B, nonce=12B, counter=32-bit)
- On terminal: summary (key, nonce, counter, time)
- If --log dr or dr+qr: logs go into chacha20_log.txt automatically
- --parallel: quarter-rounds for each column/diagonal are done in parallel
- --log dr+qr: print 8 quarter-rounds + 1 double-round per DR (like slides)
- If --diff: creates chacha20_diff.txt with compact 3-col diff + full QR/DR logs

Notes:
* Strict parameter checks: key must be 32 bytes, nonce 12 bytes, counter 0..2^32-1.
* 4x4 matrices are printed in row-major order (state[0..15]).
"""

import argparse, binascii, time, os
from concurrent.futures import ThreadPoolExecutor

# ---- helpers ----
def u32(x): return x & 0xffffffff

def rotl(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def to_u32(b):
    # expects exactly 4 bytes
    if len(b) != 4:
        raise ValueError("expected 4 bytes for a u32")
    return int.from_bytes(b, "little")

def to_bytes(x):
    return x.to_bytes(4, "little")

# ---- ChaCha quarter round ----
def qround(a, b, c, d):
    a = u32(a + b); d ^= a; d = rotl(d, 16)
    c = u32(c + d); b ^= c; b = rotl(b, 12)
    a = u32(a + b); d ^= a; d = rotl(d, 8)
    c = u32(c + d); b ^= c; b = rotl(b, 7)
    return u32(a), u32(b), u32(c), u32(d)

# ---- matrix printer ----
def print_matrix(state, f, title=None):
    if f is None: return
    if title: f.write(title + "\n")
    for r in range(4):
        f.write(" ".join(f"{state[4*r+i]:08x}" for i in range(4)) + "\n")

# ---- double round (sequential) ----
def doubleround_seq(x, log="off", f=None):
    # Column round
    cols = [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)]
    for j,(i0,i1,i2,i3) in enumerate(cols):
        x[i0],x[i1],x[i2],x[i3] = qround(x[i0],x[i1],x[i2],x[i3])
        if log == "dr+qr": print_matrix(x, f, f"QR1{chr(ord('a')+j)} (column)")
    # Diagonal round
    diags = [(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]
    for j,(i0,i1,i2,i3) in enumerate(diags):
        x[i0],x[i1],x[i2],x[i3] = qround(x[i0],x[i1],x[i2],x[i3])
        if log == "dr+qr": print_matrix(x, f, f"QR2{chr(ord('a')+j)} (diag)")
    return [u32(w) for w in x]

# ---- double round (parallel) ----
def _map_qr(x, tuples):
    return [qround(x[a],x[b],x[c],x[d]) for (a,b,c,d) in tuples]

def doubleround_par(x, log="off", f=None):
    cols = [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)]
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda t: qround(x[t[0]],x[t[1]],x[t[2]],x[t[3]]), cols))
    for j,(idxs,vals) in enumerate(zip(cols, results)):
        for i,v in zip(idxs, vals): x[i] = v
        if log == "dr+qr": print_matrix(x, f, f"QR1{chr(ord('a')+j)} (column)")
    diags = [(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda t: qround(x[t[0]],x[t[1]],x[t[2]],x[t[3]]), diags))
    for j,(idxs,vals) in enumerate(zip(diags, results)):
        for i,v in zip(idxs, vals): x[i] = v
        if log == "dr+qr": print_matrix(x, f, f"QR2{chr(ord('a')+j)} (diag)")
    return [u32(w) for w in x]

# ---- setup ----
SIGMA = b"expand 32-byte k"

def setup(key, nonce, counter):
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be exactly 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be exactly 12 bytes (96 bits)")
    if counter < 0 or counter >= (1<<32):
        raise ValueError("ChaCha20 counter must be a 32-bit unsigned integer")

    s = [0]*16
    s[0]  = to_u32(SIGMA[0:4])
    s[1]  = to_u32(SIGMA[4:8])
    s[2]  = to_u32(SIGMA[8:12])
    s[3]  = to_u32(SIGMA[12:16])
    # key (8 words)
    for i in range(8):
        s[4+i] = to_u32(key[4*i:4*i+4])
    # counter and nonce (IETF layout): state[12]=counter, [13..15]=nonce
    s[12] = u32(counter)
    s[13] = to_u32(nonce[0:4])
    s[14] = to_u32(nonce[4:8])
    s[15] = to_u32(nonce[8:12])
    return [u32(w) for w in s]

# ---- block ----
def chacha20_block(key, nonce, counter, log, f, parallel=False):
    state = setup(key, nonce, counter)
    work = state.copy(); dr_states = []
    round_func = doubleround_par if parallel else doubleround_seq
    for i in range(10):
        work = round_func(work, log, f)
        dr_states.append(work.copy())
        if log in ("dr","dr+qr"): print_matrix(work, f, f"Result of Double Round {i+1}")
    out = [(work[i] + state[i]) & 0xffffffff for i in range(16)]
    return b"".join(to_bytes(w) for w in out), dr_states, state

# ---- stream XOR ----
def xor_stream(data, key, nonce, counter, log, f, parallel=False):
    out = bytearray(); i = 0
    while i < len(data):
        ks,_,_ = chacha20_block(key, nonce, counter, log, f, parallel)
        counter = (counter + 1) & 0xffffffff
        n = min(64, len(data)-i)
        out.extend(bytes(a ^ b for a,b in zip(data[i:i+n], ks[:n])))
        i += n
    return bytes(out)

# ---- diff helpers ----
def diff_states(a,b): return [(x ^ y) & 0xffffffff for x,y in zip(a,b)]

def print_3col(a,b,f,title):
    f.write(title + "\n")
    for r in range(4):
        xa=a[4*r:4*r+4]; ya=b[4*r:4*r+4]; da=diff_states(xa,ya)
        f.write("{}   {}   {}\n".format(
            " ".join(f"{w:08x}" for w in xa),
            " ".join(f"{w:08x}" for w in ya),
            " ".join(f"{w:08x}" for w in da)))

# Full diff flow, matching Salsa tool structure
ndef_run_warning = ""  # placeholder to keep function order readable

def run_diff(key, nonce, c0, c1, parallel=False):
    with open("chacha20_diff.txt", "w") as f:
        f.write(f"=== Differential {c0} vs {c1} ===\n")
        f.write(f"Key: {key.hex()}\nNonce: {nonce.hex()}\n")
        # Initial states (3-col)
        _,_,s0 = chacha20_block(key, nonce, c0, "off", None, parallel)
        _,_,s1 = chacha20_block(key, nonce, c1, "off", None, parallel)
        print_3col(s0, s1, f, "Initial State")
        # Double rounds (3-col)
        _,sa,_ = chacha20_block(key, nonce, c0, "off", None, parallel)
        _,sb,_ = chacha20_block(key, nonce, c1, "off", None, parallel)
        for i,(x,y) in enumerate(zip(sa,sb),1):
            print_3col(x, y, f, f"After DR{i}")
        # Detailed QR/DR dumps for each counter
        f.write("\n=========================\nDetailed States (Counter={})\n".format(c0))
        chacha20_block(key, nonce, c0, "dr+qr", f, parallel)
        f.write("\n=========================\nDetailed States (Counter={})\n".format(c1))
        chacha20_block(key, nonce, c1, "dr+qr", f, parallel)

# ---- CLI ----
def parse_hex(s):
    s = s.lower().replace("0x", "")
    return binascii.unhexlify(s)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--enc', action='store_true'); ap.add_argument('--dec', action='store_true')
    ap.add_argument('--in', dest='infile'); ap.add_argument('--out', dest='outfile')
    ap.add_argument('--key', type=parse_hex); ap.add_argument('--nonce', type=parse_hex); ap.add_argument('--counter', type=int)
    ap.add_argument('--log', choices=['off','dr','dr+qr'], default='off')
    ap.add_argument('--diff', nargs=2, type=int)
    ap.add_argument('--keystream', action='store_true')
    ap.add_argument('--parallel', action='store_true', help='Parallelize quarter-rounds')
    args = ap.parse_args()

    key = args.key or (b"\x00"*32)
    nonce = args.nonce or (b"\x00"*12)
    ctr = args.counter or 0

    # strict checks
    if len(key) != 32:
        raise SystemExit("[error] key must be 32 bytes (256-bit) for ChaCha20")
    if len(nonce) != 12:
        raise SystemExit("[error] nonce must be 12 bytes (96-bit) for ChaCha20")
    if ctr < 0 or ctr >= (1<<32):
        raise SystemExit("[error] counter must be a 32-bit unsigned integer (0..2^32-1)")

    t0 = time.perf_counter()

    if args.diff:
        c0, c1 = args.diff
        run_diff(key, nonce, c0, c1, args.parallel)
    else:
        f = None
        if args.log != 'off':
            f = open('chacha20_log.txt', 'w')
            f.write(f"Key: {key.hex()}\nNonce: {nonce.hex()}\nCounter: {ctr}\n")
        if args.enc or args.dec:
            with open(args.infile, 'rb') as fi:
                data = fi.read()
            if f: f.write(f"Plaintext: {data.hex()}\n")
            out = xor_stream(data, key, nonce, ctr, args.log, f, args.parallel)
            if f:
                f.write(f"Ciphertext: {out.hex()}\n")
                try:
                    fsize = len(out)
                    f.write(f"Encrypted bytes: {fsize}\n")
                except Exception:
                    pass
            with open(args.outfile, 'wb') as fo:
                fo.write(out)
        elif args.keystream:
            ks,_,_ = chacha20_block(key, nonce, ctr, args.log, f, args.parallel)
            if f: f.write(f"Keystream: {ks.hex()}\n")
            print("Keystream:", ks.hex())
        else:
            ap.print_help(); return
        if f: f.close()

    t1 = time.perf_counter()
    print(f"Done in {t1-t0:.7f} seconds")
    print(f"Key: {key.hex()}\nNonce: {nonce.hex()}\nCounter: {ctr}")
    if args.parallel:
        print("Parallel quarter-rounds enabled")

if __name__ == '__main__':
    main()
