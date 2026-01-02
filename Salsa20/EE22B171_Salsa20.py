#!/usr/bin/env python3
"""
Salsa20 CLI tool with logging and optional parallel quarter-rounds
- Modes: enc, dec, diff, keystream
- Default key/nonce/counter = all zeros
- On terminal: summary (key, nonce, counter, time)
- If --log dr or dr+qr: logs go into salsa20_log.txt automatically
- --parallel: use alternate functions where quarter-rounds are parallelized
- --log dr+qr: print 8 quarter-rounds + 1 double-round per DR
- If --diff: creates salsa20_diff.txt with compact 3-col diff + full QR/DR logs
"""

import argparse, binascii, time
from concurrent.futures import ThreadPoolExecutor

# ---- helpers ----
def u32(x): return x & 0xffffffff
def rotl(x,n): x&=0xffffffff; return ((x<<n)|(x>>(32-n))) & 0xffffffff
def to_u32(b): return int.from_bytes(b,"little")
def to_bytes(x): return x.to_bytes(4,"little")

# ---- quarter round ----
def qround(a,b,c,d):
    b^=rotl(a+d,7); c^=rotl(b+a,9); d^=rotl(c+b,13); a^=rotl(d+c,18)
    return u32(a),u32(b),u32(c),u32(d)

# ---- sequential double round with optional QR logging ----
def doubleround_seq(x, log="off", f=None):
    idxs=[(0,4,8,12),(5,9,13,1),(10,14,2,6),(15,3,7,11)]
    for j,(i0,i1,i2,i3) in enumerate(idxs):
        x[i0],x[i1],x[i2],x[i3]=qround(x[i0],x[i1],x[i2],x[i3])
        if log=="dr+qr": print_matrix(x,f,f"QR1{chr(ord('a')+j)} (column)")
    idxs=[(0,1,2,3),(5,6,7,4),(10,11,8,9),(15,12,13,14)]
    for j,(i0,i1,i2,i3) in enumerate(idxs):
        x[i0],x[i1],x[i2],x[i3]=qround(x[i0],x[i1],x[i2],x[i3])
        if log=="dr+qr": print_matrix(x,f,f"QR2{chr(ord('a')+j)} (row)")
    return [u32(w) for w in x]

# ---- parallel double round with optional QR logging ----
def doubleround_par(x, log="off", f=None):
    jobs=[(0,4,8,12),(5,9,13,1),(10,14,2,6),(15,3,7,11)]
    with ThreadPoolExecutor(max_workers=4) as ex:
        results=list(ex.map(lambda idxs:qround(*[x[i] for i in idxs]),jobs))
    for j,(idxs,vals) in enumerate(zip(jobs,results)):
        for i,v in zip(idxs,vals): x[i]=v
        if log=="dr+qr": print_matrix(x,f,f"QR1{chr(ord('a')+j)} (column)")
    jobs=[(0,1,2,3),(5,6,7,4),(10,11,8,9),(15,12,13,14)]
    with ThreadPoolExecutor(max_workers=4) as ex:
        results=list(ex.map(lambda idxs:qround(*[x[i] for i in idxs]),jobs))
    for j,(idxs,vals) in enumerate(zip(jobs,results)):
        for i,v in zip(idxs,vals): x[i]=v
        if log=="dr+qr": print_matrix(x,f,f"QR2{chr(ord('a')+j)} (row)")
    return [u32(w) for w in x]

# ---- logging ----
def print_matrix(state, f, title=None):
    if f is None: return
    if title: f.write(title+"\n")
    for r in range(4): f.write(" ".join(f"{state[4*r+i]:08x}" for i in range(4))+"\n")

# ---- setup ----
SIGMA=b"expand 32-byte k"; TAU=b"expand 16-byte k"

def setup(key,nonce,counter):
    if len(key)==32: const=SIGMA; k0=key[:16]; k1=key[16:]
    elif len(key)==16: const=TAU; k0=key; k1=key
    else: raise ValueError("key must be 16 or 32 bytes")
    if len(nonce)!=8: raise ValueError("Nonce must be exactly 8 bytes (64 bits)")
    if counter<0 or counter>=(1<<64): raise ValueError("Counter must be 64-bit unsigned int")
    s=[0]*16
    s[0]=to_u32(const[0:4]); s[1]=to_u32(k0[0:4]); s[2]=to_u32(k0[4:8]); s[3]=to_u32(k0[8:12]);
    s[4]=to_u32(k0[12:16]); s[5]=to_u32(const[4:8]); s[6]=to_u32(nonce[0:4]); s[7]=to_u32(nonce[4:8]);
    ctr=counter.to_bytes(8,'little'); s[8]=to_u32(ctr[0:4]); s[9]=to_u32(ctr[4:8]);
    s[10]=to_u32(const[8:12]); s[11]=to_u32(k1[0:4]); s[12]=to_u32(k1[4:8]);
    s[13]=to_u32(k1[8:12]); s[14]=to_u32(k1[12:16]); s[15]=to_u32(const[12:16]);
    return [u32(w) for w in s]

# ---- block ----
def salsa20_block(key,nonce,counter,log,f,parallel=False):
    state=setup(key,nonce,counter)
    work=state.copy(); dr_states=[]
    round_func = doubleround_par if parallel else doubleround_seq
    for i in range(10):
        work=round_func(work,log,f)
        dr_states.append(work.copy())
        if log in ("dr","dr+qr"): print_matrix(work,f,f"Result of Double Round {i+1}")
    out=[(work[i]+state[i])&0xffffffff for i in range(16)]
    return b"".join(to_bytes(w) for w in out), dr_states, state

# ---- stream ----
def xor_stream(data,key,nonce,counter,log,f,parallel=False):
    out=bytearray(); i=0
    while i<len(data):
        ks,_,_=salsa20_block(key,nonce,counter,log,f,parallel)
        counter+=1
        n=min(64,len(data)-i)
        out.extend(bytes(a^b for a,b in zip(data[i:i+n],ks[:n])))
        i+=n
    return bytes(out)

# ---- diff ----
def diff_states(a,b): return [(x^y)&0xffffffff for x,y in zip(a,b)]

def print_3col(a,b,f,title):
    f.write(title+"\n")
    for r in range(4):
        xa=a[4*r:4*r+4]; ya=b[4*r:4*r+4]; da=diff_states(xa,ya)
        f.write("{}   {}   {}\n".format(
            " ".join(f"{w:08x}" for w in xa),
            " ".join(f"{w:08x}" for w in ya),
            " ".join(f"{w:08x}" for w in da)))

def run_diff(key,nonce,c0,c1,parallel=False):
    with open("salsa20_diff.txt","w") as f:
        f.write(f"=== Differential {c0} vs {c1} ===\n")
        f.write(f"Key: {key.hex()}\nNonce: {nonce.hex()}\n")
        # Initial states
        _,_,s0= salsa20_block(key,nonce,c0,"off",None,parallel)
        _,_,s1= salsa20_block(key,nonce,c1,"off",None,parallel)
        print_3col(s0,s1,f,"Initial State")
        # Double rounds
        _,sa,_=salsa20_block(key,nonce,c0,"off",None,parallel)
        _,sb,_=salsa20_block(key,nonce,c1,"off",None,parallel)
        for i,(x,y) in enumerate(zip(sa,sb),1):
            print_3col(x,y,f,f"After DR{i}")
        # Detailed logs
        f.write("\n=========================\nDetailed States (Counter={})\n".format(c0))
        salsa20_block(key,nonce,c0,"dr+qr",f,parallel)
        f.write("\n=========================\nDetailed States (Counter={})\n".format(c1))
        salsa20_block(key,nonce,c1,"dr+qr",f,parallel)

# ---- cli ----
def parse_hex(s): s=s.lower().replace("0x",""); return binascii.unhexlify(s)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--enc',action='store_true'); ap.add_argument('--dec',action='store_true')
    ap.add_argument('--in',dest='infile'); ap.add_argument('--out',dest='outfile')
    ap.add_argument('--key',type=parse_hex); ap.add_argument('--nonce',type=parse_hex); ap.add_argument('--counter',type=int)
    ap.add_argument('--variant',choices=['128','256'],default='256')
    ap.add_argument('--log',choices=['off','dr','dr+qr'],default='off')
    ap.add_argument('--diff',nargs=2,type=int)
    ap.add_argument('--keystream',action='store_true')
    ap.add_argument('--parallel',action='store_true',help='Parallelize quarter-rounds')
    args=ap.parse_args()

    klen=32 if args.variant=='256' else 16
    key=args.key or (b"\x00"*klen); nonce=args.nonce or (b"\x00"*8); ctr=args.counter or 0

    start=time.perf_counter()

    if args.diff:
        c0,c1=args.diff; run_diff(key,nonce,c0,c1,args.parallel)
    else:
        f=None
        if args.log != "off":
            f=open("salsa20_log.txt","w")
            f.write(f"Key: {key.hex()}\nNonce: {nonce.hex()}\nCounter: {ctr}\n")
        if args.enc or args.dec:
            with open(args.infile,'rb') as fi: data=fi.read()
            if f: f.write(f"Plaintext: {data.hex()}\n")
            out=xor_stream(data,key,nonce,ctr,args.log,f,args.parallel)
            if f: f.write(f"Ciphertext: {out.hex()}\n")
            with open(args.outfile,'wb') as fo: fo.write(out)
        elif args.keystream:
            ks,_,_=salsa20_block(key,nonce,ctr,args.log,f,args.parallel)
            if f: f.write(f"Keystream: {ks.hex()}\n")
            print("Keystream:", ks.hex())
        else:
            ap.print_help(); return
        if f: f.close()

    end=time.perf_counter()
    print(f"Done in {end-start:.7f} seconds")
    print(f"Key: {key.hex()}\nNonce: {nonce.hex()}\nCounter: {ctr}")
    
    if args.parallel:
        print("Parallel quarter-rounds enabled")

if __name__=='__main__': main()
