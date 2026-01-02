import time
from EE22B171_Salsa20 import xor_stream

def benchmark_salsa(keylen=32, msglen=1*1024*1024):
    key   = b"\x00" * keylen
    nonce = b"\x00" * 8
    ctr   = 0

    data = b"\x00" * msglen

    start = time.perf_counter()
    out = xor_stream(data, key, nonce, ctr, log="off", f=None)
    end = time.perf_counter()

    secs = end - start
    mbps = (msglen / (1024 * 1024)) / secs

    print(f"Encrypted {msglen} bytes in {secs:.6f} seconds ({mbps:.2f} MB/s)")
    print("\nFirst 64 keystream bytes:")
    print(out[:64].hex())

if __name__ == "__main__":
    benchmark_salsa(msglen=1*1024*1024)
    benchmark_salsa(msglen=10*1024*1024)
    
