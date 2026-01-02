import time
from EE22B171_ChaCha20 import xor_stream   # adjust import path to your file

def benchmark_chacha(keylen=32, msglen=1*1024*1024, parallel=False):
    key   = b"\x00" * keylen     # all-zero key (256-bit)
    nonce = b"\x00" * 12         # ChaCha uses 96-bit (12-byte) nonce
    ctr   = 0                    # 32-bit counter

    # allocate plaintext
    data = b"\x00" * msglen

    # measure time
    start = time.perf_counter()
    out = xor_stream(data, key, nonce, ctr, "off", None, parallel=parallel)
    end = time.perf_counter()

    secs = end - start
    mbps = (msglen / (1024 * 1024)) / secs

    print(f"Encrypted {msglen} bytes in {secs:.6f} seconds ({mbps:.2f} MB/s)")
    print("\nFirst 64 keystream bytes:")
    print(out[:64].hex())

if __name__ == "__main__":
    benchmark_chacha(keylen=32, msglen=1*1024*1024, parallel=False)
    benchmark_chacha(keylen=32,msglen=10*1024*1024,parallel=False)
