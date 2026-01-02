#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ecrypt-sync.h"

int main() {
    ECRYPT_ctx ctx;

    u8 key[32] = { 0 };   // 256-bit key
    u8 iv[8] = { 0 };   // 64-bit nonce

    size_t msglen = 100 * 1024 * 1024;   // 1 MB
    u8* plaintext = (u8*)calloc(msglen, 1);
    u8* ciphertext = (u8*)malloc(msglen);

    ECRYPT_keysetup(&ctx, key, 256, 64);
    ECRYPT_ivsetup(&ctx, iv);

    clock_t start = clock();
    ECRYPT_encrypt_bytes(&ctx, plaintext, ciphertext, msglen);
    clock_t end = clock();

    double secs = (double)(end - start) / CLOCKS_PER_SEC;
    double mbps = (msglen / (1024.0 * 1024.0)) / secs;

    printf("Encrypted %zu bytes in %.6f seconds (%.2f MB/s)\n",
        msglen, secs, mbps);

    // Print first 64 keystream bytes for verification
    printf("\nFirst 64 keystream bytes:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", ciphertext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }

    free(plaintext);
    free(ciphertext);
    return 0;
}
