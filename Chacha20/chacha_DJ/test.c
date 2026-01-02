#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ecrypt-sync.h"

int main() {
    ECRYPT_ctx ctx;
    unsigned char key[32] = { 0 };   // 256-bit all zero key
    unsigned char iv[8] = { 0 };    // 64-bit all zero nonce
    unsigned char keystream[64];   // first 64 bytes
    const size_t MSG_SIZE = 100*1024 * 1024; // 1 MB test
    unsigned char* buf = malloc(MSG_SIZE);
    clock_t start, end;

    if (!buf) {
        printf("Memory allocation failed\n");
        return 1;
    }

    memset(buf, 0, MSG_SIZE);

    // Init and setup
    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, 256, 64);
    ECRYPT_ivsetup(&ctx, iv);

    // Generate and print first keystream block
    ECRYPT_keystream_bytes(&ctx, keystream, 64);
    printf("First 64 bytes of ChaCha keystream:\n");
    for (int i = 0; i < 64; i++) printf("%02x", keystream[i]);
    printf("\n");

    // Reset IV to start from counter=0
    ECRYPT_ivsetup(&ctx, iv);

    // Measure encryption speed on 1MB zero buffer
    start = clock();
    ECRYPT_encrypt_bytes(&ctx, buf, buf, MSG_SIZE);
    end = clock();

    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Processed %zu bytes in %.7f seconds\n", MSG_SIZE, seconds);

    free(buf);
    return 0;
}
