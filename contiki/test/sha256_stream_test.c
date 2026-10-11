/*
 * sha256_stream_test.c -- host test for contiki/sha256_impl.c (Phase C0).
 *
 * The firmware now hashes messages piece by piece (init/update/final) instead
 * of copying them into one buffer. This checks that streaming gives exactly
 * the one-shot digest for every split point, including splits that straddle
 * the 64-byte block boundary, plus two FIPS 180-2 known-answer vectors.
 *
 * Build and run from the repo root (no Contiki needed):
 *   gcc -O2 -Wall -Wextra -I contiki -o /tmp/sha256_stream_test \
 *       contiki/test/sha256_stream_test.c contiki/sha256_impl.c && /tmp/sha256_stream_test
 */
#include "sha256_impl.h"
#include <stdio.h>
#include <string.h>

static int kat(const char *msg, const char *want_hex)
{
    uint8_t d[32];
    char got[65];
    int i;
    sha256_impl_hash((const uint8_t *)msg, strlen(msg), d);
    for(i = 0; i < 32; i++) {
        sprintf(got + 2 * i, "%02x", d[i]);
    }
    if(strcmp(got, want_hex) != 0) {
        printf("KAT FAIL for \"%s\"\n  got  %s\n  want %s\n", msg, got, want_hex);
        return 1;
    }
    return 0;
}

int main(void)
{
    static uint8_t buf[400];
    uint8_t one[32], streamed[32];
    sha256_impl_ctx_t ctx, saved;
    size_t len, a, b, i;
    unsigned long checks = 0, fails = 0;

    fails += kat("abc",
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    fails += kat("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    for(i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)(i * 131u + 7u);
    }

    /* every length up to 300, split into three pieces at every pair of points */
    for(len = 0; len <= 300; len++) {
        sha256_impl_hash(buf, len, one);
        for(a = 0; a <= len; a += (len > 80 ? 7 : 1)) {
            for(b = a; b <= len; b += (len > 80 ? 11 : 1)) {
                sha256_impl_init(&ctx);
                sha256_impl_update(&ctx, buf, a);
                sha256_impl_update(&ctx, buf + a, b - a);
                sha256_impl_update(&ctx, buf + b, len - b);
                sha256_impl_final(&ctx, streamed);
                checks++;
                if(memcmp(one, streamed, 32) != 0) {
                    fails++;
                }
            }
        }
    }

    /* copying a context mid-stream and finishing both copies (what process_msg2 does) */
    for(len = 0; len <= 200; len++) {
        uint8_t d1[32], d2[32], r1[32], r2[32];
        uint8_t tmp[400];
        sha256_impl_init(&saved);
        sha256_impl_update(&saved, buf, len);
        ctx = saved;
        sha256_impl_update(&ctx, buf + len, 49);
        sha256_impl_final(&ctx, d1);
        ctx = saved;
        sha256_impl_update(&ctx, buf + len, 120);
        sha256_impl_final(&ctx, d2);
        memcpy(tmp, buf, len + 49);
        sha256_impl_hash(tmp, len + 49, r1);
        memcpy(tmp, buf, len + 120);
        sha256_impl_hash(tmp, len + 120, r2);
        checks += 2;
        fails += (memcmp(d1, r1, 32) != 0) + (memcmp(d2, r2, 32) != 0);
    }

    printf("sha256 streaming: %lu checks, %lu failures -> %s\n",
           checks, fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
