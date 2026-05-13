/*
 * Adler-32 (RFC 1950 — zlib's checksum). Two running 16-bit accumulators
 * mod 65521, recombined into a 32-bit output. The classic "almost as
 * cheap as a sum, much better collision resistance" checksum.
 *
 * NMAX (5552) is the largest run that keeps the inner sums inside
 * uint32_t without modding every iteration — we never approach that for
 * a 1024-byte block, so the mod fires exactly once at the end.
 */
#include "hashes.h"

#define ADLER_MOD 65521u

void hash_adler32(const uint8_t *data, uint16_t len, uint8_t out[4]) {
    uint32_t a = 1u, b = 0u;
    uint16_t i;

    for (i = 0; i < len; i++) {
        a += data[i];
        b += a;
    }
    a %= ADLER_MOD;
    b %= ADLER_MOD;

    out[0] = (uint8_t)(b >> 8u);
    out[1] = (uint8_t)(b);
    out[2] = (uint8_t)(a >> 8u);
    out[3] = (uint8_t)(a);
}
