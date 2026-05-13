/*
 * MurmurHash3 x64 128-bit by Austin Appleby — the 128-bit sibling of
 * Murmur3-32 in murmur3.c. Two 64-bit lanes (h1, h2) accumulate
 * 16-byte blocks via two mixing functions, then a 128-bit final
 * mixer (`fmix64` on each half plus cross-mixing).
 *
 * Used wherever 32-bit collision probability is uncomfortable but
 * cryptographic strength isn't needed: ClickHouse, parts of Apache
 * Hive, libstdc++ unordered_map (with seed), …
 *
 * Two variants exist in the upstream SMHasher: x86 (4 × uint32_t lanes)
 * and x64 (2 × uint64_t lanes). They produce DIFFERENT 128-bit outputs
 * for the same input. We implement the x64 form, which matches Python's
 * `mmh3.hash128(data, x64arch=True)` and Java's Guava
 * `Hashing.murmur3_128()`.
 *
 * Seed = 0. Reference: murmur3_x64_128(buf) =
 *   81DFF2B157E1F18581A9A5A4204401E6
 * (h1 is the high 64 bits, h2 the low — i.e. the on-screen first 4
 *  bytes will read 85 F1 E1 57.)
 */
#include "hashes.h"

#define ROL64(x,n) (((uint64_t)(x) << (n)) | ((uint64_t)(x) >> (64u - (n))))

#define M3_C1   0x87C37B91114253D5ULL
#define M3_C2   0x4CF5AD432745937FULL

static uint64_t fmix64(uint64_t k) {
    k ^= k >> 33; k *= 0xFF51AFD7ED558CCDULL;
    k ^= k >> 33; k *= 0xC4CEB9FE1A85EC53ULL;
    k ^= k >> 33;
    return k;
}

void hash_murmur3_128(const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED {
    uint64_t h1 = 0u, h2 = 0u;
    uint16_t nblocks = (uint16_t)(len >> 4u);
    uint16_t i;
    uint64_t k1, k2;
    const uint8_t *p;
    const uint8_t *tail;
    uint8_t  rem;

    /* Body — 16-byte little-endian blocks. */
    p = data;
    for (i = 0; i < nblocks; i++) {
        k1 = ((uint64_t)p[ 0])       | ((uint64_t)p[ 1] <<  8) |
             ((uint64_t)p[ 2] << 16) | ((uint64_t)p[ 3] << 24) |
             ((uint64_t)p[ 4] << 32) | ((uint64_t)p[ 5] << 40) |
             ((uint64_t)p[ 6] << 48) | ((uint64_t)p[ 7] << 56);
        k2 = ((uint64_t)p[ 8])       | ((uint64_t)p[ 9] <<  8) |
             ((uint64_t)p[10] << 16) | ((uint64_t)p[11] << 24) |
             ((uint64_t)p[12] << 32) | ((uint64_t)p[13] << 40) |
             ((uint64_t)p[14] << 48) | ((uint64_t)p[15] << 56);

        k1 *= M3_C1; k1 = ROL64(k1, 31u); k1 *= M3_C2; h1 ^= k1;
        h1 = ROL64(h1, 27u); h1 += h2; h1 = h1 * 5u + 0x52DCE729ULL;

        k2 *= M3_C2; k2 = ROL64(k2, 33u); k2 *= M3_C1; h2 ^= k2;
        h2 = ROL64(h2, 31u); h2 += h1; h2 = h2 * 5u + 0x38495AB5ULL;
        p += 16u;
    }

    /* Tail — 0..15 unprocessed bytes split into k1 (low 8) and k2 (high 8). */
    tail = data + (nblocks * 16u);
    rem  = (uint8_t)(len & 0x0Fu);
    k1 = 0u; k2 = 0u;
    if (rem >= 15u) k2 ^= (uint64_t)tail[14] << 48;
    if (rem >= 14u) k2 ^= (uint64_t)tail[13] << 40;
    if (rem >= 13u) k2 ^= (uint64_t)tail[12] << 32;
    if (rem >= 12u) k2 ^= (uint64_t)tail[11] << 24;
    if (rem >= 11u) k2 ^= (uint64_t)tail[10] << 16;
    if (rem >= 10u) k2 ^= (uint64_t)tail[ 9] <<  8;
    if (rem >=  9u) {
        k2 ^= (uint64_t)tail[ 8];
        k2 *= M3_C2; k2 = ROL64(k2, 33u); k2 *= M3_C1; h2 ^= k2;
    }
    if (rem >=  8u) k1 ^= (uint64_t)tail[ 7] << 56;
    if (rem >=  7u) k1 ^= (uint64_t)tail[ 6] << 48;
    if (rem >=  6u) k1 ^= (uint64_t)tail[ 5] << 40;
    if (rem >=  5u) k1 ^= (uint64_t)tail[ 4] << 32;
    if (rem >=  4u) k1 ^= (uint64_t)tail[ 3] << 24;
    if (rem >=  3u) k1 ^= (uint64_t)tail[ 2] << 16;
    if (rem >=  2u) k1 ^= (uint64_t)tail[ 1] <<  8;
    if (rem >=  1u) {
        k1 ^= (uint64_t)tail[ 0];
        k1 *= M3_C1; k1 = ROL64(k1, 31u); k1 *= M3_C2; h1 ^= k1;
    }

    /* Finalisation. */
    h1 ^= (uint64_t)len;
    h2 ^= (uint64_t)len;
    h1 += h2;
    h2 += h1;
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 += h2;
    h2 += h1;

    /* Output: h1 in low 8 bytes, h2 in high 8 bytes (little-endian). */
    out[ 0] = (uint8_t)(h1      ); out[ 1] = (uint8_t)(h1 >>  8);
    out[ 2] = (uint8_t)(h1 >> 16); out[ 3] = (uint8_t)(h1 >> 24);
    out[ 4] = (uint8_t)(h1 >> 32); out[ 5] = (uint8_t)(h1 >> 40);
    out[ 6] = (uint8_t)(h1 >> 48); out[ 7] = (uint8_t)(h1 >> 56);
    out[ 8] = (uint8_t)(h2      ); out[ 9] = (uint8_t)(h2 >>  8);
    out[10] = (uint8_t)(h2 >> 16); out[11] = (uint8_t)(h2 >> 24);
    out[12] = (uint8_t)(h2 >> 32); out[13] = (uint8_t)(h2 >> 40);
    out[14] = (uint8_t)(h2 >> 48); out[15] = (uint8_t)(h2 >> 56);
}
