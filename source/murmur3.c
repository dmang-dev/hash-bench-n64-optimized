/*
 * MurmurHash3 32-bit by Austin Appleby — workhorse non-cryptographic
 * hash used by Hadoop, Cassandra, Guava, libstdc++ unordered_map,
 * Redis, … Wikipedia or the upstream SMHasher repo for full spec.
 *
 * Block size is 4 bytes; tail handler covers 0/1/2/3 trailing bytes.
 * The two multiplies + two rotates per block are why it benchmarks
 * faster than FNV-1a on platforms with a real MUL (GBA) but barely
 * different on the GB where every 32×32 multiply is synthesised.
 *
 * Seed = 0 — the standard "no seed" call, matches `mmh3.hash(data)`
 * in Python with `seed=0` and `signed=False`.
 */
#include "hashes.h"

#define MM3_C1   0xCC9E2D51UL
#define MM3_C2   0x1B873593UL
#define MM3_M    5u
#define MM3_N    0xE6546B64UL

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

void hash_murmur3(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 0u;
    uint16_t nblocks = (uint16_t)(len >> 2u);
    uint16_t i;
    uint32_t k;
    const uint8_t *p;
    const uint8_t *tail;
    uint8_t  rem;

    /* Body — 4-byte little-endian blocks. */
    p = data;
    for (i = 0; i < nblocks; i++) {
        k = ((uint32_t)p[0])         | ((uint32_t)p[1] <<  8u)
          | ((uint32_t)p[2] << 16u)  | ((uint32_t)p[3] << 24u);
        k *= MM3_C1;
        k  = ROL32(k, 15u);
        k *= MM3_C2;

        h ^= k;
        h  = ROL32(h, 13u);
        h  = h * MM3_M + MM3_N;
        p += 4u;
    }

    /* Tail — 0..3 unprocessed bytes. */
    tail = data + (nblocks * 4u);
    rem  = (uint8_t)(len & 0x03u);
    k    = 0u;
    if (rem >= 3u) k ^= (uint32_t)tail[2] << 16u;
    if (rem >= 2u) k ^= (uint32_t)tail[1] <<  8u;
    if (rem >= 1u) {
        k ^= (uint32_t)tail[0];
        k *= MM3_C1;
        k  = ROL32(k, 15u);
        k *= MM3_C2;
        h ^= k;
    }

    /* Finalize — fmix32. */
    h ^= (uint32_t)len;
    h ^= h >> 16u; h *= 0x85EBCA6BUL;
    h ^= h >> 13u; h *= 0xC2B2AE35UL;
    h ^= h >> 16u;

    out[0] = (uint8_t)(h >> 24u);
    out[1] = (uint8_t)(h >> 16u);
    out[2] = (uint8_t)(h >>  8u);
    out[3] = (uint8_t)(h);
}
