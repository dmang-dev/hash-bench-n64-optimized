/*
 * xxHash64 — 64-bit successor to xxHash32 by Yann Collet. Same design
 * pattern: four 64-bit lanes accumulating 8-byte chunks, then the four
 * lanes are merged into a single 64-bit hash and fed through a finaliser.
 * Drop-in replacement when 32-bit collision probability is too high.
 *
 * Used by LZ4, Zstandard, RocksDB, ClickHouse, … Compare against
 * `xxhash.xxh64(data, seed=0).intdigest()` from the `xxhash` package
 * or `xxh64sum`'s output.
 *
 * Seed = 0 (no seed). Reference test vectors:
 *   xxh64("",   seed=0) = EF46DB3751D8E999
 *   xxh64(buf,  seed=0) = 149AA44972CDAE00   (buf = (i*31+7) & 0xFF, i<1024)
 */
#include "hashes.h"

#define ROL64(x,n) (((uint64_t)(x) << (n)) | ((uint64_t)(x) >> (64u - (n))))

#define P1 0x9E3779B185EBCA87ULL
#define P2 0xC2B2AE3D27D4EB4FULL
#define P3 0x165667B19E3779F9ULL
#define P4 0x85EBCA77C2B2AE63ULL
#define P5 0x27D4EB2F165667C5ULL

#define ROUND(acc, lane)                                          \
    do { (acc) += (lane) * P2; (acc) = ROL64((acc), 31u);         \
         (acc) *= P1; } while (0)

#define MERGE(acc, val)                                           \
    do { uint64_t _v = 0u; ROUND(_v, (val)); (acc) ^= _v;         \
         (acc) = (acc) * P1 + P4; } while (0)

static uint64_t read_u64_le(const uint8_t *p) {
    return ((uint64_t)p[0])       | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return ((uint32_t)p[0])       | ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void hash_xxh64(const uint8_t *data, uint16_t len, uint8_t out[8]) HBENCH_BANKED {
    uint64_t h64;
    uint16_t off = 0u;

    if (len >= 32u) {
        uint64_t v1 = (uint64_t)0u + P1 + P2;
        uint64_t v2 = (uint64_t)0u + P2;
        uint64_t v3 = (uint64_t)0u;
        uint64_t v4 = (uint64_t)0u - P1;

        while ((uint16_t)(off + 32u) <= len) {
            ROUND(v1, read_u64_le(data + off       ));
            ROUND(v2, read_u64_le(data + off + 8u  ));
            ROUND(v3, read_u64_le(data + off + 16u ));
            ROUND(v4, read_u64_le(data + off + 24u ));
            off = (uint16_t)(off + 32u);
        }

        h64 = ROL64(v1, 1u) + ROL64(v2, 7u) + ROL64(v3, 12u) + ROL64(v4, 18u);
        MERGE(h64, v1); MERGE(h64, v2); MERGE(h64, v3); MERGE(h64, v4);
    } else {
        h64 = (uint64_t)0u + P5;
    }

    h64 += (uint64_t)len;

    /* 8-byte tail blocks. */
    while ((uint16_t)(off + 8u) <= len) {
        uint64_t k = read_u64_le(data + off);
        ROUND(k, k);
        h64 ^= k;
        h64 = ROL64(h64, 27u) * P1 + P4;
        off = (uint16_t)(off + 8u);
    }
    /* 4-byte tail. */
    if ((uint16_t)(off + 4u) <= len) {
        h64 ^= ((uint64_t)read_u32_le(data + off)) * P1;
        h64 = ROL64(h64, 23u) * P2 + P3;
        off = (uint16_t)(off + 4u);
    }
    /* Single bytes. */
    while (off < len) {
        h64 ^= ((uint64_t)data[off]) * P5;
        h64 = ROL64(h64, 11u) * P1;
        off++;
    }

    /* Avalanche. */
    h64 ^= h64 >> 33; h64 *= P2;
    h64 ^= h64 >> 29; h64 *= P3;
    h64 ^= h64 >> 32;

    out[0] = (uint8_t)(h64      ); out[1] = (uint8_t)(h64 >>  8);
    out[2] = (uint8_t)(h64 >> 16); out[3] = (uint8_t)(h64 >> 24);
    out[4] = (uint8_t)(h64 >> 32); out[5] = (uint8_t)(h64 >> 40);
    out[6] = (uint8_t)(h64 >> 48); out[7] = (uint8_t)(h64 >> 56);
}
