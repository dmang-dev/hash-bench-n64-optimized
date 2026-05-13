/*
 * xxHash32 by Yann Collet — a fast, high-quality non-cryptographic
 * hash. https://github.com/Cyan4973/xxHash
 *
 * Implements the streaming-equivalent "one shot" form: 4 lanes of
 * ARX (add, rotate, xor-not — actually mul/rot/add) for the bulk
 * 16-byte stride, then a finalizer.
 *
 * Heavy on 32-bit multiplies. Designed to be roughly memcpy-speed on
 * modern x86; the SM83 has no native MUL so this benchmark reveals
 * just how punishing 32x32-bit MULTU lowering is on an 8-bit CPU.
 */
#include "hashes.h"

#define XXH_PRIME1 0x9E3779B1UL
#define XXH_PRIME2 0x85EBCA77UL
#define XXH_PRIME3 0xC2B2AE3DUL
#define XXH_PRIME4 0x27D4EB2FUL
#define XXH_PRIME5 0x165667B1UL

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

static uint32_t xxh_round(uint32_t acc, uint32_t input) {
    acc += input * XXH_PRIME2;
    acc  = ROL32(acc, 13u);
    acc *= XXH_PRIME1;
    return acc;
}

void hash_xxh32(const uint8_t *data, uint16_t len, uint8_t out[4]) {
    const uint32_t SEED = 0u;
    uint32_t h;
    const uint8_t *p   = data;
    const uint8_t *end = data + len;

    if (len >= 16u) {
        uint32_t v1 = SEED + XXH_PRIME1 + XXH_PRIME2;
        uint32_t v2 = SEED + XXH_PRIME2;
        uint32_t v3 = SEED;
        uint32_t v4 = SEED - XXH_PRIME1;
        const uint8_t *limit = end - 16u;

        do {
            uint32_t w;
            w  = ((uint32_t)p[0])         | ((uint32_t)p[1]  <<  8u)
               | ((uint32_t)p[2]  << 16u) | ((uint32_t)p[3]  << 24u);
            v1 = xxh_round(v1, w);
            w  = ((uint32_t)p[4])         | ((uint32_t)p[5]  <<  8u)
               | ((uint32_t)p[6]  << 16u) | ((uint32_t)p[7]  << 24u);
            v2 = xxh_round(v2, w);
            w  = ((uint32_t)p[8])         | ((uint32_t)p[9]  <<  8u)
               | ((uint32_t)p[10] << 16u) | ((uint32_t)p[11] << 24u);
            v3 = xxh_round(v3, w);
            w  = ((uint32_t)p[12])        | ((uint32_t)p[13] <<  8u)
               | ((uint32_t)p[14] << 16u) | ((uint32_t)p[15] << 24u);
            v4 = xxh_round(v4, w);
            p += 16u;
        } while (p <= limit);

        h = ROL32(v1, 1u) + ROL32(v2, 7u) + ROL32(v3, 12u) + ROL32(v4, 18u);
    } else {
        h = SEED + XXH_PRIME5;
    }

    h += (uint32_t)len;

    while (p + 4u <= end) {
        uint32_t w = ((uint32_t)p[0])        | ((uint32_t)p[1] <<  8u)
                   | ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
        h += w * XXH_PRIME3;
        h  = ROL32(h, 17u) * XXH_PRIME4;
        p += 4u;
    }
    while (p < end) {
        h += (uint32_t)(*p) * XXH_PRIME5;
        h  = ROL32(h, 11u) * XXH_PRIME1;
        p++;
    }

    h ^= h >> 15u; h *= XXH_PRIME2;
    h ^= h >> 13u; h *= XXH_PRIME3;
    h ^= h >> 16u;

    /* xxHash32 canonical output is big-endian. */
    out[0] = (uint8_t)(h >> 24u);
    out[1] = (uint8_t)(h >> 16u);
    out[2] = (uint8_t)(h >>  8u);
    out[3] = (uint8_t)(h);
}
