/*
 * SipHash-2-4 (Aumasson + Bernstein, 2012) — keyed pseudorandom
 * function with a 64-bit output. Designed as a fast short-input MAC
 * to defend hash tables against collision-DoS, now the default hash
 * inside Python's `dict`, Rust's `HashMap`, Perl, Ruby, OpenDNS, …
 *
 * "2-4" = 2 SIPROUNDs per message block during absorb, 4 SIPROUNDs in
 * the finalisation. A SIPROUND is four 64-bit ARX operations on the
 * four-word state (v0,v1,v2,v3). The state is initialised by XOR'ing
 * the 128-bit key into a fixed magic vector.
 *
 * This benchmark uses the standard self-test key (bytes 0x00..0x0F).
 * Compare against the Aumasson/Bernstein reference implementation.
 */
#include "hashes.h"

#define ROL64(x,n) (((uint64_t)(x) << (n)) | ((uint64_t)(x) >> (64u - (n))))

#define SIPROUND(v0,v1,v2,v3) do {                       \
    v0 += v1;  v1 = ROL64(v1, 13);  v1 ^= v0;            \
    v0 = ROL64(v0, 32);                                  \
    v2 += v3;  v3 = ROL64(v3, 16);  v3 ^= v2;            \
    v0 += v3;  v3 = ROL64(v3, 21);  v3 ^= v0;            \
    v2 += v1;  v1 = ROL64(v1, 17);  v1 ^= v2;            \
    v2 = ROL64(v2, 32);                                  \
} while (0)

/* Standard self-test key — bytes 0x00..0x0F, packed little-endian. */
#define K0  0x0706050403020100ULL
#define K1  0x0F0E0D0C0B0A0908ULL

void hash_siphash24(const uint8_t *data, uint16_t len, uint8_t out[8]) HBENCH_BANKED {
    uint64_t v0 = K0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = K1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = K0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = K1 ^ 0x7465646279746573ULL;

    uint16_t off = 0u;
    uint16_t end = (uint16_t)(len & 0xFFF8u);   /* drop tail */
    uint64_t m, b;
    uint8_t  i;

    /* Absorb 8-byte blocks. */
    while (off < end) {
        const uint8_t *p = data + off;
        m = ((uint64_t)p[0])       | ((uint64_t)p[1] <<  8) |
            ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
            ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
            ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
        off = (uint16_t)(off + 8u);
    }

    /* Tail: pack remaining 0..7 bytes into the low part of `b`, with
     * the *low* byte of len in the top byte. */
    b = ((uint64_t)(len & 0xFFu)) << 56;
    {
        uint8_t rem = (uint8_t)(len - off);
        for (i = 0; i < rem; i++) {
            b |= ((uint64_t)data[off + i]) << (8u * i);
        }
    }

    v3 ^= b;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= b;

    /* Finalisation: 4 SIPROUNDs after xoring 0xFF into v2. */
    v2 ^= 0xFFu;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    {
        uint64_t h = v0 ^ v1 ^ v2 ^ v3;
        out[0] = (uint8_t)(h      ); out[1] = (uint8_t)(h >>  8);
        out[2] = (uint8_t)(h >> 16); out[3] = (uint8_t)(h >> 24);
        out[4] = (uint8_t)(h >> 32); out[5] = (uint8_t)(h >> 40);
        out[6] = (uint8_t)(h >> 48); out[7] = (uint8_t)(h >> 56);
    }
}
