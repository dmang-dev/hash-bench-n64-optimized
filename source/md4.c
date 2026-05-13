/*
 * MD4 (RFC 1320) — Rivest's 1990 design, predecessor to MD5 (and
 * structural ancestor of SHA-1 / RIPEMD). Same 64-byte block / 512-bit
 * digest-padding layout, but only 3 rounds × 16 ops instead of MD5's
 * 4 × 16 — so ~25% fewer operations per block. Catastrophically broken
 * cryptographically (Wang 2005 found collisions in microseconds), but
 * still in use as part of NT LAN Manager (NTLM) password hashing,
 * which is why it lingers in CTF and security benchmark contexts.
 *
 * Length field is little-endian (unlike SHA-1 / SHA-256), and the
 * final state is also written little-endian.
 */
#include "hashes.h"

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

#define F(x,y,z)  (((x) & (y)) | ((~(x)) & (z)))
#define G(x,y,z)  (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x,y,z)  ((x) ^ (y) ^ (z))

#define FF(a,b,c,d,k,s) (a) = ROL32((a) + F((b),(c),(d)) + M[(k)],                  (s))
#define GG(a,b,c,d,k,s) (a) = ROL32((a) + G((b),(c),(d)) + M[(k)] + 0x5A827999UL,   (s))
#define HH(a,b,c,d,k,s) (a) = ROL32((a) + H((b),(c),(d)) + M[(k)] + 0x6ED9EBA1UL,   (s))

/* Block message words — like SHA-1's W[], lifted off the stack. */
static uint32_t M[16];

static void md4_compress(uint32_t state[4], const uint8_t blk[64]) {
    uint32_t a, b, c, d;
    uint8_t  i;

    for (i = 0; i < 16u; i++) {
        M[i] = ((uint32_t)blk[i*4u])         |
               ((uint32_t)blk[i*4u + 1u] <<  8u) |
               ((uint32_t)blk[i*4u + 2u] << 16u) |
               ((uint32_t)blk[i*4u + 3u] << 24u);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];

    /* Round 1 — 16 ops, shifts 3/7/11/19, no K addend. */
    FF(a,b,c,d, 0u, 3u);  FF(d,a,b,c, 1u, 7u);  FF(c,d,a,b, 2u,11u);  FF(b,c,d,a, 3u,19u);
    FF(a,b,c,d, 4u, 3u);  FF(d,a,b,c, 5u, 7u);  FF(c,d,a,b, 6u,11u);  FF(b,c,d,a, 7u,19u);
    FF(a,b,c,d, 8u, 3u);  FF(d,a,b,c, 9u, 7u);  FF(c,d,a,b,10u,11u);  FF(b,c,d,a,11u,19u);
    FF(a,b,c,d,12u, 3u);  FF(d,a,b,c,13u, 7u);  FF(c,d,a,b,14u,11u);  FF(b,c,d,a,15u,19u);

    /* Round 2 — 16 ops, message-word stride 4, K=0x5A827999. */
    GG(a,b,c,d, 0u, 3u);  GG(d,a,b,c, 4u, 5u);  GG(c,d,a,b, 8u, 9u);  GG(b,c,d,a,12u,13u);
    GG(a,b,c,d, 1u, 3u);  GG(d,a,b,c, 5u, 5u);  GG(c,d,a,b, 9u, 9u);  GG(b,c,d,a,13u,13u);
    GG(a,b,c,d, 2u, 3u);  GG(d,a,b,c, 6u, 5u);  GG(c,d,a,b,10u, 9u);  GG(b,c,d,a,14u,13u);
    GG(a,b,c,d, 3u, 3u);  GG(d,a,b,c, 7u, 5u);  GG(c,d,a,b,11u, 9u);  GG(b,c,d,a,15u,13u);

    /* Round 3 — 16 ops, message-word "perfect-shuffle" order, K=0x6ED9EBA1. */
    HH(a,b,c,d, 0u, 3u);  HH(d,a,b,c, 8u, 9u);  HH(c,d,a,b, 4u,11u);  HH(b,c,d,a,12u,15u);
    HH(a,b,c,d, 2u, 3u);  HH(d,a,b,c,10u, 9u);  HH(c,d,a,b, 6u,11u);  HH(b,c,d,a,14u,15u);
    HH(a,b,c,d, 1u, 3u);  HH(d,a,b,c, 9u, 9u);  HH(c,d,a,b, 5u,11u);  HH(b,c,d,a,13u,15u);
    HH(a,b,c,d, 3u, 3u);  HH(d,a,b,c,11u, 9u);  HH(c,d,a,b, 7u,11u);  HH(b,c,d,a,15u,15u);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void hash_md4(const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED {
    uint32_t state[4] = {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL
    };
    uint8_t  block[64];
    uint16_t off;
    uint8_t  rem;
    uint32_t bit_count;
    uint8_t  i;

    for (off = 0; off + 64u <= len; off += 64u) {
        md4_compress(state, data + off);
    }

    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem] = 0x80u;
    rem++;
    if (rem > 56u) {
        while (rem < 64u) block[rem++] = 0;
        md4_compress(state, block);
        rem = 0;
    }
    while (rem < 56u) block[rem++] = 0;

    /* Length as little-endian 64-bit (high 32 bits always 0 here). */
    bit_count = (uint32_t)len << 3u;
    block[56] = (uint8_t)(bit_count);
    block[57] = (uint8_t)(bit_count >>  8u);
    block[58] = (uint8_t)(bit_count >> 16u);
    block[59] = (uint8_t)(bit_count >> 24u);
    block[60] = 0; block[61] = 0; block[62] = 0; block[63] = 0;
    md4_compress(state, block);

    for (i = 0; i < 4u; i++) {
        out[i*4u]      = (uint8_t)(state[i]);
        out[i*4u + 1u] = (uint8_t)(state[i] >>  8u);
        out[i*4u + 2u] = (uint8_t)(state[i] >> 16u);
        out[i*4u + 3u] = (uint8_t)(state[i] >> 24u);
    }
}
