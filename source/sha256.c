/*
 * SHA-256 (FIPS 180-4) — one-shot wrapper.
 *
 * 64-byte block, 32-byte digest. Same big-endian message-schedule layout
 * as SHA-1 but with two extra mixing functions (BSIG0/1 and SSIG0/1)
 * and a 64-entry round constant table. The constants live in ROM, so
 * they cost no RAM.
 *
 * W[] is a 16-entry sliding window like SHA-1's; static for the same
 * single-threaded reason.
 */
#include "hashes.h"

/* hash-bench-n64-optimized PERF: see md5.c — same single-file -O3
** + unroll-loops treatment, no hot/flatten.  Measured baseline →
** patched on Ares: SHA-256: 778 → 851 KB/s (+9%).  Modest win;
** SHA-256's W[] schedule has cross-iteration dependencies that
** limit how much unrolling helps. */
#if defined(__GNUC__) && (defined(__N64__) || defined(__mips__))
#  pragma GCC optimize ("O3,unroll-loops")
#endif

#define ROR32(x,n)  (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32u - (n))))
#define CH(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)    (ROR32(x,2u)  ^ ROR32(x,13u) ^ ROR32(x,22u))
#define BSIG1(x)    (ROR32(x,6u)  ^ ROR32(x,11u) ^ ROR32(x,25u))
#define SSIG0(x)    (ROR32(x,7u)  ^ ROR32(x,18u) ^ ((x) >> 3u))
#define SSIG1(x)    (ROR32(x,17u) ^ ROR32(x,19u) ^ ((x) >> 10u))

static const uint32_t K2[64] = {
    0x428A2F98UL,0x71374491UL,0xB5C0FBCFUL,0xE9B5DBA5UL,
    0x3956C25BUL,0x59F111F1UL,0x923F82A4UL,0xAB1C5ED5UL,
    0xD807AA98UL,0x12835B01UL,0x243185BEUL,0x550C7DC3UL,
    0x72BE5D74UL,0x80DEB1FEUL,0x9BDC06A7UL,0xC19BF174UL,
    0xE49B69C1UL,0xEFBE4786UL,0x0FC19DC6UL,0x240CA1CCUL,
    0x2DE92C6FUL,0x4A7484AAUL,0x5CB0A9DCUL,0x76F988DAUL,
    0x983E5152UL,0xA831C66DUL,0xB00327C8UL,0xBF597FC7UL,
    0xC6E00BF3UL,0xD5A79147UL,0x06CA6351UL,0x14292967UL,
    0x27B70A85UL,0x2E1B2138UL,0x4D2C6DFCUL,0x53380D13UL,
    0x650A7354UL,0x766A0ABBUL,0x81C2C92EUL,0x92722C85UL,
    0xA2BFE8A1UL,0xA81A664BUL,0xC24B8B70UL,0xC76C51A3UL,
    0xD192E819UL,0xD6990624UL,0xF40E3585UL,0x106AA070UL,
    0x19A4C116UL,0x1E376C08UL,0x2748774CUL,0x34B0BCB5UL,
    0x391C0CB3UL,0x4ED8AA4AUL,0x5B9CCA4FUL,0x682E6FF3UL,
    0x748F82EEUL,0x78A5636FUL,0x84C87814UL,0x8CC70208UL,
    0x90BEFFFAUL,0xA4506CEBUL,0xBEF9A3F7UL,0xC67178F2UL
};

static uint32_t W[16];

static void sha256_compress(uint32_t state[8], const uint8_t blk[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint8_t  i;

    for (i = 0; i < 16u; i++) {
        W[i] = ((uint32_t)blk[i*4u]      << 24u) |
               ((uint32_t)blk[i*4u + 1u] << 16u) |
               ((uint32_t)blk[i*4u + 2u] <<  8u) |
                (uint32_t)blk[i*4u + 3u];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64u; i++) {
        uint32_t w;
        if (i < 16u) {
            w = W[i];
        } else {
            uint8_t j  = (uint8_t)(i & 0x0Fu);
            uint8_t jm2 = (uint8_t)((i - 2u)  & 0x0Fu);
            uint8_t jm7 = (uint8_t)((i - 7u)  & 0x0Fu);
            uint8_t jm15= (uint8_t)((i - 15u) & 0x0Fu);
            w = SSIG1(W[jm2]) + W[jm7] + SSIG0(W[jm15]) + W[j];
            W[j] = w;
        }
        t1 = h + BSIG1(e) + CH(e, f, g) + K2[i] + w;
        t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void hash_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
        0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
    };
    uint8_t  block[64];
    uint16_t off;
    uint8_t  rem;
    uint32_t bit_count;
    uint8_t  i;

    for (off = 0; off + 64u <= len; off += 64u) {
        sha256_compress(state, data + off);
    }

    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem] = 0x80u;
    rem++;
    if (rem > 56u) {
        while (rem < 64u) block[rem++] = 0;
        sha256_compress(state, block);
        rem = 0;
    }
    while (rem < 56u) block[rem++] = 0;

    bit_count = (uint32_t)len << 3u;
    block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
    block[60] = (uint8_t)(bit_count >> 24u);
    block[61] = (uint8_t)(bit_count >> 16u);
    block[62] = (uint8_t)(bit_count >>  8u);
    block[63] = (uint8_t)(bit_count);
    sha256_compress(state, block);

    for (i = 0; i < 8u; i++) {
        out[i*4u]      = (uint8_t)(state[i] >> 24u);
        out[i*4u + 1u] = (uint8_t)(state[i] >> 16u);
        out[i*4u + 2u] = (uint8_t)(state[i] >>  8u);
        out[i*4u + 3u] = (uint8_t)(state[i]);
    }
}
