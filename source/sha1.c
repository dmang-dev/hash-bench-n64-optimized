/*
 * SHA-1 (FIPS 180-4) — one-shot wrapper that takes a flat buffer and
 * writes a 20-byte digest. Identical algorithm to the streaming
 * implementation in totp-gb / totp-gba, just flattened into a single
 * call so the benchmark harness can time it without ctx setup overhead.
 *
 * W[] is a 16-entry sliding window (saves 256 B of stack vs W[80]).
 * static -> not reentrant, fine on single-threaded GB / GBA.
 */
#include "hashes.h"

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

static const uint32_t K1[4] = {
    0x5A827999UL, 0x6ED9EBA1UL, 0x8F1BBCDCUL, 0xCA62C1D6UL
};

static uint32_t W[16];

static void sha1_compress(uint32_t state[5], const uint8_t *blk) {
    uint32_t a, b, c, d, e, temp, f, k;
    uint8_t  i;

    for (i = 0; i < 16u; i++) {
        W[i] = ((uint32_t)blk[i*4u]      << 24u) |
               ((uint32_t)blk[i*4u + 1u] << 16u) |
               ((uint32_t)blk[i*4u + 2u] <<  8u) |
                (uint32_t)blk[i*4u + 3u];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 80u; i++) {
        if (i >= 16u) {
            uint8_t j = (uint8_t)(i & 0x0Fu);
            W[j] = ROL32(W[(i-3u)  & 0x0Fu] ^
                         W[(i-8u)  & 0x0Fu] ^
                         W[(i-14u) & 0x0Fu] ^
                         W[j], 1u);
        }
        /* K rotates every 20 rounds, not every 32 — see totp-gb sha1.c
         * for the cautionary tale that motivated this comment. */
        if      (i < 20u) { f = (b & c) | ((~b) & d);          k = K1[0]; }
        else if (i < 40u) { f = b ^ c ^ d;                     k = K1[1]; }
        else if (i < 60u) { f = (b & c) | (b & d) | (c & d);   k = K1[2]; }
        else              { f = b ^ c ^ d;                     k = K1[3]; }

        temp = ROL32(a, 5u) + f + e + k + W[i & 0x0Fu];
        e = d; d = c; c = ROL32(b, 30u); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

void hash_sha1(const uint8_t *data, uint16_t len, uint8_t out[20]) {
    uint32_t state[5] = {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL,
        0x10325476UL, 0xC3D2E1F0UL
    };
    uint8_t  block[64];
    uint16_t off;
    uint8_t  rem;
    uint32_t bit_count;
    uint8_t  i;

    for (off = 0; off + 64u <= len; off += 64u) {
        sha1_compress(state, data + off);
    }

    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem] = 0x80u;
    rem++;
    if (rem > 56u) {
        while (rem < 64u) block[rem++] = 0;
        sha1_compress(state, block);
        rem = 0;
    }
    while (rem < 56u) block[rem++] = 0;

    bit_count = (uint32_t)len << 3u;
    block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
    block[60] = (uint8_t)(bit_count >> 24u);
    block[61] = (uint8_t)(bit_count >> 16u);
    block[62] = (uint8_t)(bit_count >>  8u);
    block[63] = (uint8_t)(bit_count);
    sha1_compress(state, block);

    for (i = 0; i < 5u; i++) {
        out[i*4u]      = (uint8_t)(state[i] >> 24u);
        out[i*4u + 1u] = (uint8_t)(state[i] >> 16u);
        out[i*4u + 2u] = (uint8_t)(state[i] >>  8u);
        out[i*4u + 3u] = (uint8_t)(state[i]);
    }
}
