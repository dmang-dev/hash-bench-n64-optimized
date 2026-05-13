/*
 * MD5 (RFC 1321) — one-shot wrapper over the textbook 64-byte block
 * compression. Init constants and per-round S/K tables match the spec.
 *
 * Kept independent of the SHA1/SHA256 buffers so each algorithm is
 * benchmarkable in isolation. The on-stack 64-byte block buffer is the
 * largest stack footprint of any algorithm here (still fine on the GB).
 */
#include "hashes.h"
#include <string.h>

/* hash-bench-n64-optimized PERF: -O3 + unroll-loops on this file only.
** libdragon's n64.mk ships -O2 across the project; opt this file into
** the heavier transforms because MD5's round loop is straight-line
** state (4 uint32 working regs) that gcc can fully register-allocate
** after unrolling.  Measured baseline → patched on Ares:
**   MD5: 1878 → 2432 KB/s  (+29%)
** No hot/flatten attribute on md5_compress — adding it earlier shifted
** other algos' .text into conflicting I-cache slots on VR4300 and
** dropped SHA-3 by 47% with zero changes to sha3.c.  See the upstream
** hash-bench-n64 reverted-commit log for the postmortem. */
#if defined(__GNUC__) && (defined(__N64__) || defined(__mips__))
#  pragma GCC optimize ("O3,unroll-loops")
#endif

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

static const uint8_t S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static const uint32_t K[64] = {
    0xD76AA478UL,0xE8C7B756UL,0x242070DBUL,0xC1BDCEEEUL,
    0xF57C0FAFUL,0x4787C62AUL,0xA8304613UL,0xFD469501UL,
    0x698098D8UL,0x8B44F7AFUL,0xFFFF5BB1UL,0x895CD7BEUL,
    0x6B901122UL,0xFD987193UL,0xA679438EUL,0x49B40821UL,
    0xF61E2562UL,0xC040B340UL,0x265E5A51UL,0xE9B6C7AAUL,
    0xD62F105DUL,0x02441453UL,0xD8A1E681UL,0xE7D3FBC8UL,
    0x21E1CDE6UL,0xC33707D6UL,0xF4D50D87UL,0x455A14EDUL,
    0xA9E3E905UL,0xFCEFA3F8UL,0x676F02D9UL,0x8D2A4C8AUL,
    0xFFFA3942UL,0x8771F681UL,0x6D9D6122UL,0xFDE5380CUL,
    0xA4BEEA44UL,0x4BDECFA9UL,0xF6BB4B60UL,0xBEBFBC70UL,
    0x289B7EC6UL,0xEAA127FAUL,0xD4EF3085UL,0x04881D05UL,
    0xD9D4D039UL,0xE6DB99E5UL,0x1FA27CF8UL,0xC4AC5665UL,
    0xF4292244UL,0x432AFF97UL,0xAB9423A7UL,0xFC93A039UL,
    0x655B59C3UL,0x8F0CCC92UL,0xFFEFF47DUL,0x85845DD1UL,
    0x6FA87E4FUL,0xFE2CE6E0UL,0xA3014314UL,0x4E0811A1UL,
    0xF7537E82UL,0xBD3AF235UL,0x2AD7D2BBUL,0xEB86D391UL
};

/* Like SHA-1's W[], lifted off the stack to keep MD5 cheap on the GB. */
static uint32_t M[16];

static void md5_compress(uint32_t state[4], const uint8_t blk[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t f, g, temp;
    uint8_t  i;

    for (i = 0; i < 16u; i++) {
        M[i] = ((uint32_t)blk[i*4u])         |
               ((uint32_t)blk[i*4u + 1u] <<  8u) |
               ((uint32_t)blk[i*4u + 2u] << 16u) |
               ((uint32_t)blk[i*4u + 3u] << 24u);
    }

    for (i = 0; i < 64u; i++) {
        if      (i < 16u) { f = (b & c) | ((~b) & d);   g = i; }
        else if (i < 32u) { f = (d & b) | ((~d) & c);   g = (uint8_t)((5u*i + 1u) & 0x0Fu); }
        else if (i < 48u) { f = b ^ c ^ d;              g = (uint8_t)((3u*i + 5u) & 0x0Fu); }
        else              { f = c ^ (b | (~d));         g = (uint8_t)((7u*i)      & 0x0Fu); }

        temp = d;
        d = c;
        c = b;
        b = b + ROL32(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void hash_md5(const uint8_t *data, uint16_t len, uint8_t out[16]) {
    uint32_t state[4] = {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL
    };
    uint8_t  block[64];
    uint16_t off;
    uint8_t  rem;
    uint32_t bit_count;
    uint8_t  i;

    for (off = 0; off + 64u <= len; off += 64u) {
        md5_compress(state, data + off);
    }

    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem] = 0x80u;
    rem++;
    if (rem > 56u) {
        while (rem < 64u) block[rem++] = 0;
        md5_compress(state, block);
        rem = 0;
    }
    while (rem < 56u) block[rem++] = 0;

    bit_count = (uint32_t)len << 3u;
    block[56] = (uint8_t)(bit_count);
    block[57] = (uint8_t)(bit_count >>  8u);
    block[58] = (uint8_t)(bit_count >> 16u);
    block[59] = (uint8_t)(bit_count >> 24u);
    block[60] = 0; block[61] = 0; block[62] = 0; block[63] = 0;
    md5_compress(state, block);

    for (i = 0; i < 4u; i++) {
        out[i*4u]      = (uint8_t)(state[i]);
        out[i*4u + 1u] = (uint8_t)(state[i] >>  8u);
        out[i*4u + 2u] = (uint8_t)(state[i] >> 16u);
        out[i*4u + 3u] = (uint8_t)(state[i] >> 24u);
    }
}
