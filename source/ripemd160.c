/*
 * RIPEMD-160 — Belgian alternative to SHA-1, 160-bit output, 64-byte
 * block. Designed by Dobbertin / Bosselaers / Preneel (1996) after
 * weaknesses appeared in the original RIPEMD. Distinguished by running
 * TWO parallel pipelines (left + right) on every block with different
 * round functions, K constants, and message-word orderings — the final
 * state mixes the two halves.
 *
 * Best known today as the second hash in Bitcoin's RIPEMD160(SHA256(x))
 * address derivation. Slower than SHA-1 due to the doubled round work
 * but no published collisions to date (vs SHA-1's SHAttered in 2017).
 *
 * Compare against `hashlib.new('ripemd160', data).hexdigest()`.
 */
#include "hashes.h"

#define ROL32(x,n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32u - (n))))

/* Five round functions — one per round in each pipeline. */
#define F1(x,y,z) ((x) ^ (y) ^ (z))
#define F2(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
#define F3(x,y,z) (((x) | (~(y))) ^ (z))
#define F4(x,y,z) (((x) & (z)) | ((y) & (~(z))))
#define F5(x,y,z) ((x) ^ ((y) | (~(z))))

/* Message-word index for each step in left + right pipelines. */
static const uint8_t RL[80] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};
static const uint8_t RR[80] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

/* Per-step rotation amounts (left then right pipelines). */
static const uint8_t SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};
static const uint8_t SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

/* Per-round K constants (left then right). Five rounds × 16 steps. */
static const uint32_t KL[5] = {
    0x00000000UL, 0x5A827999UL, 0x6ED9EBA1UL, 0x8F1BBCDCUL, 0xA953FD4EUL
};
static const uint32_t KR[5] = {
    0x50A28BE6UL, 0x5C4DD124UL, 0x6D703EF3UL, 0x7A6D76E9UL, 0x00000000UL
};

static uint32_t M[16];

static void rmd_compress(uint32_t state[5], const uint8_t blk[64]) {
    uint32_t al, bl, cl, dl, el;
    uint32_t ar, br, cr, dr, er;
    uint32_t T;
    uint8_t  i;

    for (i = 0; i < 16u; i++) {
        M[i] = ((uint32_t)blk[i*4u])         |
               ((uint32_t)blk[i*4u + 1u] <<  8) |
               ((uint32_t)blk[i*4u + 2u] << 16) |
               ((uint32_t)blk[i*4u + 3u] << 24);
    }

    al = ar = state[0];
    bl = br = state[1];
    cl = cr = state[2];
    dl = dr = state[3];
    el = er = state[4];

    for (i = 0; i < 80u; i++) {
        uint32_t fl, fr, kl, kr;
        uint8_t  rd = (uint8_t)(i >> 4u);   /* round 0..4 */

        switch (rd) {
            case 0: fl = F1(bl, cl, dl); fr = F5(br, cr, dr); break;
            case 1: fl = F2(bl, cl, dl); fr = F4(br, cr, dr); break;
            case 2: fl = F3(bl, cl, dl); fr = F3(br, cr, dr); break;
            case 3: fl = F4(bl, cl, dl); fr = F2(br, cr, dr); break;
            default: fl = F5(bl, cl, dl); fr = F1(br, cr, dr); break;
        }
        kl = KL[rd]; kr = KR[rd];

        T  = ROL32(al + fl + M[RL[i]] + kl, SL[i]) + el;
        al = el; el = dl; dl = ROL32(cl, 10u); cl = bl; bl = T;

        T  = ROL32(ar + fr + M[RR[i]] + kr, SR[i]) + er;
        ar = er; er = dr; dr = ROL32(cr, 10u); cr = br; br = T;
    }

    /* Mix the two pipelines into the next state. */
    T        = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = T;
}

void hash_ripemd160(const uint8_t *data, uint16_t len, uint8_t out[20]) HBENCH_BANKED {
    /* IV — same as MD4 / SHA-1 with a fifth word added. */
    uint32_t state[5] = {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
    };
    uint8_t  block[64];
    uint16_t off;
    uint8_t  rem, i;
    uint32_t bit_count;

    for (off = 0; off + 64u <= len; off += 64u) {
        rmd_compress(state, data + off);
    }

    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem++] = 0x80u;
    if (rem > 56u) {
        while (rem < 64u) block[rem++] = 0;
        rmd_compress(state, block);
        rem = 0;
    }
    while (rem < 56u) block[rem++] = 0;

    /* Length: 64-bit little-endian. */
    bit_count = (uint32_t)len << 3u;
    block[56] = (uint8_t)(bit_count);
    block[57] = (uint8_t)(bit_count >>  8);
    block[58] = (uint8_t)(bit_count >> 16);
    block[59] = (uint8_t)(bit_count >> 24);
    block[60] = block[61] = block[62] = block[63] = 0u;
    rmd_compress(state, block);

    for (i = 0; i < 5u; i++) {
        out[i*4u]      = (uint8_t)(state[i]);
        out[i*4u + 1u] = (uint8_t)(state[i] >>  8);
        out[i*4u + 2u] = (uint8_t)(state[i] >> 16);
        out[i*4u + 3u] = (uint8_t)(state[i] >> 24);
    }
}
