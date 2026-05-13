/*
 * NOTE: this file's code + tables (~3 KB once SDCC's 32-bit math runtime
 * is amortised in) overflow the 32 KiB bank-0/1 budget on GB. The
 * `#pragma bank 2` below moves all of it into bank 2; the function is
 * declared `BANKED` so SDCC inserts an auto-trampoline at every call.
 * On GBA the pragma is ignored and HBENCH_BANKED expands to nothing.
 *
 * BLAKE2s-256 (RFC 7693) — modern cryptographic hash by Aumasson, Neves,
 * Wilcox-O'Hearn, Winnerlein (2012). Designed as a faster alternative
 * to SHA-2 with the same security profile; widely used by Argon2,
 * WireGuard, IPFS, NaCl, etc. The "s" variant has 32-bit words /
 * 64-byte block / up to 256-bit digest — sized for 32-bit CPUs (and
 * 8-bit toy benchmarks like this one).
 *
 * Mode: unkeyed, 256-bit output. Personalisation / salt parameters
 * are zero. Compare against `hashlib.blake2s(data).hexdigest()`.
 *
 * Implementation is the straight-from-RFC reference C — ten rounds
 * of eight G() invocations each, mixing eight working-state words
 * (h[]) with sixteen message words (m[]) via the sigma permutation.
 */
#include "hashes.h"

#ifdef __PORT_sm83
#pragma bank 2
#endif

#define ROR32(x,n) (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32u - (n))))

static const uint32_t IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

/* Message-word permutation — one row per round (10 rounds). */
static const uint8_t SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
};

/* Working state lifted off the stack — single-threaded GB / GBA. */
static uint32_t m[16];
static uint32_t v[16];

#define G(a,b,c,d,x,y)                       \
    v[a] = v[a] + v[b] + (x);                \
    v[d] = ROR32(v[d] ^ v[a], 16u);          \
    v[c] = v[c] + v[d];                      \
    v[b] = ROR32(v[b] ^ v[c], 12u);          \
    v[a] = v[a] + v[b] + (y);                \
    v[d] = ROR32(v[d] ^ v[a],  8u);          \
    v[c] = v[c] + v[d];                      \
    v[b] = ROR32(v[b] ^ v[c],  7u)

static void blake2s_compress(uint32_t h[8], const uint8_t blk[64],
                             uint32_t t0, uint32_t t1, uint8_t last)
{
    uint8_t i, r;

    for (i = 0; i < 16u; i++) {
        m[i] = ((uint32_t)blk[i*4u])         |
               ((uint32_t)blk[i*4u + 1u] <<  8u) |
               ((uint32_t)blk[i*4u + 2u] << 16u) |
               ((uint32_t)blk[i*4u + 3u] << 24u);
    }

    for (i = 0; i < 8u; i++) v[i]    = h[i];
    for (i = 0; i < 8u; i++) v[8u+i] = IV[i];
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    for (r = 0; r < 10u; r++) {
        const uint8_t *s = SIGMA[r];
        G(0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        G(0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8u; i++) h[i] ^= v[i] ^ v[i + 8u];
}

void hash_blake2s(const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED {
    uint32_t h[8];
    uint8_t  block[64];
    uint16_t off, processed;
    uint8_t  i, rem;

    /* Parameter block — unkeyed, 32-byte digest, no salt/personal. The
     * RFC mandates this xor-in pattern on h[0]:
     *   digest_length | (key_length << 8) | (fanout << 16) | (depth << 24)
     *   = 0x01010020  for 32-byte output, 0 key, fanout 1, depth 1. */
    for (i = 0; i < 8u; i++) h[i] = IV[i];
    h[0] ^= 0x01010020UL;

    processed = 0u;
    for (off = 0; off + 64u < len; off += 64u) {
        processed = (uint16_t)(processed + 64u);
        blake2s_compress(h, data + off, (uint32_t)processed, 0u, 0u);
    }

    /* Final block — pad with zeros, last=true. The counter must reflect
     * the *total* bytes hashed including the final (potentially partial)
     * block, not the block-aligned amount. */
    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    while (rem < 64u) block[rem++] = 0;
    processed = (uint16_t)(processed + (uint16_t)(len - off));
    blake2s_compress(h, block, (uint32_t)processed, 0u, 1u);

    for (i = 0; i < 8u; i++) {
        out[i*4u]      = (uint8_t)(h[i]);
        out[i*4u + 1u] = (uint8_t)(h[i] >>  8u);
        out[i*4u + 2u] = (uint8_t)(h[i] >> 16u);
        out[i*4u + 3u] = (uint8_t)(h[i] >> 24u);
    }
}
