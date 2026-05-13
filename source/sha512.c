/*
 * SHA-512 (FIPS 180-4 §6.4) — 64-bit-word sibling of SHA-256, 128-byte
 * block, 80 rounds, 64-byte output.
 *
 * Designed for 64-bit hardware: every round mixes eight 64-bit words
 * with rotates, XORs, and 64-bit adds. ARM7TDMI / ARM946E lack a
 * native 64-bit ALU, so each `uint64_t` op compiles into 2-3 ARM
 * instructions — but it still flies on the 33 MHz NDS ARM9 (this is
 * the algorithm where the GB / GBA SHA-256 spread becomes the
 * NDS / GBA SHA-512 story).
 *
 * Compare against `hashlib.sha512(data).hexdigest()`.
 */
#include "hashes.h"

/* hash-bench-n64-optimized PERF: see md5.c — single-file -O3 + unroll
** treatment, no hot/flatten.  Measured baseline → patched on Ares:
**   SHA-512: 1379 → 1569 KB/s  (+14%)
** This is the biggest absolute jump in the family because SHA-512
** runs on native uint64 instructions on VR4300 (daddu/dsrlv/dxor),
** and unrolling exposes more of them to gcc's instruction scheduler
** without spilling. */
#if defined(__GNUC__) && (defined(__N64__) || defined(__mips__))
#  pragma GCC optimize ("O3,unroll-loops")
#endif

#define ROR64(x,n) (((uint64_t)(x) >> (n)) | ((uint64_t)(x) << (64u - (n))))
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)    (ROR64(x,28) ^ ROR64(x,34) ^ ROR64(x,39))
#define BSIG1(x)    (ROR64(x,14) ^ ROR64(x,18) ^ ROR64(x,41))
#define SSIG0(x)    (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define SSIG1(x)    (ROR64(x,19) ^ ROR64(x,61) ^ ((x) >> 6))

/* First 64 bits of fractional parts of the cube roots of the first 80
 * primes — the standard SHA-512 K table (FIPS 180-4 §4.2.3). */
static const uint64_t K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

static uint64_t W[80];   /* lift the message schedule off the stack */

static void sha512_compress(uint64_t state[8], const uint8_t blk[128]) {
    uint64_t a, b, c, d, e, f, g, h, T1, T2;
    uint8_t  i;

    /* Big-endian byte → 64-bit word. */
    for (i = 0; i < 16u; i++) {
        const uint8_t *p = blk + (uint16_t)i * 8u;
        W[i] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
               ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
               ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
               ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]      );
    }
    for (i = 16; i < 80u; i++) {
        W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80u; i++) {
        T1 = h + BSIG1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = BSIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void hash_sha512(const uint8_t *data, uint16_t len, uint8_t out[64]) HBENCH_BANKED {
    /* SHA-512 IV — first 64 bits of fractional parts of square roots
     * of the first 8 primes (FIPS 180-4 §5.3.5). */
    uint64_t state[8] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
        0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
    };
    uint8_t  block[128];
    uint16_t off;
    uint8_t  rem, i;
    uint64_t bit_count;

    for (off = 0; off + 128u <= len; off += 128u) {
        sha512_compress(state, data + off);
    }

    /* Final block(s) — 0x80, zero pad, 128-bit BE length in last 16 bytes.
     * Length here is always small enough that the high u64 is zero. */
    rem = (uint8_t)(len - off);
    for (i = 0; i < rem; i++) block[i] = data[off + i];
    block[rem++] = 0x80u;
    if (rem > 112u) {
        while (rem < 128u) block[rem++] = 0;
        sha512_compress(state, block);
        rem = 0;
    }
    while (rem < 112u) block[rem++] = 0;

    bit_count = (uint64_t)len << 3u;
    /* High 64 bits of the 128-bit length: always zero for our buffer
     * sizes, but write them out properly so the implementation stays
     * spec-compliant for callers passing >2 GiB inputs (theoretical). */
    for (i = 0; i < 8u; i++) block[112 + i] = 0u;
    block[120] = (uint8_t)(bit_count >> 56);
    block[121] = (uint8_t)(bit_count >> 48);
    block[122] = (uint8_t)(bit_count >> 40);
    block[123] = (uint8_t)(bit_count >> 32);
    block[124] = (uint8_t)(bit_count >> 24);
    block[125] = (uint8_t)(bit_count >> 16);
    block[126] = (uint8_t)(bit_count >>  8);
    block[127] = (uint8_t)(bit_count      );
    sha512_compress(state, block);

    for (i = 0; i < 8u; i++) {
        uint64_t v = state[i];
        out[i*8u]      = (uint8_t)(v >> 56);
        out[i*8u + 1u] = (uint8_t)(v >> 48);
        out[i*8u + 2u] = (uint8_t)(v >> 40);
        out[i*8u + 3u] = (uint8_t)(v >> 32);
        out[i*8u + 4u] = (uint8_t)(v >> 24);
        out[i*8u + 5u] = (uint8_t)(v >> 16);
        out[i*8u + 6u] = (uint8_t)(v >>  8);
        out[i*8u + 7u] = (uint8_t)(v      );
    }
}
