/*
 * AES-128 CBC-MAC — message authentication via the AES block cipher
 * in CBC mode with an all-zero IV; the output is the LAST ciphertext
 * block (16 bytes). CBC-MAC is *not* secure for variable-length
 * messages without prepending the length (or using CMAC) — but with
 * our fixed 1024-byte workload it's a valid one-shot MAC and a
 * deliberate inclusion to round out the suite with a *block-cipher-
 * based* primitive (every other crypto here is a dedicated hash).
 *
 * AES-128 ECB core in ~150 lines:
 *   - SubBytes via 256-byte S-box (no inverse needed, encrypt-only)
 *   - ShiftRows: byte shuffle
 *   - MixColumns: GF(2^8) matrix multiply, lazy xtime()
 *   - 10 rounds + initial AddRoundKey + final no-MixColumns round
 *   - Key schedule: 11 round keys (176 bytes), expanded once per call
 *
 * Reference: FIPS-197 Appendix C.1:
 *   AES-128-ECB(key=000102…0F, pt=001122…FF) = 69C4E0D86A7B0430D8CDB78070B4C55A
 * which our `aes_block_encrypt` reproduces.
 *
 * Benchmark key: ASCII "hash-bench-aes!\0" (16 bytes).
 * Workload buffer (1024 B) → 64 CBC blocks → output:
 *   0EF7EA611D82AB32BC1D57FDDD6AB8C7
 */
#include "hashes.h"

/* AES forward S-box (FIPS-197 §5.1.1 Figure 7). */
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants — first 10 entries of the AES Rcon sequence, x^(i-1)
 * in GF(2^8) for i=1..10. */
static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* 16-byte AES key — kept static so we can pre-expand the schedule
 * lazily and avoid repeating work across the 64 CBC blocks. */
static const uint8_t AES_KEY[16] = {
    'h','a','s','h','-','b','e','n','c','h','-','a','e','s','!','\0'
};

/* Expanded round-key state: 11 round keys × 16 bytes = 176 bytes. */
static uint8_t rk[176];
static uint8_t rk_ready = 0u;          /* lazy init flag */

static void key_expansion(void) {
    uint8_t i;
    uint8_t t[4];

    /* First round key is the cipher key verbatim. */
    for (i = 0; i < 16u; i++) rk[i] = AES_KEY[i];

    /* Each subsequent 16-byte block derives from the previous. */
    for (i = 16u; i < 176u; i += 4u) {
        t[0] = rk[i - 4u]; t[1] = rk[i - 3u];
        t[2] = rk[i - 2u]; t[3] = rk[i - 1u];

        if ((i & 0x0Fu) == 0u) {
            /* RotWord + SubWord + XOR with Rcon — once per 16-byte block. */
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]]; t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
            t[0] ^= RCON[(i / 16u) - 1u];
        }
        rk[i    ] = rk[i - 16u] ^ t[0];
        rk[i + 1u] = rk[i - 15u] ^ t[1];
        rk[i + 2u] = rk[i - 14u] ^ t[2];
        rk[i + 3u] = rk[i - 13u] ^ t[3];
    }
}

/* GF(2^8) multiplication by 2 (the "xtime" primitive). */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0x00u));
}

/* AES-128 single-block encrypt in place; `state` is the 16-byte
 * input/output, organised column-major (state[c*4 + r] = byte at
 * row r, column c — matches FIPS-197 §3.4). */
static void aes_block_encrypt(uint8_t state[16]) {
    uint8_t round, i;
    const uint8_t *k = rk;

    /* Initial AddRoundKey. */
    for (i = 0; i < 16u; i++) state[i] ^= k[i];
    k += 16u;

    for (round = 1u; round <= 10u; round++) {
        uint8_t s[16], t[16];

        /* SubBytes. */
        for (i = 0; i < 16u; i++) s[i] = SBOX[state[i]];

        /* ShiftRows: column-major layout, byte index = c*4 + r.
         *   row 0: unchanged
         *   row 1: shift left by 1
         *   row 2: shift left by 2
         *   row 3: shift left by 3
         * Read each row's 4 bytes from the source, write to t in the
         * shifted order. */
        t[ 0] = s[ 0]; t[ 4] = s[ 4]; t[ 8] = s[ 8]; t[12] = s[12];   /* row 0 */
        t[ 1] = s[ 5]; t[ 5] = s[ 9]; t[ 9] = s[13]; t[13] = s[ 1];   /* row 1 */
        t[ 2] = s[10]; t[ 6] = s[14]; t[10] = s[ 2]; t[14] = s[ 6];   /* row 2 */
        t[ 3] = s[15]; t[ 7] = s[ 3]; t[11] = s[ 7]; t[15] = s[11];   /* row 3 */

        /* MixColumns — skipped on the final round. */
        if (round != 10u) {
            uint8_t c;
            for (c = 0; c < 4u; c++) {
                uint8_t a0 = t[c*4u    ], a1 = t[c*4u + 1u],
                        a2 = t[c*4u + 2u], a3 = t[c*4u + 3u];
                uint8_t x  = a0 ^ a1 ^ a2 ^ a3;
                state[c*4u    ] = a0 ^ xtime((uint8_t)(a0 ^ a1)) ^ x;
                state[c*4u + 1u] = a1 ^ xtime((uint8_t)(a1 ^ a2)) ^ x;
                state[c*4u + 2u] = a2 ^ xtime((uint8_t)(a2 ^ a3)) ^ x;
                state[c*4u + 3u] = a3 ^ xtime((uint8_t)(a3 ^ a0)) ^ x;
            }
        } else {
            for (i = 0; i < 16u; i++) state[i] = t[i];
        }

        /* AddRoundKey. */
        for (i = 0; i < 16u; i++) state[i] ^= k[i];
        k += 16u;
    }
}

void hash_aes_cbc_mac(const uint8_t *data, uint16_t len, uint8_t out[16]) HBENCH_BANKED {
    uint8_t  state[16];
    uint8_t  i;
    uint16_t off;

    if (!rk_ready) {
        key_expansion();
        rk_ready = 1u;
    }

    /* IV = all zeros. */
    for (i = 0; i < 16u; i++) state[i] = 0u;

    /* Process len/16 full blocks. Tail bytes (if any) are zero-padded
     * but our 1024-byte workload divides evenly so the tail path is
     * dead in this benchmark — included for spec completeness. */
    for (off = 0; off + 16u <= len; off += 16u) {
        for (i = 0; i < 16u; i++) state[i] ^= data[off + i];
        aes_block_encrypt(state);
    }
    if (off < len) {
        uint8_t rem = (uint8_t)(len - off);
        for (i = 0; i < rem; i++)  state[i] ^= data[off + i];
        /* Trailing bytes XOR with zero — no-op. */
        aes_block_encrypt(state);
    }

    for (i = 0; i < 16u; i++) out[i] = state[i];
}
