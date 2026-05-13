/*
 * PBKDF2-HMAC-SHA256 (RFC 8018 §5.2 / RFC 2898) — key-derivation
 * function: derive a 32-byte key from a password by iterating
 * HMAC-SHA256 N times and XOR-folding all the intermediate digests.
 *
 *   U_1 = HMAC(pwd, salt || INT(1))
 *   U_i = HMAC(pwd, U_{i-1})        for i = 2..iters
 *   T_1 = U_1 XOR U_2 XOR … XOR U_iters
 *   out = T_1[0..outlen]
 *
 * This benchmark uses the input buffer as the *password*, a fixed
 * 16-byte salt, and a baked-in iteration count of `PBKDF2_ITERS = 100`.
 * Output is exactly 32 bytes (one SHA-256-output block) so we don't
 * need to handle the multi-block T_2, T_3… case.
 *
 * Cost: 2 × iters × SHA-256 evaluations. On NDS ARM9 (~10 µs per
 * SHA-256 of a small input) → ~2 ms total per call. On GBA → ~200 ms.
 * Too slow on GB so the SM83 build skips this algorithm.
 *
 * Reference vs `hashlib.pbkdf2_hmac('sha256', pwd=buf, salt='hash-bench-salt', iters=100, outlen=32)`:
 *   4FACC738DE0C37C2F286EEF5380F49FB1B26CCFDAE2BBAD88550C3479F15E68A
 */
#include "hashes.h"

#define BLK 64u
#define DGS 32u
#define PBKDF2_ITERS    100u
#define PBKDF2_SALT_LEN 15u

/* Salt — "hash-bench-salt" (15 bytes, no trailing NUL needed). */
static const uint8_t PBKDF2_SALT[PBKDF2_SALT_LEN] = {
    'h','a','s','h','-','b','e','n','c','h','-','s','a','l','t'
};

/* Working buffers — static so the SM83 stack stays calm; safe because
 * we're single-threaded and PBKDF2 isn't re-entrant. */
static uint8_t k_block[BLK];      /* HMAC-padded password (zero-padded to 64) */
static uint8_t k_ipad[BLK];
static uint8_t k_opad[BLK];
static uint8_t inner_in[BLK + 1024u];   /* inner hash input: k_ipad || msg */
static uint8_t inner_dig[DGS];
static uint8_t outer_in[BLK + DGS];
static uint8_t U[DGS];
static uint8_t T[DGS];
/* Dedicated scratch for the U_1 message (salt || INT(1)) — kept
 * SEPARATE from inner_in so the hmac_one's internal copy-from-in
 * step can't alias and clobber the message before reading it. */
static uint8_t u1_msg[PBKDF2_SALT_LEN + 4u];

/* Run one HMAC-SHA256(key=k_block[via pads], msg=in[0..in_len]) → out[32]. */
static void hmac_one(const uint8_t *in, uint16_t in_len, uint8_t out[DGS]) {
    uint16_t i;
    /* Inner pass: SHA-256(k_ipad || in). */
    for (i = 0; i < BLK; i++) inner_in[i] = k_ipad[i];
    for (i = 0; i < in_len; i++) inner_in[BLK + i] = in[i];
    hash_sha256(inner_in, (uint16_t)(BLK + in_len), inner_dig);
    /* Outer pass: SHA-256(k_opad || inner). */
    for (i = 0; i < BLK; i++) outer_in[i] = k_opad[i];
    for (i = 0; i < DGS; i++) outer_in[BLK + i] = inner_dig[i];
    hash_sha256(outer_in, (uint16_t)(BLK + DGS), out);
}

void hash_pbkdf2_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED {
    uint16_t i;
    uint16_t iter;
    uint8_t  d;

    /* HMAC key prep: if password > 64 bytes, the spec says pre-hash it
     * to SHA-256 (32 bytes) and use that as the effective key. The
     * benchmark always passes a 1024-byte buffer so we always pre-hash. */
    if (len > BLK) {
        hash_sha256(data, len, k_block);
        for (i = DGS; i < BLK; i++) k_block[i] = 0u;
    } else {
        for (i = 0; i < len; i++)   k_block[i] = data[i];
        for (i = len; i < BLK; i++) k_block[i] = 0u;
    }

    for (i = 0; i < BLK; i++) {
        k_ipad[i] = k_block[i] ^ 0x36u;
        k_opad[i] = k_block[i] ^ 0x5Cu;
    }

    /* U_1 = HMAC(pwd, salt || INT_BE(1)). Build the message in u1_msg
     * (not inner_in!) so hmac_one's internal `inner_in[BLK..] = in[..]`
     * memcpy doesn't read from the buffer it's overwriting. */
    for (i = 0; i < PBKDF2_SALT_LEN; i++) u1_msg[i] = PBKDF2_SALT[i];
    u1_msg[PBKDF2_SALT_LEN + 0u] = 0x00u;
    u1_msg[PBKDF2_SALT_LEN + 1u] = 0x00u;
    u1_msg[PBKDF2_SALT_LEN + 2u] = 0x00u;
    u1_msg[PBKDF2_SALT_LEN + 3u] = 0x01u;
    hmac_one(u1_msg, (uint16_t)(PBKDF2_SALT_LEN + 4u), U);
    for (d = 0; d < DGS; d++) T[d] = U[d];

    /* T_1 = U_1 XOR U_2 XOR … XOR U_iters. */
    for (iter = 1u; iter < PBKDF2_ITERS; iter++) {
        hmac_one(U, DGS, U);
        for (d = 0; d < DGS; d++) T[d] ^= U[d];
    }

    for (d = 0; d < DGS; d++) out[d] = T[d];
}
