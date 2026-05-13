/*
 * HMAC-SHA256 (RFC 2104) — keyed wrapper around SHA-256:
 *
 *   HMAC(K, m) = SHA256( (K' XOR opad) ||
 *                        SHA256( (K' XOR ipad) || m ) )
 *
 * with K' = K (or SHA256(K) if K is longer than the block size). This
 * benchmark uses a fixed 16-byte key — long enough not to need
 * pre-hashing, short enough to amortise into the per-call cost — and
 * exercises two full SHA-256 evaluations (inner over message, outer
 * over the inner digest).
 *
 * Compare against
 *   `hmac.new(b'hash-bench-nds', data, hashlib.sha256).hexdigest()`.
 */
#include "hashes.h"

/* Small helpers from sha256.c are private. We rebuild HMAC by stacking
 * three concrete SHA-256 calls (one to absorb the padded message under
 * the inner pad, one to absorb the inner digest under the outer pad).
 * Total work ≈ 2 × SHA-256 + a couple of memcpys. */

static const uint8_t HMAC_KEY[16] = {
    'h','a','s','h','-','b','e','n','c','h','-','n','d','s', 0, 0
};

#define BLK 64u           /* SHA-256 block size */
#define DGS 32u           /* SHA-256 digest size */

/* Lifted off the stack so the SM83 build (default stack < 512 B) can
 * hold these without overflowing. Single-threaded benchmark — safe to
 * share across calls. inner_in is sized for BENCH_BUF_LEN. */
static uint8_t k_ipad[BLK];
static uint8_t k_opad[BLK];
static uint8_t inner_in[BLK + 1024u];
static uint8_t outer_in[BLK + DGS];
static uint8_t inner_dig[DGS];

void hash_hmac_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) HBENCH_BANKED {
    uint8_t  i;
    uint16_t j;

    /* Build pads — XOR key bytes with 0x36 (ipad) / 0x5C (opad). */
    for (i = 0; i < BLK; i++) {
        uint8_t kb = (i < sizeof(HMAC_KEY)) ? HMAC_KEY[i] : 0u;
        k_ipad[i] = kb ^ 0x36u;
        k_opad[i] = kb ^ 0x5Cu;
    }

    /* Inner: SHA-256(k_ipad || data). */
    for (i = 0; i < BLK; i++) inner_in[i] = k_ipad[i];
    for (j = 0; j < len; j++) inner_in[BLK + j] = data[j];
    hash_sha256(inner_in, (uint16_t)(BLK + len), inner_dig);

    /* Outer: SHA-256(k_opad || inner_dig). */
    for (i = 0; i < BLK; i++) outer_in[i] = k_opad[i];
    for (i = 0; i < DGS; i++) outer_in[BLK + i] = inner_dig[i];
    hash_sha256(outer_in, (uint16_t)(BLK + DGS), out);
}
