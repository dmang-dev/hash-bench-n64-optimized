/*
 * DJB2 — Daniel J. Bernstein's classic non-cryptographic string hash
 * (`hash = hash * 33 + c`, init 5381). The original was an additive
 * variant (`+ c`), distinguished from the xor variant DJB2a (`^ c`).
 *
 * Rewritten as `((h << 5) + h)` for the multiplication so the SM83
 * doesn't have to synthesise a full 32×32 multiply per byte — this is
 * the form used by every embedded port out there.
 */
#include "hashes.h"

void hash_djb2(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 5381u;
    uint16_t i;

    for (i = 0; i < len; i++) {
        h = ((h << 5) + h) + (uint32_t)data[i];   /* h * 33 + c */
    }

    out[0] = (uint8_t)(h >> 24u);
    out[1] = (uint8_t)(h >> 16u);
    out[2] = (uint8_t)(h >>  8u);
    out[3] = (uint8_t)(h);
}
