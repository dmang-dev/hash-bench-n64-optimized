/*
 * FNV-1a 32-bit (Fowler-Noll-Vo). One xor + one 32-bit multiply per
 * byte. Multiplication is the dominant cost on the SM83 (no MUL
 * instruction — SDCC synthesises it from shifts and adds), so this
 * algorithm is interesting *because* it's hostile to the GB.
 */
#include "hashes.h"

#define FNV_OFFSET 0x811C9DC5UL
#define FNV_PRIME  0x01000193UL

void hash_fnv1a32(const uint8_t *data, uint16_t len, uint8_t out[4]) {
    uint32_t h = FNV_OFFSET;
    uint16_t i;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= FNV_PRIME;
    }

    out[0] = (uint8_t)(h >> 24u);
    out[1] = (uint8_t)(h >> 16u);
    out[2] = (uint8_t)(h >>  8u);
    out[3] = (uint8_t)(h);
}
