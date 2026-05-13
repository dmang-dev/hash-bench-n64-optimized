/*
 * CRC-8/SMBUS (poly 0x07, init 0x00, no reflect, no xorout).
 *
 * The simplest CRC variant — 8-bit register, one xor + 8 shift/conditional-
 * xor pairs per byte. Used by SMBus, I²C error detection, DVB-S2 frame
 * headers. Bit-by-bit (no table) to keep ROM cost minimal.
 */
#include "hashes.h"

void hash_crc8(const uint8_t *data, uint16_t len, uint8_t out[1]) HBENCH_BANKED {
    uint8_t  crc = 0u;
    uint16_t i;
    uint8_t  j;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (j = 0; j < 8u; j++) {
            crc = (crc & 0x80u) ? (uint8_t)((crc << 1) ^ 0x07u)
                                : (uint8_t)(crc << 1);
        }
    }
    out[0] = crc;
}
