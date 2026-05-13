/*
 * CRC-64/ECMA-182 (poly 0x42F0E1EBA9EA3693, init 0, no reflect, no xorout).
 *
 * The "DLT-1 / ECMA-182" variant standardised for backup-tape error
 * detection. Used by btrfs, .xz container format, and a handful of
 * archive formats. 64-bit CRC register, MSB-first; bit-by-bit (no
 * table) to keep ROM cost minimal at the price of speed (8 conditional
 * shifts per input byte).
 *
 * Reference: crc64(buf) = 29103DD16C9C1449 for our standard 1024-byte
 * buffer. Cross-check with `crc64sum --type=ecma` if available, or
 * `crcmod.predefined.mkPredefinedCrcFun('crc-64')`.
 */
#include "hashes.h"

#define CRC64_POLY  0x42F0E1EBA9EA3693ULL

void hash_crc64(const uint8_t *data, uint16_t len, uint8_t out[8]) HBENCH_BANKED {
    uint64_t crc = 0u;
    uint16_t i;
    uint8_t  j;

    for (i = 0; i < len; i++) {
        crc ^= ((uint64_t)data[i]) << 56u;
        for (j = 0; j < 8u; j++) {
            crc = (crc & (1ULL << 63))
                ? ((crc << 1) ^ CRC64_POLY)
                :  (crc << 1);
        }
    }
    out[0] = (uint8_t)(crc >> 56); out[1] = (uint8_t)(crc >> 48);
    out[2] = (uint8_t)(crc >> 40); out[3] = (uint8_t)(crc >> 32);
    out[4] = (uint8_t)(crc >> 24); out[5] = (uint8_t)(crc >> 16);
    out[6] = (uint8_t)(crc >>  8); out[7] = (uint8_t)(crc);
}
