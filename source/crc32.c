/*
 * CRC-32/IEEE 802.3 (poly 0xEDB88320 reflected, init 0xFFFFFFFF, xorout
 * 0xFFFFFFFF, reflected I/O). The textbook PNG / zlib / Ethernet CRC.
 *
 * Table-less reflected variant — same as crc16, no ROM table. Mostly
 * here so we can see how much slower 32-bit arithmetic is on the SM83
 * versus ARM7. (A 256-entry table would be ~4× faster but costs 1 KiB
 * of ROM and obscures the actual algorithmic cost we're trying to
 * measure.)
 */
#include "hashes.h"

void hash_crc32(const uint8_t *data, uint16_t len, uint8_t out[4]) {
    uint32_t crc = 0xFFFFFFFFUL;
    uint16_t i;
    uint8_t  j;

    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (j = 0; j < 8u; j++) {
            crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320UL)
                             : (crc >> 1);
        }
    }
    crc ^= 0xFFFFFFFFUL;
    out[0] = (uint8_t)(crc);
    out[1] = (uint8_t)(crc >>  8u);
    out[2] = (uint8_t)(crc >> 16u);
    out[3] = (uint8_t)(crc >> 24u);
}
