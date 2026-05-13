/*
 * CRC-16/XMODEM (poly 0x1021, init 0x0000, no xorout, MSB-first).
 *
 * Table-less variant — the per-byte inner loop is 8 iterations, which is
 * the slowest of the CRC implementations here but uses no ROM for tables.
 * Useful as a "what does the naive case look like?" baseline.
 */
#include "hashes.h"

void hash_crc16(const uint8_t *data, uint16_t len, uint8_t out[2]) {
    uint16_t crc = 0u;
    uint16_t i;
    uint8_t  j;

    for (i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8u;
        for (j = 0; j < 8u; j++) {
            crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u)
                                  : (uint16_t)(crc << 1);
        }
    }
    out[0] = (uint8_t)(crc >> 8u);
    out[1] = (uint8_t)(crc);
}
