/*
 * Fletcher checksums (16/32/64) — John Fletcher's 1982 design, a
 * direct ancestor of Adler-32 and an easier-than-CRC alternative that
 * detects almost all real-world bit errors. Two running sums:
 *
 *   sum_a = Σ x_i   (mod M)
 *   sum_b = Σ (n - i + 1) * x_i   (mod M)   i.e. cumulative prefix sums
 *   output = (sum_b << k) | sum_a
 *
 * with M = 2^k - 1 (255 for Fletcher-16, 65535 for Fletcher-32,
 * 2^32-1 for Fletcher-64). Word size: 1 byte for F-16, 2 bytes BE for
 * F-32, 4 bytes BE for F-64 (RFC 1146 specification).
 *
 * Reference values for the standard `(i*31+7) & 0xFF` 1024-byte buffer:
 *   fletcher16 = D400
 *   fletcher32 = F5F3FF00
 *   fletcher64 = 9C5C1DDD807F7E81
 */
#include "hashes.h"

/* On GB, place this file in bank 3 alongside RIPEMD-160 / HMAC-SHA256 /
 * AES-CBC-MAC to keep bank 0/1 under 32 KB. The pragma is gated on
 * __PORT_sm83 so devkitARM / host gcc ignore it. */
#ifdef __PORT_sm83
#pragma bank 3
#endif

/* Fletcher-16: byte-wise mod 255. */
void hash_fletcher16(const uint8_t *data, uint16_t len, uint8_t out[2]) HBENCH_BANKED {
    uint16_t a = 0u, b = 0u;
    uint16_t i;
    for (i = 0; i < len; i++) {
        a = (uint16_t)((a + data[i]) % 255u);
        b = (uint16_t)((b + a) % 255u);
    }
    out[0] = (uint8_t)b;          /* high byte */
    out[1] = (uint8_t)a;
}

/* Fletcher-32: 16-bit big-endian word-wise mod 65535. RFC 1146 calls
 * for left-shift padding if the input length is odd; we pad with a
 * single zero byte. */
void hash_fletcher32(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t a = 0u, b = 0u;
    uint16_t i;
    uint16_t pairs = (uint16_t)(len & ~1u);
    uint16_t w;

    for (i = 0; i < pairs; i += 2u) {
        w = ((uint16_t)data[i] << 8) | data[i + 1u];
        a = (a + w) % 65535u;
        b = (b + a) % 65535u;
    }
    if (len & 1u) {
        /* Pad last odd byte with a trailing zero in the low byte. */
        w = (uint16_t)((uint16_t)data[len - 1u] << 8);
        a = (a + w) % 65535u;
        b = (b + a) % 65535u;
    }
    /* Output: high 16 bits = b, low 16 bits = a (big-endian). */
    out[0] = (uint8_t)(b >>  8); out[1] = (uint8_t)(b);
    out[2] = (uint8_t)(a >>  8); out[3] = (uint8_t)(a);
}

/* Fletcher-64: 32-bit big-endian word-wise mod (2^32 - 1). Output is
 * a 64-bit value: high 32 = b, low 32 = a. Pads odd-length input with
 * trailing zero bytes to a 4-byte boundary.
 *
 * SM83-skip: SDCC's sm83 runtime lacks __modulonglong, so the
 * 64-bit % operator below would link-fail on GB. Since GB's
 * hashes.h doesn't declare hash_fletcher64 anyway, gate the entire
 * function out for that target. */
#ifndef __PORT_sm83
void hash_fletcher64(const uint8_t *data, uint16_t len, uint8_t out[8]) HBENCH_BANKED {
    uint64_t a = 0u, b = 0u;
    uint16_t i;
    uint16_t aligned = (uint16_t)(len & ~3u);
    uint32_t w;

    for (i = 0; i < aligned; i += 4u) {
        w = ((uint32_t)data[i    ] << 24) |
            ((uint32_t)data[i + 1u] << 16) |
            ((uint32_t)data[i + 2u] <<  8) |
            ((uint32_t)data[i + 3u]      );
        a = (a + w) % 0xFFFFFFFFULL;
        b = (b + a) % 0xFFFFFFFFULL;
    }
    if (len & 3u) {
        uint8_t  rem  = (uint8_t)(len & 3u);
        uint8_t  k;
        uint8_t  pad[4] = {0,0,0,0};
        for (k = 0; k < rem; k++) pad[k] = data[aligned + k];
        w = ((uint32_t)pad[0] << 24) | ((uint32_t)pad[1] << 16) |
            ((uint32_t)pad[2] <<  8) | ((uint32_t)pad[3]);
        a = (a + w) % 0xFFFFFFFFULL;
        b = (b + a) % 0xFFFFFFFFULL;
    }
    out[0] = (uint8_t)(b >> 24); out[1] = (uint8_t)(b >> 16);
    out[2] = (uint8_t)(b >>  8); out[3] = (uint8_t)(b);
    out[4] = (uint8_t)(a >> 24); out[5] = (uint8_t)(a >> 16);
    out[6] = (uint8_t)(a >>  8); out[7] = (uint8_t)(a);
}
#endif /* !__PORT_sm83 — Fletcher-64 only on GBA / NDS / 3DS / host. */
