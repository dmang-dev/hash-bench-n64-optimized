/*
 * Four classical "trivial" non-cryptographic string hashes — each
 * about ten lines of arithmetic, of mostly historical interest now
 * that DJB2 / FNV-1a / Murmur exist, but still the de-facto answer
 * for tiny embedded hash tables and for educational examples.
 *
 *   - Knuth multiplicative   (TAOCP vol 3 §6.4): single multiply per byte
 *   - Bob Jenkins one-at-a-time (Dr. Dobb's 1997): three shifts per byte
 *   - PJW / ELF hash         (Aho-Sethi-Ullman; ELF gABI symbol table)
 *   - SDBM                   (Berkeley DB / sdbm library)
 *
 * All four output 32 bits and are implemented byte-wise so the SM83
 * port can run them at sane speeds (no synthesised 32-bit multiply
 * for OAT/PJW/SDBM; Knuth has a single mul per byte but no other
 * arithmetic).
 *
 * Reference values for the standard `(i*31+7) & 0xFF` 1024-byte buffer:
 *   knuth        = 169FA000
 *   jenkins_oat  = D88778E4
 *   pjw_elf      = 0FC634A8
 *   sdbm         = 8FAF7E00
 */
#include "hashes.h"

/* Knuth multiplicative — `h = (h XOR c) * golden` per byte. The golden
 * constant 0x9E3779B1 is 2^32 / phi rounded; recommended by Knuth for
 * 32-bit hash tables (TAOCP vol 3 §6.4). */
void hash_knuth(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 0u;
    uint16_t i;
    for (i = 0; i < len; i++) {
        h = (h ^ (uint32_t)data[i]) * 0x9E3779B1UL;
    }
    out[0] = (uint8_t)(h >> 24); out[1] = (uint8_t)(h >> 16);
    out[2] = (uint8_t)(h >>  8); out[3] = (uint8_t)(h);
}

/* Bob Jenkins one-at-a-time — three-shift mix per input byte, plus a
 * three-shift finaliser. From his "A Hash Function for Hash Table
 * Lookup" (1997). Workhorse of small Perl interpreters. */
void hash_jenkins_oat(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 0u;
    uint16_t i;
    for (i = 0; i < len; i++) {
        h += (uint32_t)data[i];
        h += (h << 10);
        h ^= (h >>  6);
    }
    h += (h <<  3);
    h ^= (h >> 11);
    h += (h << 15);
    out[0] = (uint8_t)(h >> 24); out[1] = (uint8_t)(h >> 16);
    out[2] = (uint8_t)(h >>  8); out[3] = (uint8_t)(h);
}

/* PJW / ELF hash — used in the ELF gABI symbol-table chain. The high
 * nibble is captured, XOR'd back into the middle, then masked off
 * each round so the running state stays 28-bit-effective. */
void hash_pjw_elf(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 0u, g;
    uint16_t i;
    for (i = 0; i < len; i++) {
        h = (h << 4) + (uint32_t)data[i];
        g = h & 0xF0000000UL;
        if (g != 0u) {
            h ^= (g >> 24);
            h &= ~g;
        }
    }
    out[0] = (uint8_t)(h >> 24); out[1] = (uint8_t)(h >> 16);
    out[2] = (uint8_t)(h >>  8); out[3] = (uint8_t)(h);
}

/* SDBM — `h = h * 65599 + c`, refactored as `(h<<6) + (h<<16) - h + c`
 * to avoid the multiply on 8-bit hosts. From the public-domain sdbm
 * library that shipped with BSD; popular for K&R-era hash tables. */
void hash_sdbm(const uint8_t *data, uint16_t len, uint8_t out[4]) HBENCH_BANKED {
    uint32_t h = 0u;
    uint16_t i;
    for (i = 0; i < len; i++) {
        h = (uint32_t)data[i] + (h << 6) + (h << 16) - h;
    }
    out[0] = (uint8_t)(h >> 24); out[1] = (uint8_t)(h >> 16);
    out[2] = (uint8_t)(h >>  8); out[3] = (uint8_t)(h);
}
