/*
 * hash-bench-n64 — Nintendo 64 hashing-algorithm benchmark.
 *
 * libdragon toolchain. Single-screen 64×28 console (libdragon's
 * built-in software text mode — "does not respect common escape
 * sequences" per its own docs, so tier coloring is encoded as a
 * leading character rather than ANSI SGR).
 *
 * Same 32-algorithm roster as the NDS port. The VR4300 is a 64-bit
 * MIPS core with native uint64_t, so every uint64 algo (CRC-64,
 * Fletcher-64, xxh64, SipHash-2-4, SHA-512, SHA-3-{256,512},
 * Murmur3-128) compiles to real 64-bit instructions, not the
 * emulated-runtime mess we see on SDCC/cc65.
 *
 * Timing is via libdragon's get_ticks_us() (microsecond resolution,
 * never wraps in practice — 64-bit accumulator over a 46.875 MHz
 * COP0 count, lasts thousands of years). Per-algo budget is
 * BUDGET_US microseconds; we keep iterating until that elapses,
 * then report iterations / elapsed.
 *
 * Buffer-size sweep mode (Z to toggle) reruns every algorithm at
 * 64 / 256 / 1024 B and displays the three throughputs side-by-side,
 * making the per-block setup cost amortisation visible:
 *
 *   crypto algos: 64 B ≪ 256 B ≈ 1024 B (the first block dominates)
 *   per-byte algos: 64 B ≈ 256 B ≈ 1024 B (linear)
 *
 * Controls:
 *   A      : cycle sort mode (category / by-speed / by-name)
 *   B      : rerun
 *   Z      : toggle single-size / size-sweep
 *   START  : rerun (libdragon has no clean exit; alias of B)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <libdragon.h>

#include "hashes.h"

/* ---- workload buffer + digest staging --------------------------- */
static uint8_t buffer[BENCH_BUF_LEN];
static uint8_t digest[HASH_MAX_DIGEST];

/* ---- algorithm table ------------------------------------------- */
typedef void (*hash_fn)(const uint8_t *data, uint16_t len, uint8_t *out);

#define TIER_CHECKSUM   0u
#define TIER_NONCRYPTO  1u
#define TIER_CRYPTO     2u
#define NUM_TIERS       3u

/* Tier markers — printable instead of ANSI (libdragon's console
** doesn't parse escape sequences). The marker is the first column
** so columns still line up. */
static const char TIER_MARK[NUM_TIERS] = { '.', '*', '#' };
static const char * const TIER_NAMES[NUM_TIERS] = {
    "checksum", "non-crypto", "crypto"
};

typedef struct {
    const char *name;       /* 6-char fixed-width slot               */
    hash_fn     fn;
    uint8_t     digest_len;
    uint8_t     tier;
} bench_algo;

static const bench_algo ALGOS[] = {
    /* checksums */
    { "CRC8  ", hash_crc8,           1, TIER_CHECKSUM  },
    { "CRC16 ", hash_crc16,          2, TIER_CHECKSUM  },
    { "CRC32 ", hash_crc32,          4, TIER_CHECKSUM  },
    { "CRC64 ", hash_crc64,          8, TIER_CHECKSUM  },
    { "ADL32 ", hash_adler32,        4, TIER_CHECKSUM  },
    { "FLT16 ", hash_fletcher16,     2, TIER_CHECKSUM  },
    { "FLT32 ", hash_fletcher32,     4, TIER_CHECKSUM  },
    { "FLT64 ", hash_fletcher64,     8, TIER_CHECKSUM  },
    { "PRSN8 ", hash_pearson,        1, TIER_CHECKSUM  },
    /* non-crypto */
    { "KNUTH ", hash_knuth,          4, TIER_NONCRYPTO },
    { "OAT   ", hash_jenkins_oat,    4, TIER_NONCRYPTO },
    { "PJW   ", hash_pjw_elf,        4, TIER_NONCRYPTO },
    { "SDBM  ", hash_sdbm,           4, TIER_NONCRYPTO },
    { "DJB2  ", hash_djb2,           4, TIER_NONCRYPTO },
    { "FNV1A ", hash_fnv1a32,        4, TIER_NONCRYPTO },
    { "MMUR3 ", hash_murmur3,        4, TIER_NONCRYPTO },
    { "M3-128", hash_murmur3_128,   16, TIER_NONCRYPTO },
    { "XXH32 ", hash_xxh32,          4, TIER_NONCRYPTO },
    { "XXH64 ", hash_xxh64,          8, TIER_NONCRYPTO },
    { "SIP24 ", hash_siphash24,      8, TIER_NONCRYPTO },
    /* crypto */
    { "MD4   ", hash_md4,           16, TIER_CRYPTO    },
    { "MD5   ", hash_md5,           16, TIER_CRYPTO    },
    { "SHA1  ", hash_sha1,          20, TIER_CRYPTO    },
    { "RMD160", hash_ripemd160,     20, TIER_CRYPTO    },
    { "SHA256", hash_sha256,        32, TIER_CRYPTO    },
    { "SHA512", hash_sha512,        64, TIER_CRYPTO    },
    { "SHA3-2", hash_sha3_256,      32, TIER_CRYPTO    },
    { "SHA3-5", hash_sha3_512,      64, TIER_CRYPTO    },
    { "BLK2S ", hash_blake2s,       32, TIER_CRYPTO    },
    { "HMACS2", hash_hmac_sha256,   32, TIER_CRYPTO    },
    { "PBKDF2", hash_pbkdf2_sha256, 32, TIER_CRYPTO    },
    { "AESCBC", hash_aes_cbc_mac,   16, TIER_CRYPTO    },
};
#define NUM_ALGOS ((int)(sizeof(ALGOS) / sizeof(ALGOS[0])))

/* ---- timing budget --------------------------------------------- */

/* Per-(algo, buffer-size) microseconds budget. The N64 is fast: at
** 200 ms, even SHA-512 manages many iters at 1024 B (well past one
** block), and CRC-8 manages tens of thousands. */
#define BUDGET_US 200000u

/* Three buffer sizes for sweep mode — same as GBA/NDS so cross-
** platform comparisons line up. */
static const uint16_t SWEEP_SIZES[3] = { 64u, 256u, 1024u };
#define NUM_SWEEP_SIZES 3

/* ---- result storage -------------------------------------------- */

typedef struct {
    uint32_t iters;                    /* iterations completed     */
    uint64_t elapsed_us;               /* wall time elapsed        */
    uint8_t  digest_head[4];           /* first 4 bytes of digest  */
} bench_result;

static bench_result results[NUM_ALGOS][NUM_SWEEP_SIZES];

/* ---- sort modes ------------------------------------------------ */
typedef enum {
    SORT_CATEGORY = 0,   /* tier groups, insertion order within     */
    SORT_BY_SPEED,       /* fastest first (1024 B baseline)         */
    SORT_BY_NAME,        /* alphabetic                              */
    NUM_SORT_MODES
} sort_mode_t;

static const char * const SORT_NAMES[NUM_SORT_MODES] = {
    "category", "by-speed", "by-name"
};

static int order[NUM_ALGOS];          /* indices into ALGOS[]      */
static sort_mode_t sort_mode = SORT_CATEGORY;
static bool        sweep_mode = false;

/* ---- helpers --------------------------------------------------- */

/* Same byte pattern as every other port — keep digests cross-checkable. */
static void fill_buffer(void) {
    uint16_t i;
    for (i = 0; i < BENCH_BUF_LEN; i++) {
        buffer[i] = (uint8_t)((i * 31u + 7u) & 0xFFu);
    }
}

static void init_order(void) {
    int i;
    for (i = 0; i < NUM_ALGOS; i++) order[i] = i;
}

/* Insertion sort `order[]` ascending by (tier, idx) — keeps the
** ALGOS[] insertion order within each tier. */
static void sort_by_category(void) {
    int i, j, key;
    init_order();
    for (i = 1; i < NUM_ALGOS; i++) {
        key = order[i];
        j = i - 1;
        while (j >= 0 && ALGOS[order[j]].tier > ALGOS[key].tier) {
            order[j+1] = order[j];
            j--;
        }
        order[j+1] = key;
    }
}

/* Sort by 1024 B throughput descending. iters/elapsed gives rate;
** compare via cross-multiply to avoid division. */
static void sort_by_speed_fn(void) {
    int i, j, key;
    init_order();
    for (i = 1; i < NUM_ALGOS; i++) {
        key = order[i];
        j = i - 1;
        while (j >= 0) {
            const bench_result *a = &results[order[j]][2];   /* 1024 B */
            const bench_result *b = &results[key][2];
            /* "a slower than b" iff a.iters * b.us < b.iters * a.us */
            uint64_t lhs = (uint64_t)a->iters * b->elapsed_us;
            uint64_t rhs = (uint64_t)b->iters * a->elapsed_us;
            if (a->iters == 0 || (b->iters != 0 && lhs < rhs)) {
                order[j+1] = order[j];
                j--;
            } else break;
        }
        order[j+1] = key;
    }
}

static void sort_by_name_fn(void) {
    int i, j, key;
    init_order();
    for (i = 1; i < NUM_ALGOS; i++) {
        key = order[i];
        j = i - 1;
        while (j >= 0 && strcmp(ALGOS[order[j]].name, ALGOS[key].name) > 0) {
            order[j+1] = order[j];
            j--;
        }
        order[j+1] = key;
    }
}

static void apply_sort(void) {
    switch (sort_mode) {
        case SORT_CATEGORY: sort_by_category(); break;
        case SORT_BY_SPEED: sort_by_speed_fn(); break;
        case SORT_BY_NAME:  sort_by_name_fn();  break;
        default: break;
    }
}

/* Run one algorithm at a given buffer size until BUDGET_US has
** elapsed. Records iters + elapsed_us + first 4 digest bytes. */
static void run_one(int algo_idx, int size_idx) {
    const bench_algo *a = &ALGOS[algo_idx];
    uint16_t          n = SWEEP_SIZES[size_idx];
    uint64_t          t0 = get_ticks_us();
    uint64_t          dt;
    uint32_t          iters = 0u;

    do {
        a->fn(buffer, n, digest);
        iters++;
        dt = get_ticks_us() - t0;
    } while (dt < BUDGET_US);

    results[algo_idx][size_idx].iters      = iters;
    results[algo_idx][size_idx].elapsed_us = dt;
    {
        int k;
        for (k = 0; k < 4 && k < a->digest_len; k++) {
            results[algo_idx][size_idx].digest_head[k] = digest[k];
        }
    }
}

/* Run every (algo, size) combination requested by the current mode. */
static void run_all(void) {
    int i, s;
    int sizes_to_run = sweep_mode ? NUM_SWEEP_SIZES : 1;
    int start_size   = sweep_mode ? 0 : 2;       /* index 2 = 1024 B */

    /* Wipe so partial runs don't show stale data. */
    memset(results, 0, sizeof(results));

    console_clear();
    printf("hash-bench-n64 OPT   VR4300 93.75MHz   running...\n");
    printf("budget=%u ms/algo  buffer=%s\n\n",
           BUDGET_US / 1000u,
           sweep_mode ? "64/256/1024 B sweep" : "1024 B");
    /* Render once up-front so the user sees "running..." even while
    ** the long-running crypto benches occupy the CPU. RENDER_MANUAL
    ** mode means each printf only updates the buffer, not the screen. */
    console_render();

    for (i = 0; i < NUM_ALGOS; i++) {
        printf("[%2d/%d] %s ", i+1, NUM_ALGOS, ALGOS[i].name);
        for (s = start_size; s < start_size + sizes_to_run; s++) {
            run_one(i, s);
            printf("%lu ", (unsigned long)results[i][s].iters);
        }
        printf("\n");
        /* Refresh after each algo so progress is visible — without
        ** this the screen would only update once at the very end. */
        console_render();
    }
}

/* ---- rendering ------------------------------------------------- */

/* Compute KB/s = (iters * size) / elapsed_us, in integer KB/s.
** iters * size in bytes; divided by elapsed_us gives MB/s, ×1000
** gives KB/s. To keep integer math safe:
**   kbps = (iters * size * 1000) / elapsed_us       [bytes * ms/us]
** All intermediates fit in uint64_t. */
static uint32_t kb_per_sec(const bench_result *r, uint16_t size) {
    if (r->iters == 0u || r->elapsed_us == 0u) return 0u;
    return (uint32_t)(((uint64_t)r->iters * size * 1000ULL) / r->elapsed_us);
}

/* Microseconds per iteration. */
static uint32_t us_per_iter(const bench_result *r) {
    if (r->iters == 0u) return 0u;
    return (uint32_t)(r->elapsed_us / r->iters);
}

static void render_single(void) {
    int i, idx;

    console_clear();
    printf("hash-bench-n64 OPT   VR4300 93.75MHz   1024 B baseline\n");
    printf("sort=%s   budget=%u ms\n",
           SORT_NAMES[sort_mode], BUDGET_US / 1000u);
    printf("================================================================\n");
    printf(" ALGO   TIER       ITER  US/IT  KB/s    H0 H1 H2 H3\n");
    printf("----------------------------------------------------------------\n");

    for (i = 0; i < NUM_ALGOS; i++) {
        idx = order[i];
        const bench_algo   *a = &ALGOS[idx];
        const bench_result *r = &results[idx][2];   /* 1024 B */

        if (r->iters == 0u) {
            printf("%c%s %-10s    ---\n",
                   TIER_MARK[a->tier], a->name, TIER_NAMES[a->tier]);
            continue;
        }
        printf("%c%s %-10s %6lu %5lu %5lu    %02X %02X %02X %02X\n",
               TIER_MARK[a->tier],
               a->name,
               TIER_NAMES[a->tier],
               (unsigned long)r->iters,
               (unsigned long)us_per_iter(r),
               (unsigned long)kb_per_sec(r, 1024u),
               r->digest_head[0], r->digest_head[1],
               r->digest_head[2], r->digest_head[3]);
    }

    printf("----------------------------------------------------------------\n");
    printf("A:sort  B:rerun  Z:size-sweep  ST:rerun\n");
}

static void render_sweep(void) {
    int i, idx;

    console_clear();
    printf("hash-bench-n64 OPT   VR4300 93.75MHz   SWEEP MODE\n");
    printf("sort=%s   budget=%u ms each\n",
           SORT_NAMES[sort_mode], BUDGET_US / 1000u);
    printf("================================================================\n");
    printf(" ALGO   TIER       KB/s@64  KB/s@256  KB/s@1024\n");
    printf("----------------------------------------------------------------\n");

    for (i = 0; i < NUM_ALGOS; i++) {
        idx = order[i];
        const bench_algo *a = &ALGOS[idx];

        if (results[idx][0].iters == 0u) {
            printf("%c%s %-10s    ---\n",
                   TIER_MARK[a->tier], a->name, TIER_NAMES[a->tier]);
            continue;
        }
        printf("%c%s %-10s %7lu  %8lu  %9lu\n",
               TIER_MARK[a->tier], a->name, TIER_NAMES[a->tier],
               (unsigned long)kb_per_sec(&results[idx][0], 64u),
               (unsigned long)kb_per_sec(&results[idx][1], 256u),
               (unsigned long)kb_per_sec(&results[idx][2], 1024u));
    }

    printf("----------------------------------------------------------------\n");
    printf("A:sort  B:rerun  Z:size-sweep  ST:rerun   tiers: .=chksum *=nc #=crypto\n");
}

static void render(void) {
    if (sweep_mode) render_sweep();
    else            render_single();
    /* Manual render mode — explicit flush at the end of a render
    ** pass.  Without this the screen would still show the previous
    ** "running..." log because nothing has reached the framebuffer
    ** yet. */
    console_render();
}

/* ---- input ------------------------------------------------------ */

/* Wait for any joypad button press on port 1. Returns the pressed
** buttons set on the falling edge. libdragon's joypad_get_buttons_pressed
** already returns the edge-detected diff vs. previous poll, so each
** poll-call cycle here yields a clean press event. */
static joypad_buttons_t wait_press(void) {
    joypad_buttons_t b;
    for (;;) {
        joypad_poll();
        b = joypad_get_buttons_pressed(JOYPAD_PORT_1);
        if (b.raw) return b;
        /* Yield to keep the system responsive; 4ms is fine for input.
        ** We don't have a vsync hook because console is auto-rendered
        ** by stdio. */
        wait_ms(4);
    }
}

/* ---- main ------------------------------------------------------- */

int main(void) {
    console_init();
    /* MANUAL means printf only writes to the in-memory buffer; the
    ** screen updates only when console_render() is called. With
    ** AUTOMATIC, every printf in a multi-line block triggers a full
    ** display_get / draw / display_show sequence — that's a vsync
    ** wait per line, ~16 ms each, which makes the running display
    ** thrash and (on Project64) sometimes never recover. */
    console_set_render_mode(RENDER_MANUAL);
    joypad_init();

    fill_buffer();
    init_order();

    /* "Hello world" probe — proves the display chain works before we
    ** kick off the benchmark, which can run for many seconds before
    ** anything else hits the screen.  If you see this banner but no
    ** running…/results, the issue is in the bench, not init. */
    console_clear();
    printf("hash-bench-n64 OPT\n");
    printf("VR4300 @ 93.75 MHz, libdragon\n\n");
    printf("Press A to run benchmark.\n");
    printf("\n");
    printf("Notes:\n");
    printf(" - libdragon ROMs use a custom IPL3.\n");
    printf("   Project64 < 4.x may not boot it.\n");
    printf("   Recommended: Ares, mupen64plus, m64p, cen64.\n");
    console_render();

    /* Wait for the user before starting — also serves as a delay so
    ** an unstable VI on a strict emulator has time to settle. */
    {
        joypad_buttons_t b;
        do {
            joypad_poll();
            b = joypad_get_buttons_pressed(JOYPAD_PORT_1);
            wait_ms(16);
        } while (!b.a);
    }

    /* Initial run. */
    run_all();
    apply_sort();
    render();

    for (;;) {
        joypad_buttons_t b = wait_press();
        if (b.a) {
            sort_mode = (sort_mode_t)((sort_mode + 1) % NUM_SORT_MODES);
            apply_sort();
            render();
        } else if (b.b) {
            run_all();
            apply_sort();
            render();
        } else if (b.z) {
            sweep_mode = !sweep_mode;
            run_all();
            apply_sort();
            render();
        } else if (b.start) {
            /* libdragon doesn't expose a clean reboot; just rerun. */
            run_all();
            apply_sort();
            render();
        }
    }
    /* not reached */
}
