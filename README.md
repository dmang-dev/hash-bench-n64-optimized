# hash-bench-n64-optimized

Experimental performance-tuning sibling of
[hash-bench-n64](https://github.com/dmang-dev/hash-bench-n64) — a
*mini code-golf* attempt to squeeze more KB/s out of the VR4300
without breaking anything else. **Same 32 algorithms, same source
tree, same UI** — just `-O3 + unroll-loops` applied to a hand-picked
short list of files.

Whether this should be considered "the right way to ship the N64
benchmark" depends on the answer to a methodology question: do you
care about absolute throughput on the algorithms that win here, or
do you care about a clean apples-to-apples cross-platform comparison
where every platform uses its toolchain's default `-O2`? Both repos
exist so the answer can be "yes" to either or both.

The ROM at the repo root is named [`hash-bench-n64-opt.z64`](hash-bench-n64-opt.z64)
to make it unambiguous when both sit in your emulator's recents list
side-by-side. Title in the n64tool header is `hash-bench-n64-opt`.

[![ROM](https://img.shields.io/badge/ROM-prebuilt%20%26%20committed-success)](hash-bench-n64-opt.z64)
[![Sibling](https://img.shields.io/badge/sibling%20of-hash--bench--n64-blue)](https://github.com/dmang-dev/hash-bench-n64)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#)

---

## What's different from hash-bench-n64

Three files in `source/` get a `#pragma GCC optimize ("O3,unroll-loops")`
at the top, gated on `__GNUC__ && (__N64__ || __mips__)` so other
projects sharing these source files don't pick it up:

| File | Algorithm | Expected gain | Why it wins |
|---|---|---|---|
| `md5.c`    | MD5    | +29% | Straight-line a/b/c/d state fits in MIPS GPRs after unrolling |
| `sha256.c` | SHA-256 | +9%  | Modest — message schedule has cross-iter dependencies that cap how much unroll helps |
| `sha512.c` | SHA-512 | +14% | Unrolling exposes native uint64 ops to gcc's scheduler |

Cascading wins from these three (no source change in their files):

| Algorithm | Expected gain | Mechanism |
|---|---|---|
| HMAC-SHA256 | +10% | Calls into the optimized `sha256_compress` for every block |
| PBKDF2-HMAC-SHA256 | +22% | Calls into HMAC 1000 times |

### What's deliberately NOT changed

- **`blake2s.c`, `md4.c`, `ripemd160.c`** — these *regressed* by 6-14%
  under the same pragma when the broad-sweep experiment ran on the
  upstream repo. Their inner ops can't fit in MIPS register pressure
  after expansion, so unrolling forces extra spill/fill. Left at -O2.

- **`sha3.c`** — never touched, including in the failed broad-sweep.
  When *other* files got `__attribute__((hot, flatten))` in the
  prior attempt, gcc reorganized `.text` sections enough to make
  SHA-3's keccak permutation self-conflict on the VR4300's 16 KB
  direct-mapped I-cache. **Dropping SHA-3 47%.** No source-level
  change to `sha3.c` whatsoever caused that — pure cache-layout
  collateral damage. So in this repo we also avoid `hot/flatten`
  attributes entirely, even on the files that DO win, to preserve
  the original `.text` layout near `sha3.c`.

The relevant postmortem is the reverted commit at
[`hash-bench-n64@e675698 → 38322dd`](https://github.com/dmang-dev/hash-bench-n64/commit/38322dd)
on the upstream repo.

---

## How to verify the changes

```bash
cd hash-bench-n64-optimized
diff -u ../hash-bench-n64/source/md5.c     source/md5.c
diff -u ../hash-bench-n64/source/sha256.c  source/sha256.c
diff -u ../hash-bench-n64/source/sha512.c  source/sha512.c
```

You'll see exactly the `#pragma GCC optimize ("O3,unroll-loops")`
block added at the top of each, with no other change.

---

## Predicted vs measured

The expected gains in the table above are from the broad-sweep
experiment on the upstream repo, which DID land those wins for those
three files (and lost much more elsewhere — see postmortem). This
repo applies only the per-file pieces that won, so the wins should
carry over without the breakage.

**Caveat**: this hasn't been re-measured in isolation yet on Ares.
The first person to load `hash-bench-n64-opt.z64` and screenshot the
crypto-tier output is doing real science. If the wins match the
prediction table within ~2%, ship it. If they don't, the
methodology lesson from the postmortem applies again and we file-
gate even more aggressively.

The non-crypto rows and the unchanged crypto rows (SHA-1, RMD160,
BLAKE2s, MD4, SHA-3-*, AES-CBC-MAC) should be **identical** to the
upstream baseline. If any of those differ by more than ~2% (run-to-
run noise floor for `get_ticks_us()`-based timing), that's a
regression and warrants investigation.

---

## Build

Same as `hash-bench-n64`:

```bash
make N64_INST=/opt/libdragon
```

Or on Windows: `.\build.bat` (expects `I:\libdragon`).

Output: `hash-bench-n64-opt.z64` (1 MiB, padded — same Ares /
mupen64plus / m64p / cen64 emulator-compat note as upstream).

`.text` size impact vs upstream baseline:

| Build | .text | .bss | Δ vs baseline |
|---|---:|---:|---|
| hash-bench-n64 (baseline) | 137,624 | 10,924 | — |
| hash-bench-n64-optimized | 142,040 | 10,924 | +4.4 KB .text, no BSS change |

The +4.4 KB is well within VR4300's 16 KB I-cache; the failed
broad-sweep landed at +10.8 KB which was already past comfortable.

---

## Why a separate repo

Three reasons:

1. **Easy A/B test.** Load both ROMs in your emulator of choice,
   flip between them, see if the patch is actually a win on your
   machine / emulator version.

2. **Clean cross-platform comparison stays intact.** The umbrella
   [hash-bench](https://github.com/dmang-dev/hash-bench) story uses
   the upstream baseline numbers for its "same source compiled with
   each toolchain's default -O2" comparison — that's the apples-to-
   apples view. This repo is the "what if we golf one CPU
   specifically" view.

3. **Reverting is trivial.** If a future libdragon release changes
   gcc behavior under `-O3` such that this patch becomes net
   negative, the entire repo can be archived without affecting the
   upstream benchmark.

---

## Open work

- **Measure on real hardware** (EverDrive 64 / SC64). Emulator
  timing on Ares should match real VR4300 cycle counts closely but
  not exactly — confirm at least the *direction* of every delta.
- **Try `-O3` on `xxhash32.c` / `xxhash64.c` / `murmur3_128.c`** —
  these are rotation-heavy non-crypto algos and might pick up
  smaller gains than the crypto trio. They were flat under the
  broad sweep, so the expected gain is "small or zero", but worth a
  measurement-driven try one file at a time.
- **Replace ROL32 / ROR32 / ROL64 / ROR64 macros with a single
  inline-asm rotation primitive.** GCC already lowers the standard
  shift+OR to optimal 3-instruction sequences on MIPS3 (`srl`,
  `sll`, `or`) — there's nothing to gain on the rotation itself.
  But a hand-scheduled inline asm could potentially improve
  instruction-level parallelism on the surrounding code. Untested.
- **N64 RSP coprocessor.** The RSP is a 62.5 MHz vector unit on the
  RCP. It can run 8-way SIMD over 16-bit lanes — totally wrong
  shape for SHA-2's 32-bit ARX, but a good fit for SHA-3's lane
  permutation or for the message schedule of BLAKE2s. Real
  homebrew effort to port any algorithm to RSP assembly; would be
  a separate sub-project rather than a single file change.

---

## Acknowledgments

- Everything from the upstream
  [hash-bench-n64 acknowledgments](https://github.com/dmang-dev/hash-bench-n64#acknowledgments).
- The reverted broad-sweep experiment that taught me which files
  win and which break.
