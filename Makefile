# hash-bench-n64-opt — libdragon build
#
# The libdragon build system is one giant include: $(N64_INST)/include/n64.mk
# brings in toolchain macros (N64_CC, N64_LDFLAGS, etc.), recipe templates
# for .o → .elf → .z64, and the n64tool ROM-stamping rules. All we declare
# here is the source list and ROM metadata.
#
# Build with:
#   make N64_INST=I:/libdragon
# or set N64_INST in the shell env first. build.bat does that.

# n64.mk's %.o rule does "$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c". Make
# preserves trailing whitespace before inline `#` comments in `:=`
# assignments, so the comments stay on their own lines or the trailing
# spaces will make SOURCE_DIR concat to e.g. "source       /adler32.c".
BUILD_DIR  := build
SOURCE_DIR := source

# Standard target wiring — n64.mk's %.z64 rule expects $(BUILD_DIR)/%.elf
# which in turn expects $(OBJS) plus the implicit %.c → %.o rule that
# n64.mk also provides.
all: hash-bench-n64-opt.z64

include $(N64_INST)/include/n64.mk

# Tell n64.mk where to look for our project-local hashes.h.
N64_CFLAGS += -Iinclude

# Glob every .c under source/ so adding an algorithm doesn't require a
# Makefile edit. (libdragon expects the sources to live alongside the
# object dir, but it tolerates explicit paths just fine.)
SRC_FILES := $(wildcard source/*.c)
OBJS      := $(patsubst source/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

# Per-ROM metadata. Embedded in the .z64 header by n64tool — visible
# to N64 menus / emulators that show titles.
hash-bench-n64-opt.z64: N64_ROM_TITLE = "hash-bench-n64-opt"
hash-bench-n64-opt.z64: N64_ROM_REGIONFREE = true

# Pad the ROM to 1 MiB. Many emulators (notably Project64 < 4.x and
# some real flash-cart loaders) refuse to boot ROMs smaller than the
# canonical commercial minimum size; libdragon's default tool output
# leaves the .z64 at the actual byte count (~160 KB here). Padding
# is harmless on accurate emulators (Ares / mupen64plus / cen64).
N64_TOOLFLAGS += --size 1M

$(BUILD_DIR)/hash-bench-n64-opt.elf: $(OBJS)

clean:
	rm -rf $(BUILD_DIR) hash-bench-n64-opt.z64

.PHONY: all clean

-include $(wildcard $(BUILD_DIR)/*.d)
