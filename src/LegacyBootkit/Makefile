# Legacy Bootkit Build System
#
# Builds 16-bit real-mode MBR/VBR bootkit research modules using NASM.
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

NASM ?= nasm
BUILD_DIR ?= ../../build/legacy

TARGETS = $(BUILD_DIR)/mbr_infector.bin $(BUILD_DIR)/vbr_hook.bin

.PHONY: all clean

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/mbr_infector.bin: mbr_infector.asm
	$(NASM) -f bin -o $@ $<
	@echo "Built MBR infector ($(shell wc -c < $@ 2>/dev/null || echo 512) bytes)"

$(BUILD_DIR)/vbr_hook.bin: vbr_hook.asm
	$(NASM) -f bin -o $@ $<
	@echo "Built VBR hook ($(shell wc -c < $@ 2>/dev/null || echo 512) bytes)"

clean:
	rm -rf $(BUILD_DIR)
