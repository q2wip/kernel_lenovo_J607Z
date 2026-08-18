SPDX := SPDX-License-Identifier: GPL-2.0-only

OUTPUT ?= ./
HOSTCC ?= cc
HOSTCFLAGS ?=
HOSTLDFLAGS ?=

TARGET := $(OUTPUT)/resolve_btfids

all: $(TARGET)

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(TARGET): main.c | $(OUTPUT)
	$(HOSTCC) $(HOSTCFLAGS) -I../../include -I../../include/uapi \
		$(HOSTLDFLAGS) -o $@ $< -lelf

clean:
	rm -f $(TARGET)

.PHONY: all clean
