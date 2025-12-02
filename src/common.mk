BUILD_DIR   := bin

CC_64       := x86_64-w64-mingw32-gcc
SRC_C_DIR   := c
OUT_C_DIR   := $(BUILD_DIR)/c
C_SRCS      := $(wildcard $(SRC_C_DIR)/*.c)

RC_64       := x86_64-pc-windows-gnu
SRC_RS_DIR  := rs
OUT_RS_DIR  := $(BUILD_DIR)/rs
RS_SRCS     := $(wildcard $(SRC_RS_DIR)/*.rs)
RS_BINS     := $(basename $(notdir $(RS_SRCS)))

# Rust objects: build/loader1/rs/foo.x64.o, bar.x64.o, ...
RS_OBJS     := $(addprefix $(OUT_RS_DIR)/,$(addsuffix .x64.o,$(RS_BINS)))

# Derive C object names from C_SRCS (foo.c -> build/.../foo.x64.o)
C_BASENAMES := $(basename $(notdir $(C_SRCS)))
C_OBJS      := $(addprefix $(OUT_C_DIR)/,$(addsuffix .x64.o,$(C_BASENAMES)))

.PHONY: all c rust clean

all: c rust

# ---------- C ----------

c: $(C_OBJS)

$(OUT_C_DIR):
	mkdir -p $(OUT_C_DIR)

$(OUT_C_DIR)/%.x64.o: $(SRC_C_DIR)/%.c | $(OUT_C_DIR)
	$(CC_64) $(CFLAGS_64) -c $< -o $@


# ---------- Rust ----------

rust: $(RS_OBJS)

$(OUT_RS_DIR):
	mkdir -p $(OUT_RS_DIR)

$(OUT_RS_DIR)/%.x64.o: | $(OUT_RS_DIR)
	cd $(SRC_RS_DIR) && \
	cargo +nightly rustc \
		--release \
		--target $(RC_64) \
		--bin $* \
		-- -Zno-link -Cjump-tables=no --emit=obj=$(abspath $@)

# ---------- clean ----------

clean:
	rm -rf $(BUILD_DIR)