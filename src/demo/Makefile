CC_64=x86_64-w64-mingw32-gcc

RC_64       := x86_64-pc-windows-gnu

BUILD_DIR   := bin
C_BUILD_DIR := $(BUILD_DIR)/c
RS_BUILD_DIR:= $(BUILD_DIR)/rs

RUN_EXE   := $(BUILD_DIR)/run.x64.exe
TEST_DLL  := $(BUILD_DIR)/test.x64.dll
C_OBJ     := $(C_BUILD_DIR)/test.x64.o
RS_OBJ    :=  $(abspath $(RS_BUILD_DIR)/test.x64.o)

all: dirs $(RUN_EXE) $(TEST_DLL) $(C_OBJ) $(RS_OBJ)

dirs:
	mkdir -p $(BUILD_DIR) $(C_BUILD_DIR) $(RS_BUILD_DIR)

$(RUN_EXE): c/run.c
	$(CC_64) -DWIN_X64 -masm=intel -Wall -Wno-pointer-arith $< -o $@ -lws2_32

$(TEST_DLL): c/testdll.c
	$(CC_64) -shared $< -o $@

$(C_OBJ): c/testobj.c
	$(CC_64) -c $< -o $@

$(RS_OBJ):
	cd rs && \
	cargo +nightly rustc \
		--release \
		--target $(RC_64) \
		--bin testobj \
		-- -Zno-link --emit=obj=$(RS_OBJ)

clean:
	rm -rf $(BUILD_DIR)
