# Toolchain
CC = clang
LD = ld.lld
OBJCOPY = llvm-objcopy

# path macros
BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
DBG_PATH := debug

# flags
CFLAGS := -I$(SRC_PATH) -Wno-deprecated-declarations -Werror -c $(CFLAGS)
LDFLAGS := -Wall -fPIC $(LDFLAGS) -fuse-ld=lld

ARCH ?= amd64

# compile macros
TARGET_NAME_DYNAMIC := zakosign

ifeq ($(DEBUG_MODE),1)
	CFLAGS := -DBUILD_DEBUG=1 -O1 -g $(CFLAGS)
	LDFLAGS := -O1 -g $(LDFLAGS)
else
	CFLAGS := $(CFLAGS) -O3
	LDFLAGS := $(LDFLAGS) -O3
endif

ifeq ($(ARCH),amd64) 
	OBJCOPY_ARCH := x86-64
else
	OBJCOPY_ARCH := aarch64
endif

LDFLAGS := \
	-L/usr/lib \
	-lcrypto \
	-lssl \
	$(LDFLAGS)

CFLAGS := \
	$(CFLAGS)

TARGET_DYNAMIC := $(BIN_PATH)/$(TARGET_NAME_DYNAMIC)

# src files & obj files
SRC := $(shell find $(SRC_PATH) -name '*.c')
OBJ := $(patsubst $(SRC_PATH)/%.c, $(OBJ_PATH)/%.o, $(SRC))

# Find all .bin files in SRC_PATH and its subdirectories
BIN_FILES := $(shell find $(SRC_PATH) -name '*.bin')
# Generate corresponding .o files for the bin files
BIN_OBJ := $(patsubst $(SRC_PATH)/%.bin, $(OBJ_PATH)/bin_%.o, $(BIN_FILES))

# Add BIN_OBJ to the main OBJ list to ensure they are compiled and linked
OBJ += $(BIN_OBJ)

# clean files list
DISTCLEAN_LIST := $(OBJ)
CLEAN_LIST := $(TARGET_DYNAMIC) \
			  $(DISTCLEAN_LIST)

# default rule
default: makedir all

$(TARGET_DYNAMIC): $(OBJ)
	$(info $(NULL)  ELF     $(TARGET_DYNAMIC))
	@$(CC) -o $@ -lzstd  $(OBJ) $(LDFLAGS)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	$(info $(NULL)  CC      $< $@)
	@$(CC) $(CFLAGS) -o $@ $<

$(OBJ_PATH)/bin_%.o: $(SRC_PATH)/%.bin
	$(info $(NULL)  BIN2OBJ $< $@)
	@$(OBJCOPY) --input-target binary \
	           --output-target=elf64-$(OBJCOPY_ARCH) \
	           --binary-architecture=$(OBJCOPY_ARCH) \
			   $< $@

# phony rules
.PHONY: envinfo
envinfo:

ifeq ($(OS),Windows_NT)
	$(info Platform: Windows $())
else
	$(info Platform: $(shell uname -a))
endif
	$(info CC: $(CC))
	$(info CFlags : $(CFLAGS))
	$(info LDFlags: $(LDFLAGS))
	$(info Targets: $(TARGET_DYNAMIC)) 

.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH)
	@mkdir -p $(sort $(dir $(OBJ))) $(BIN_PATH)

.PHONY: all
all: envinfo $(TARGET_DYNAMIC) 

.PHONY: clean
clean:
	@echo "  CLEAN $(CLEAN_LIST)"
	@rm -rf $(CLEAN_LIST)

