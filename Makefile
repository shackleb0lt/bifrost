# Comment below line to see actual linker and compiler flags while running makefile
.SILENT:

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Iinc
LDLIBS := #-lpthread -lrt

SRC_DIR := src
INC_DIR := inc
BUILD_DIR := bld

# Build modes and flags
DEBUG_FLAGS := -O0 -g -Wformat=2 -Wconversion -Wimplicit-fallthrough -DDEBUG
RELEASE_FLAGS := -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
RELEASE_LDFLAGS := -s -Wl,-z,noexecstack -Wl,-z,defs -Wl,-z,nodump

#Source Files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Object files
SRC_OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))

SERVER_OBJS := bld/serv_tftp.o bld/common.o
CLIENT_OBJS := bld/client_tftp.o bld/common.o

# Final executable
SERVER_TARGET := $(BUILD_DIR)/serv_tftp
CLIENT_TARGET := $(BUILD_DIR)/client_tftp

# Default SERVER_TARGET
.PHONY: all
all: debug

# Debug build SERVER_TARGET
.PHONY: debug
debug: CFLAGS += $(DEBUG_FLAGS)
debug: LDFLAGS += $(LDLIBS)
debug: $(SERVER_TARGET) $(CLIENT_TARGET)
debug: $(SERVER_TARGET) $(CLIENT_TARGET)

# Release build SERVER_TARGET
.PHONY: release
release: CFLAGS += $(RELEASE_FLAGS)
release: LDFLAGS += $(RELEASE_LDFLAGS) $(LDLIBS)
release: $(SERVER_TARGET) $(CLIENT_TARGET)
release: $(SERVER_TARGET) $(CLIENT_TARGET)

# Build executable SERVER_TARGET
$(SERVER_TARGET): $(SRC_OBJECTS)
	@echo "Linking executable $(SERVER_TARGET)"
	$(CC) $(CFLAGS) $(SERVER_OBJS) $(LDFLAGS)-o $(SERVER_TARGET)

# Build executable CLIENT_TARGET
$(CLIENT_TARGET) : $(SRC_OBJECTS)
	@echo "Linking executable $(CLIENT_TARGET)"
	$(CC) $(CFLAGS) $(CLIENT_OBJS) $(LDFLAGS)-o $(CLIENT_TARGET)

# Compile source object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Create the build directory
$(BUILD_DIR):
	@echo "Creating build directory $(BUILD_DIR)"
	mkdir -p $(BUILD_DIR)

# Clean up build files
.PHONY: clean
clean:
	@echo "Cleaning up build files"
	rm -rf $(BUILD_DIR)