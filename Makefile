# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -std=c17
LDFLAGS =
TARGET = rsa_tool

# Detect GMP via pkg-config if available, else fall back to common locations
PKG_CONFIG ?= pkg-config
GMP_CFLAGS := $(shell $(PKG_CONFIG) --cflags gmp 2>/dev/null)
GMP_LIBS := $(shell $(PKG_CONFIG) --libs gmp 2>/dev/null)

ifeq ($(strip $(GMP_CFLAGS)),)
  # Try Homebrew on Apple Silicon
  ifneq (,$(wildcard /opt/homebrew/include/gmp.h))
    GMP_CFLAGS := -I/opt/homebrew/include
    GMP_LIBS := -L/opt/homebrew/lib -lgmp
  else ifneq (,$(wildcard /usr/local/include/gmp.h))
    GMP_CFLAGS := -I/usr/local/include
    GMP_LIBS := -L/usr/local/lib -lgmp
  else
    # Fallback: hope system toolchain can find gmp
    GMP_LIBS := -lgmp
  endif
endif

CFLAGS += $(GMP_CFLAGS)
LDFLAGS += $(GMP_LIBS)

# Source and object files
SOURCES = main.c rsa.c test_module.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Link the objects to create the executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJECTS) $(TARGET)

# Phony targets
.PHONY: all clean
