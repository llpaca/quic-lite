CC = gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -g \
          -fsanitize=address,undefined
INCLUDES := -Iinclude

SRC := $(wildcard src/*.c)
TESTS := $(wildcard test/*.c)

BUILD_DIR := builds

# builds/test_stack builds/test_queue ...
TARGETS := $(patsubst test/%.c,$(BUILD_DIR)/%,$(TESTS))

.PHONY: all test clean

all: test

test: $(TARGETS)
	@for t in $(TARGETS); do \
		echo "Running $$t"; \
		./$$t; \
	done

# Build each test executable
$(BUILD_DIR)/%: test/%.c $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $< -o $@

clean:
	rm -rf $(BUILD_DIR)