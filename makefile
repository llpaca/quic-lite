CC = gcc
CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror -g \
          -fsanitize=address,undefined
INCLUDES := -Iinclude -I"$(HOME)/quictls-install/include"
LDFLAGS  := -L"$(HOME)/quictls-install/lib64" -Wl,-rpath,"$(HOME)/quictls-install/lib64"
LDLIBS   := -lssl -lcrypto

SRC := $(wildcard src/*.c)
TESTS := $(wildcard test/*.c)
BUILD_DIR := builds
TARGETS := $(patsubst test/%.c,$(BUILD_DIR)/%,$(TESTS))

.PHONY: all test lint lint-fix clean
all: test

lint:
	clang-tidy include/qlite.h -- $(CFLAGS) $(INCLUDES)
	clang-tidy $(TESTS) -- $(CFLAGS) $(INCLUDES)
	find include src test \( -name '*.h' -o -name '*.c' \) -print0 \
		| xargs -0 clang-format --dry-run --Werror

lint-fix:
	clang-tidy -fix -fix-errors include/qlite.h -- $(CFLAGS) $(INCLUDES)
	clang-tidy -fix -fix-errors $(TESTS) -- $(CFLAGS) $(INCLUDES)
	find include src test \( -name '*.h' -o -name '*.c' \) -print0 \
		| xargs -0 clang-format -i

test: $(TARGETS)
	@for t in $(TARGETS); do \
		echo "Running $$t"; \
		./$$t; \
	done

$(BUILD_DIR)/%: test/%.c $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR)