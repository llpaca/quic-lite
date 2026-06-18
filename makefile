CC = gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -g -fsanitize=address,undefined
INCLUDES := -Iinclude

SRC := $(wildcard src/*.c)
TESTS := $(wildcard test/*.c)

TARGET := builds/tests

.PHONY: all test clean

all: test

$(TARGET): $(SRC) $(TESTS)
	mkdir -p builds
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test: $(TARGET)
	./$(TARGET)

clean:
	rm -rf builds/*