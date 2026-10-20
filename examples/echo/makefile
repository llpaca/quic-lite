CC = gcc
QUICTLS ?= $(HOME)/quictls-install

CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809L \
          -Wall -Wextra -Wpedantic -Werror -g \
          -fsanitize=address,undefined \
          -Iinclude -I"$(QUICTLS)/include"

LDFLAGS := -L"$(QUICTLS)/lib64" \
           -Wl,-rpath,"$(QUICTLS)/lib64"

LIBS := -lssl -lcrypto

all: server client cert.pem

server: server.c ../../include/qlite.h
	$(CC) $(CFLAGS) -o $@ server.c $(LDFLAGS) $(LIBS)

client: client.c ../../include/qlite.h
	$(CC) $(CFLAGS) -o $@ client.c $(LDFLAGS) $(LIBS)

cert.pem key.pem:
	openssl req -x509 -newkey rsa:2048 -nodes \
	    -keyout key.pem -out cert.pem \
	    -days 365 -subj "/CN=localhost"

clean:
	rm -f server client cert.pem key.pem

.PHONY: all clean