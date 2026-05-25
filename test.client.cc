/// @file: test.client.cc
#include <iostream>
#include <cstring>
#include "beaver/beaver.h"

int main() {
    Beaver client;

    if (client.establish(8080, "127.0.0.1") < 0) {
        std::cerr << "[client] failed to set peer\n";
        return 1;
    }

    const char *msg = "hello from beaver client";
    int sent = client.send_stream(
        reinterpret_cast<const byte *>(msg),
        strlen(msg)
    );

    if (sent < 0) {
        std::cerr << "[client] send_stream failed\n";
        return 1;
    }

    return 0;
}