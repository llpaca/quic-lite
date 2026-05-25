/// @file: test.client.cc
#include <iostream>
#include <cstring>
#include "beaver/beaver.h"

int main() {
    Beaver client;
    if (client.establish(8080, "127.0.0.1") < 0) {std::cerr << "[client] failed to set peer\n";return 1;}

    constexpr size_t PACKET_COUNT = 1900;
    constexpr size_t PACKET_SIZE  = 5;

    char msg[PACKET_COUNT * PACKET_SIZE] = {};

    // fill stream
    for (size_t i = 0; i < PACKET_COUNT; i++) {
        msg[i] = static_cast<char>(i);
    }

    int sent = client.send_stream(
        reinterpret_cast<const byte*>(msg),
        sizeof(msg)
    );

    if (sent < 0) {std::cerr << "[client] send_stream failed\n";return 1;}
    return 0;
}