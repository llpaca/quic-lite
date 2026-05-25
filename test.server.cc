///@file: test.server.cc
#include "beaver/beaver.h"
#include <iostream>

int main(){
    Beaver server; // default it is on ipv4
    server.listen_on(8080);
    byte buf[4*4096];
    // server.recv_stream()
    int received = server.recv_stream(buf, sizeof(buf));
    buf[received] = '\0';
    std::cout << "[server] got: " << reinterpret_cast<char *>(buf) << "\n";
    return 0;
}