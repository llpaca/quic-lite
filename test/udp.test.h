#define _POSIX_C_SOURCE 200809L
#include <qlite.h>
#include "test.h"
#include <poll.h>
#include <time.h>

/* -------------------------------------------------------------------
 * Small helper: build a loopback sockaddr_in for a given port.
 * just shared setup used by the tests below
 * ------------------------------------------------------------------- */
static struct sockaddr_in loopback_addr(uint16_t port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

/* =========================================================================
 * ql_udp_socket() tests
 * ========================================================================= */

TEST(test_udp_socket_bind_any_ephemeral_port) {
    /* NULL bind_addr -> INADDR_ANY, port 0 -> kernel picks an ephemeral
     * port. Just creating it and getting a valid fd back is the bar. */
    int fd = ql_udp_socket(NULL, 0);
    EXPECT_GE(fd, 0);
    close(fd);
}

TEST(test_udp_socket_bind_specific_loopback) {
    int fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(fd, 0);

    struct sockaddr_in bound;
    socklen_t len = sizeof(bound);
    int rc = getsockname(fd, (struct sockaddr *)&bound, &len);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(bound.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    EXPECT_NE(bound.sin_port, 0); /* kernel must have assigned one */

    close(fd);
}

TEST(test_udp_socket_is_nonblocking) {
    int fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(fd, 0);

    int flags = fcntl(fd, F_GETFL, 0);
    EXPECT_GE(flags, 0);
    EXPECT_EQ(flags & O_NONBLOCK, O_NONBLOCK);

    close(fd);
}

TEST(test_udp_socket_rejects_bad_address) {
    int fd = ql_udp_socket("not-an-ip-address", 0);
    EXPECT_EQ(fd, QLITE_ERR_INTERNAL);
}

TEST(test_udp_socket_two_sockets_get_distinct_ports) {
    int fd1 = ql_udp_socket("127.0.0.1", 0);
    int fd2 = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(fd1, 0);
    EXPECT_GE(fd2, 0);

    struct sockaddr_in a1, a2;
    socklen_t l1 = sizeof(a1), l2 = sizeof(a2);
    EXPECT_EQ(getsockname(fd1, (struct sockaddr *)&a1, &l1), 0);
    EXPECT_EQ(getsockname(fd2, (struct sockaddr *)&a2, &l2), 0);
    EXPECT_NE(a1.sin_port, a2.sin_port);

    close(fd1);
    close(fd2);
}

/* =========================================================================
 * ql_udp_recv() tests
 * ========================================================================= */

TEST(test_udp_recv_returns_again_when_empty) {
    int fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(fd, 0);

    uint8_t buf[256];
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);

    int n = ql_udp_recv(fd, buf, sizeof(buf), &src, &srclen);
    EXPECT_EQ(n, QLITE_ERR_WOULDBLOCK);

    close(fd);
}

// TEST(test_udp_recv_rejects_null_args) {
//     int fd = ql_udp_socket("127.0.0.1", 0);
//     EXPECT_GE(fd, 0);

//     uint8_t buf[16];
//     struct sockaddr_storage src;
//     socklen_t srclen = sizeof(src);

//     EXPECT_EQ(ql_udp_recv(fd, NULL, sizeof(buf), &src, &srclen), QLITE_ERR_ARGS);
//     EXPECT_EQ(ql_udp_recv(fd, buf, sizeof(buf), NULL, &srclen), QLITE_ERR_ARGS);
//     EXPECT_EQ(ql_udp_recv(fd, buf, sizeof(buf), &src, NULL), QLITE_ERR_ARGS);
//     EXPECT_EQ(ql_udp_recv(fd, buf, 0, &src, &srclen), QLITE_ERR_ARGS);

//     close(fd);
// }

/* =========================================================================
 * ql_udp_send() tests
 * ========================================================================= */

// TEST(test_udp_send_rejects_null_buf) {
//     int fd = ql_udp_socket("127.0.0.1", 0);
//     EXPECT_GE(fd, 0);

//     struct sockaddr_in dst = loopback_addr(9999);
//     int n = ql_udp_send(fd, (struct sockaddr *)&dst, sizeof(dst), NULL, 5);
//     EXPECT_EQ(n, QLITE_ERR_ARGS);

//     close(fd);
// }

TEST(test_udp_send_rejects_zero_len) {
    int fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(fd, 0);

    struct sockaddr_in dst = loopback_addr(9999);
    uint8_t byte = 0x42;
    int n = ql_udp_send(fd, (struct sockaddr *)&dst, sizeof(dst), &byte, 0);
    EXPECT_EQ(n, QLITE_ERR_ARGS);

    close(fd);
}

TEST(test_udp_send_returns_full_length_on_success) {
    /* Sending to *some* bound loopback port should succeed at the
     * sendto() level even before anyone calls recv() on the other end —
     * UDP doesn't require the receiver to be "ready". */
    int sender_fd = ql_udp_socket("127.0.0.1", 0);
    int receiver_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(sender_fd, 0);
    EXPECT_GE(receiver_fd, 0);

    struct sockaddr_in receiver_addr;
    socklen_t alen = sizeof(receiver_addr);
    EXPECT_EQ(getsockname(receiver_fd, (struct sockaddr *)&receiver_addr, &alen), 0);

    const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    int n = ql_udp_send(sender_fd, (struct sockaddr *)&receiver_addr,
                         sizeof(receiver_addr), payload, sizeof(payload));
    EXPECT_EQ(n, (int)sizeof(payload));

    close(sender_fd);
    close(receiver_fd);
}

/* =========================================================================
 * ql_udp_send() / ql_udp_recv() round-trip
 * ========================================================================= */

TEST(test_udp_send_recv_roundtrip) {
    int server_fd = ql_udp_socket("127.0.0.1", 0);
    int client_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(server_fd, 0);
    EXPECT_GE(client_fd, 0);

    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    EXPECT_EQ(getsockname(server_fd, (struct sockaddr *)&server_addr,
                          &server_addr_len), 0);

    const uint8_t payload[] = "quic-lite chunk 1.5 roundtrip";
    size_t payload_len = sizeof(payload) - 1; /* exclude NUL */

    int sent = ql_udp_send(client_fd, (struct sockaddr *)&server_addr,
                            sizeof(server_addr), payload, payload_len);
    EXPECT_EQ(sent, (int)payload_len);

    /* Give the kernel a moment to make the datagram readable. On
     * loopback this is near-instant, but poll() makes it deterministic
     * instead of racy. */
    struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
    int pr = poll(&pfd, 1, 1000);
    EXPECT_EQ(pr, 1);
    EXPECT_EQ(pfd.revents & POLLIN, POLLIN);

    uint8_t rbuf[256];
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);
    int n = ql_udp_recv(server_fd, rbuf, sizeof(rbuf), &src, &srclen);
    EXPECT_EQ(n, (int)payload_len);
    EXPECT_EQ(memcmp(rbuf, payload, payload_len), 0);

    close(server_fd);
    close(client_fd);
}

TEST(test_udp_recv_reports_correct_source_address) {
    int server_fd = ql_udp_socket("127.0.0.1", 0);
    int client_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(server_fd, 0);
    EXPECT_GE(client_fd, 0);

    struct sockaddr_in server_addr, client_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    socklen_t client_addr_len = sizeof(client_addr);
    EXPECT_EQ(getsockname(server_fd, (struct sockaddr *)&server_addr,
                          &server_addr_len), 0);
    EXPECT_EQ(getsockname(client_fd, (struct sockaddr *)&client_addr,
                          &client_addr_len), 0);

    uint8_t ping = 0x01;
    int sent = ql_udp_send(client_fd, (struct sockaddr *)&server_addr,
                            sizeof(server_addr), &ping, sizeof(ping));
    EXPECT_EQ(sent, (int)sizeof(ping));

    struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
    EXPECT_EQ(poll(&pfd, 1, 1000), 1);

    uint8_t rbuf[16];
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);
    int n = ql_udp_recv(server_fd, rbuf, sizeof(rbuf), &src, &srclen);
    EXPECT_EQ(n, (int)sizeof(ping));

    EXPECT_EQ(srclen, sizeof(struct sockaddr_in));
    struct sockaddr_in *src_in = (struct sockaddr_in *)&src;
    EXPECT_EQ(src_in->sin_family, AF_INET);
    EXPECT_EQ(src_in->sin_port, client_addr.sin_port);
    EXPECT_EQ(src_in->sin_addr.s_addr, client_addr.sin_addr.s_addr);

    close(server_fd);
    close(client_fd);
}

TEST(test_udp_recv_again_after_drain) {
    /* After the one queued datagram is drained, the next recv() must
     * go back to AGAIN rather than returning stale/zero data. */
    int server_fd = ql_udp_socket("127.0.0.1", 0);
    int client_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(server_fd, 0);
    EXPECT_GE(client_fd, 0);

    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    EXPECT_EQ(getsockname(server_fd, (struct sockaddr *)&server_addr,
                          &server_addr_len), 0);

    uint8_t byte = 0x07;
    EXPECT_EQ(ql_udp_send(client_fd, (struct sockaddr *)&server_addr,
                           sizeof(server_addr), &byte, 1), 1);

    struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
    EXPECT_EQ(poll(&pfd, 1, 1000), 1);

    uint8_t rbuf[16];
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);

    int first = ql_udp_recv(server_fd, rbuf, sizeof(rbuf), &src, &srclen);
    EXPECT_EQ(first, 1);

    srclen = sizeof(src);
    int second = ql_udp_recv(server_fd, rbuf, sizeof(rbuf), &src, &srclen);
    EXPECT_EQ(second, QLITE_ERR_WOULDBLOCK);

    close(server_fd);
    close(client_fd);
}

/* =========================================================================
 * ql_now_ms() tests
 * ========================================================================= */

TEST(test_now_ms_is_nonzero) {
    uint64_t t = ql_now_ms();
    EXPECT_GT(t, 0);
}

TEST(test_now_ms_is_monotonic_nondecreasing) {
    uint64_t t0 = ql_now_ms();
    uint64_t t1 = ql_now_ms();
    EXPECT_GE(t1, t0);
}

TEST(test_now_ms_advances_after_sleep) {
    uint64_t t0 = ql_now_ms();

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000000L }; /* 20ms */
    nanosleep(&ts, NULL);

    uint64_t t1 = ql_now_ms();
    EXPECT_GT(t1, t0);

    uint64_t delta = t1 - t0;
    /* Loose bounds: must reflect roughly 20ms, but scheduler jitter on
     * a shared CI box means we don't pin this exactly. */
    EXPECT_GE(delta, 10);
    EXPECT_LT(delta, 500);
}