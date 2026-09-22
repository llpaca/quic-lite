#ifndef QL_CLOSE_TEST_H
#define QL_CLOSE_TEST_H

#include "harness.test.h"
#include "test.h"
#include <qlite.h>

/* =========================================================================
 * PART 1 — chunk 7.2  Graceful close, drain, idle timeout
 * ========================================================================= */

TEST(test_close_transitions_self_to_closing) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, "bye"), QLITE_OK);
    EXPECT_EQ(p.client.state, QL_CONN_CLOSING);
    EXPECT(p.client.closing);
    EXPECT_GT(p.client.close_pkt_len, (size_t)0);
    EXPECT(p.client.timer_drain.armed);

    qlite_test_pair_teardown(&p);
}

TEST(test_close_delivers_connection_close_to_peer) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_APPLICATION_ERROR, "done"), QLITE_OK);

    qlite_test_pair_pump(&p, 10, NULL);

    EXPECT_EQ(p.server.state, QL_CONN_DRAINING);
    EXPECT(p.server.closing);
    EXPECT_EQ(p.server.close_error, (ql_transport_error_t)QL_ERR_APPLICATION_ERROR);

    qlite_test_pair_teardown(&p);
}

TEST(test_close_app_error_delivers_app_code_to_peer) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, true, 0xBEEF, "app closed"), QLITE_OK);
    qlite_test_pair_pump(&p, 10, NULL);

    EXPECT_EQ(p.server.state, QL_CONN_DRAINING);
    EXPECT_EQ(p.server.close_app_error, (ql_app_error_t)0xBEEF);

    qlite_test_pair_teardown(&p);
}

typedef struct {
    bool called;
    ql_transport_error_t err;
} close_cb_ctx_t;

static void test_on_close_cb(ql_conn_t *conn, ql_transport_error_t err, void *user) {
    (void)conn;
    close_cb_ctx_t *ctx = (close_cb_ctx_t *)user;
    ctx->called         = true;
    ctx->err            = err;
}

TEST(test_close_fires_on_close_callback_on_peer) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    close_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    p.server.cfg.on_close = test_on_close_cb;
    p.server.cfg.user     = &ctx;

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, NULL), QLITE_OK);
    qlite_test_pair_pump(&p, 10, NULL);

    EXPECT(ctx.called);
    EXPECT_EQ(ctx.err, (ql_transport_error_t)QL_ERR_NO_ERROR);

    qlite_test_pair_teardown(&p);
}

TEST(test_closing_state_retransmits_close_pkt_via_socket) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, NULL), QLITE_OK);
    EXPECT_GT(p.client.close_pkt_len, (size_t)0);

    /* §10.2.1's retransmission goes straight to the OS socket, not
     * through send_queue, so give the (otherwise deterministic, fd=-1)
     * client a real loopback socket just for this check. */
    int real_fd = ql_udp_socket("127.0.0.1", 0);
    int peer_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(real_fd, 0);
    EXPECT_GE(peer_fd, 0);

    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    EXPECT_EQ(getsockname(peer_fd, (struct sockaddr *)&peer_addr, &peer_len), 0);

    int old_fd  = p.client.fd;
    p.client.fd = real_fd;

    struct sockaddr_storage src;
    memset(&src, 0, sizeof(src));
    memcpy(&src, &peer_addr, peer_len);
    uint8_t garbage[64];
    memset(garbage, 0x42, sizeof(garbage));

    ql__conn_process_datagram(&p.client, garbage, sizeof(garbage), &src, peer_len, p.now_ms);

    uint8_t reply[QL_PATH_MTU_DEFAULT];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    int rn = -1;
    for (int i = 0; i < 50 && rn < 0; i++) {
        rn = ql_udp_recv(peer_fd, reply, sizeof(reply), &from, &fromlen);
        if (rn < 0) {
            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }
    }
    EXPECT_GT(rn, 0);
    EXPECT_EQ((size_t)rn, p.client.close_pkt_len);
    EXPECT_EQ(memcmp(reply, p.client.close_pkt, (size_t)rn), 0);

    p.client.fd = old_fd;
    close(real_fd);
    close(peer_fd);

    qlite_test_pair_teardown(&p);
}

TEST(test_draining_state_sends_nothing) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, NULL), QLITE_OK);
    qlite_test_pair_pump(&p, 10, NULL); /* server -> DRAINING */
    EXPECT_EQ(p.server.state, QL_CONN_DRAINING);

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    uint8_t garbage[64];
    memset(garbage, 0x42, sizeof(garbage));

    int before = p.server.send_queue.count;
    ql__conn_process_datagram(&p.server, garbage, sizeof(garbage), &addr, sizeof(addr), p.now_ms);
    EXPECT_EQ(p.server.send_queue.count, before); /* completely silent */

    qlite_test_pair_teardown(&p);
}

TEST(test_drain_timer_expiry_signals_conn_tick_done) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, NULL), QLITE_OK);
    EXPECT(p.client.timer_drain.armed);

    int rc = ql_conn_tick(&p.client, p.client.timer_drain.deadline_ms + 1);
    EXPECT_EQ(rc, QLITE_ERR_CLOSED);

    qlite_test_pair_teardown(&p);
}

TEST(test_idle_timeout_closes_silently) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_GT(p.client.last_activity_ms, (uint64_t)0);
    uint64_t far_future = p.client.last_activity_ms + qlite_test_default_tp().max_idle_timeout_ms + 1000;

    int rc = ql_conn_tick(&p.client, far_future);
    EXPECT_EQ(rc, QLITE_ERR_CLOSED);
    EXPECT_EQ(p.client.state, QL_CONN_DRAINING);
    EXPECT_EQ(p.client.close_error, (ql_transport_error_t)QL_ERR_NO_ERROR);
    /* Silent close: no CONNECTION_CLOSE queued for the peer. */
    EXPECT_EQ(p.client.close_pkt_len, (size_t)0);

    qlite_test_pair_teardown(&p);
}

TEST(test_double_close_is_a_noop) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_NO_ERROR, NULL), QLITE_OK);
    int sent_once = p.client.send_queue.count;
    EXPECT_EQ(qlite_close(&p.client, false, QL_ERR_INTERNAL_ERROR, NULL), QLITE_OK);
    /* Second call must not re-send or overwrite the close reason. */
    EXPECT_EQ(p.client.send_queue.count, sent_once);
    EXPECT_EQ(p.client.close_error, (ql_transport_error_t)QL_ERR_NO_ERROR);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 2 — chunk 7.2.6  ql_conn_free
 * ========================================================================= */

TEST(test_conn_free_releases_stream_list) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *a = NULL, *b = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &a), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &b), QLITE_OK);
    EXPECT_NE(p.client.stream_list, NULL);

    ql_conn_free(&p.client);
    EXPECT_EQ(p.client.stream_list, NULL);

    /* Don't double-free via teardown. */
    memset(&p.client, 0, sizeof(p.client));
    p.client.fd = -1;
    ql_conn_free(&p.server);
    SSL_CTX_free(p.cctx);
    SSL_CTX_free(p.sctx);
}

/* =========================================================================
 * PART 3 — chunk 7.1  Server listener over real loopback sockets
 * ========================================================================= */

static void close_test_pump_real(ql_conn_t *client, ql_listener_t *listener, uint64_t *now_ms,
                                 bool (*done)(ql_conn_t *, ql_listener_t *)) {
    for (int i = 0; i < 500; i++) {
        *now_ms += 5;
        ql_conn_tick(client, *now_ms);
        qlite_listener_tick(listener, *now_ms);
        if (done && done(client, listener)) {
            return;
        }
        struct timespec ts = {0, 1000000}; /* 1ms — real UDP needs the kernel to schedule it */
        nanosleep(&ts, NULL);
    }
}

static ql_conn_t *close_test_accepted;

static bool close_test_client_connected_and_accepted(ql_conn_t *client, ql_listener_t *listener) {
    if (!close_test_accepted) {
        close_test_accepted = qlite_accept(listener);
    }
    return client->state == QL_CONN_CONNECTED && close_test_accepted != NULL;
}

TEST(test_listener_accepts_real_client_connection) {
    SSL_CTX *cctx = tls_test_make_client_ctx();
    SSL_CTX *sctx = tls_test_make_server_ctx();
    EXPECT_NE(cctx, NULL);
    EXPECT_NE(sctx, NULL);

    ql_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_params = qlite_test_default_tp();

    ql_listener_t listener;
    EXPECT_EQ(qlite_listen(&listener, "127.0.0.1", 0, &cfg, sctx), QLITE_OK);

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    EXPECT_EQ(getsockname(listener.fd, (struct sockaddr *)&bound, &blen), 0);
    uint16_t port = ntohs(bound.sin_port);

    ql_conn_t client;
    EXPECT_EQ(ql_conn_init(&client, QL_ROLE_CLIENT, &cfg), 0);
    EXPECT_EQ(qlite_connect(&client, "127.0.0.1", port, cctx), QLITE_OK);

    close_test_accepted = NULL;
    uint64_t now_ms      = 1000;
    close_test_pump_real(&client, &listener, &now_ms, close_test_client_connected_and_accepted);

    EXPECT_EQ(client.state, QL_CONN_CONNECTED);
    EXPECT_NE(close_test_accepted, NULL);
    EXPECT_EQ(close_test_accepted->state, QL_CONN_CONNECTED);

    ql_conn_free(&client);
    /* close_test_accepted is owned by the listener's registry; freed via
     * the listener_tick reclaim path once drained, not here. */
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    close(listener.fd);
}

TEST(test_listener_sends_stateless_reset_for_unknown_short_header) {
    ql_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_params = qlite_test_default_tp();
    SSL_CTX *sctx    = tls_test_make_server_ctx();
    EXPECT_NE(sctx, NULL);

    ql_listener_t listener;
    EXPECT_EQ(qlite_listen(&listener, "127.0.0.1", 0, &cfg, sctx), QLITE_OK);

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    EXPECT_EQ(getsockname(listener.fd, (struct sockaddr *)&bound, &blen), 0);

    /* A throwaway probe socket sends a bogus short-header datagram
     * referencing a DCID no connection on this listener has ever used. */
    int probe_fd = ql_udp_socket("127.0.0.1", 0);
    EXPECT_GE(probe_fd, 0);

    uint8_t bogus[32];
    memset(bogus, 0x77, sizeof(bogus));
    bogus[0] = 0x40; /* short-header form */
    int sn = ql_udp_send(probe_fd, (struct sockaddr *)&bound, blen, bogus, sizeof(bogus));
    EXPECT_GT(sn, 0);

    uint64_t now_ms = 1000;
    bool got_reply  = false;
    for (int i = 0; i < 100 && !got_reply; i++) {
        now_ms += 5;
        qlite_listener_tick(&listener, now_ms);

        uint8_t reply[128];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        int rn = ql_udp_recv(probe_fd, reply, sizeof(reply), &from, &fromlen);
        if (rn > 0) {
            got_reply = true;
        }
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }

    EXPECT(got_reply);

    close(probe_fd);
    SSL_CTX_free(sctx);
    close(listener.fd);
}

#endif /* QL_CLOSE_TEST_H */
