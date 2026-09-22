#ifndef QL_HARNESS_TEST_H
#define QL_HARNESS_TEST_H

#include "test.h"
#include <qlite.h>

/* =========================================================================
 * Shared harness for Phase 4-7 tests (streams, loss/CC, migration/key
 * update, close/listener).
 *
 * REQUIRES tls.test.h to be #included first in test.c: this file reuses
 * tls_test_make_client_ctx() / tls_test_make_server_ctx() (static, defined
 * there) rather than duplicating certificate/ALPN setup.
 *
 * Design: two ql_conn_t driven through a REAL quictls handshake and the
 * REAL wire codec (ql_pkt_encode/decode, frame encode/decode,
 * ql__conn_process_datagram), but with conn->fd left at -1 so
 * ql_conn_tick never touches an OS socket. qlite_test_pair_pump() does the
 * datagram shuttling by hand: drain one side's send_queue, feed each
 * datagram straight into the other side's ql__conn_process_datagram().
 * This is deterministic and fast (no real network, no sleeps) while still
 * exercising every layer above the socket.
 * ========================================================================= */

typedef struct {
    ql_conn_t client;
    ql_conn_t server;
    SSL_CTX *cctx;
    SSL_CTX *sctx;
    uint64_t now_ms;
} qlite_test_pair_t;

/* A generous but finite local_params template — generous so tests aren't
 * fighting flow control by accident unless they specifically want to. */
static ql_transport_params_t qlite_test_default_tp(void) {
    ql_transport_params_t tp;
    memset(&tp, 0, sizeof(tp));
    tp.max_idle_timeout_ms                   = 30000;
    tp.initial_max_data                      = 1u << 20;
    tp.initial_max_stream_data_bidi_local     = 1u << 16;
    tp.initial_max_stream_data_bidi_remote    = 1u << 16;
    tp.initial_max_stream_data_uni            = 1u << 16;
    tp.initial_max_streams_bidi               = 16;
    tp.initial_max_streams_uni                = 16;
    tp.active_cid_limit                       = 4;
    return tp;
}

/* Feed every datagram currently queued on `from` into `to`, using a
 * distinct dummy source address per side so ql__conn_process_datagram's
 * migration-detection sees a consistent "same address" on every packet
 * (tests that want to exercise migration override this explicitly). */
static void qlite_test_shuttle(ql_conn_t *from, ql_conn_t *to, uint64_t now_ms,
                               struct sockaddr_storage *from_addr) {
    while (from->send_queue.count > 0) {
        ql_datagram_t *dg = &from->send_queue.datagrams[from->send_queue.head];
        uint8_t buf[QL_PATH_MTU_ETHERNET + 64];
        size_t len = dg->len;
        memcpy(buf, dg->data, len);
        from->send_queue.head  = (from->send_queue.head + 1) % QL_MAX_COALESCE_PKTS;
        from->send_queue.count--;

        ql__conn_process_datagram(to, buf, len, from_addr, sizeof(*from_addr), now_ms);
    }
}

/* Advance the pair by `max_ticks` rounds, or until `done` says so first.
 * `done` may be NULL to just run the full budget (useful for e.g. driving
 * a fixed number of ticks past a loss injection). */
static void qlite_test_pair_pump(qlite_test_pair_t *p, int max_ticks, bool (*done)(qlite_test_pair_t *)) {
    struct sockaddr_storage client_addr, server_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));
    client_addr.ss_family = AF_INET;
    server_addr.ss_family = AF_INET;
    ((struct sockaddr_in *)&client_addr)->sin_port = htons(11111);
    ((struct sockaddr_in *)&server_addr)->sin_port = htons(22222);

    for (int i = 0; i < max_ticks; i++) {
        p->now_ms += 5;

        ql_conn_tick(&p->client, p->now_ms);
        qlite_test_shuttle(&p->client, &p->server, p->now_ms, &client_addr);

        ql_conn_tick(&p->server, p->now_ms);
        qlite_test_shuttle(&p->server, &p->client, p->now_ms, &server_addr);

        if (done && done(p)) {
            return;
        }
    }
}

static bool qlite_test_both_connected(qlite_test_pair_t *p) {
    return p->client.state == QL_CONN_CONNECTED && p->server.state == QL_CONN_CONNECTED;
}

/*
 * qlite_test_pair_setup — chunk 3-7 integration bootstrap. Mirrors what
 * qlite_connect() + the listener's Initial-handling normally do, minus
 * the socket/listener machinery, since this harness shuttles datagrams by
 * hand. Leaves both connections in QL_CONN_CONNECTED, keys installed at
 * every level actually needed, ready for a Phase 4+ test to use directly.
 */
static void qlite_test_pair_setup_ex(qlite_test_pair_t *p, const ql_transport_params_t *tp_override,
                                     bool enable_migration) {
    memset(p, 0, sizeof(*p));
    p->now_ms = 1000;

    p->cctx = tls_test_make_client_ctx();
    p->sctx = tls_test_make_server_ctx();
    EXPECT_NE(p->cctx, NULL);
    EXPECT_NE(p->sctx, NULL);

    ql_transport_params_t tp = tp_override ? *tp_override : qlite_test_default_tp();

    ql_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_params     = tp;
    cfg.enable_migration = enable_migration;

    EXPECT_EQ(ql_conn_init(&p->client, QL_ROLE_CLIENT, &cfg), 0);
    EXPECT_EQ(ql_conn_init(&p->server, QL_ROLE_SERVER, &cfg), 0);
    p->client.fd = -1;
    p->server.fd = -1;

    /* Client picks its Initial DCID (mirrors qlite_connect). */
    ql_cid_generate(&p->client.remote_cid, QL_CID_MAX_LEN);
    EXPECT_NE(p->client.remote_cid.len, 0);

    EXPECT_EQ(ql_tls_init(&p->client.tls, p->cctx, QL_ROLE_CLIENT, p->client.remote_cid.data,
                          p->client.remote_cid.len),
              0);
    EXPECT_EQ(ql_tls_init(&p->server.tls, p->sctx, QL_ROLE_SERVER, p->client.remote_cid.data,
                          p->client.remote_cid.len),
              0);

    p->client.local_tp.initial_src_cid  = p->client.local_cid;
    p->server.local_tp.initial_src_cid  = p->server.local_cid;
    p->server.local_tp.original_dst_cid = p->client.remote_cid;

    EXPECT_EQ(ql__install_local_tp(&p->client), 0);
    EXPECT_EQ(ql__install_local_tp(&p->server), 0);

    p->client.state              = QL_CONN_INITIAL;
    p->server.state              = QL_CONN_INITIAL;
    p->client.active_path.state  = QL_PATH_VALIDATED;
    p->server.active_path.state  = QL_PATH_VALIDATED;

    qlite_test_pair_pump(p, 200, qlite_test_both_connected);

    EXPECT_EQ(p->client.state, QL_CONN_CONNECTED);
    EXPECT_EQ(p->server.state, QL_CONN_CONNECTED);
    EXPECT(p->client.keys[QL_ENC_LEVEL_APP].write.is_set);
    EXPECT(p->server.keys[QL_ENC_LEVEL_APP].write.is_set);
}

static void qlite_test_pair_setup(qlite_test_pair_t *p, const ql_transport_params_t *tp_override) {
    qlite_test_pair_setup_ex(p, tp_override, false);
}

static void qlite_test_pair_teardown(qlite_test_pair_t *p) {
    ql_conn_free(&p->client);
    ql_conn_free(&p->server);
    SSL_CTX_free(p->cctx);
    SSL_CTX_free(p->sctx);
}

/* =========================================================================
 * Harness self-check — if this fails, every Phase 4-7 test built on top
 * of it is meaningless, so it's worth its own explicit assertion.
 * ========================================================================= */

TEST(test_harness_pair_reaches_connected_state) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(p.client.state, QL_CONN_CONNECTED);
    EXPECT_EQ(p.server.state, QL_CONN_CONNECTED);
    EXPECT(p.client.handshake_confirmed);
    EXPECT(p.server.handshake_confirmed);
    /* Client's remote_cid should have been updated to the server's real
     * SCID (learned from the server's first Initial), not still be the
     * random value the client made up for key derivation. */
    EXPECT_EQ(ql_cid_cmp(&p.client.remote_cid, &p.server.local_cid), 0);

    qlite_test_pair_teardown(&p);
}

#endif /* QL_HARNESS_TEST_H */
