#ifndef QL_STREAM_TEST_H
#define QL_STREAM_TEST_H

#include "harness.test.h"
#include "test.h"
#include <qlite.h>

/* =========================================================================
 * PART 1 — chunk 4.1  Stream lifecycle
 * ========================================================================= */

TEST(test_stream_open_assigns_correct_id_and_type) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cbidi = NULL, *cuni = NULL, *sbidi = NULL, *suni = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cbidi), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, false, &cuni), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.server, true, &sbidi), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.server, false, &suni), QLITE_OK);

    EXPECT_EQ(cbidi->id, (ql_stream_id_t)0x00);
    EXPECT_EQ(cuni->id, (ql_stream_id_t)0x02);
    EXPECT_EQ(sbidi->id, (ql_stream_id_t)0x01);
    EXPECT_EQ(suni->id, (ql_stream_id_t)0x03);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_open_increments_sequentially_by_four) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &a), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &b), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &c), QLITE_OK);

    EXPECT_EQ(a->id, (ql_stream_id_t)0);
    EXPECT_EQ(b->id, (ql_stream_id_t)4);
    EXPECT_EQ(c->id, (ql_stream_id_t)8);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_open_fresh_stream_starts_ready) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *s = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &s), QLITE_OK);
    EXPECT_EQ(s->tx_state, QL_TX_STREAM_READY);
    EXPECT_EQ(s->rx_state, QL_RX_STREAM_RECV);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_find_locates_open_stream) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *s = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &s), QLITE_OK);
    EXPECT_EQ(ql_stream_find(&p.client, s->id), s);
    EXPECT_EQ(ql_stream_find(&p.client, s->id + 4), NULL);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_open_respects_peer_max_streams_limit) {
    ql_transport_params_t tp = qlite_test_default_tp();
    tp.initial_max_streams_bidi = 2;

    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, &tp);

    ql_stream_t *s = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &s), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &s), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &s), QLITE_ERR_STREAM);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 2 — chunk 4.2/4.3  Send / receive over the wire
 * ========================================================================= */

TEST(test_stream_send_recv_roundtrip_small) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    static const uint8_t msg[] = "hello, server";
    EXPECT_EQ(qlite_send(&p.client, cs, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));

    qlite_test_pair_pump(&p, 20, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);

    uint8_t out[64];
    int n = qlite_recv(&p.server, ss, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(msg) - 1));
    EXPECT_EQ(memcmp(out, msg, (size_t)n), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_send_recv_roundtrip_multi_packet) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    /* Bigger than one packet's worth (path MTU default ~1200), forcing
     * the STREAM flush loop across several ticks/frames. */
    static uint8_t big[9000];
    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 7 + 3);
    }
    int sent = qlite_send(&p.client, cs, big, sizeof(big));
    EXPECT_EQ(sent, (int)sizeof(big));

    qlite_test_pair_pump(&p, 200, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);

    uint8_t drained[9000];
    size_t off = 0;
    while (off < sizeof(big)) {
        int n = qlite_recv(&p.server, ss, drained + off, sizeof(drained) - off);
        if (n == QLITE_ERR_AGAIN) {
            break;
        }
        EXPECT_GT(n, 0);
        off += (size_t)n;
    }
    EXPECT_EQ(off, sizeof(big));
    EXPECT_EQ(memcmp(drained, big, sizeof(big)), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_fin_delivers_eof) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    static const uint8_t msg[] = "done here";
    EXPECT_EQ(qlite_send(&p.client, cs, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));
    EXPECT_EQ(qlite_stream_close(&p.client, cs, 0), QLITE_OK);

    qlite_test_pair_pump(&p, 30, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);

    uint8_t out[64];
    int n = qlite_recv(&p.server, ss, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(msg) - 1));

    /* All data consumed and FIN seen -> next read is a clean EOF (0),
     * not QLITE_ERR_AGAIN. */
    n = qlite_recv(&p.server, ss, out, sizeof(out));
    EXPECT_EQ(n, 0);
    EXPECT_EQ(ss->rx_state, QL_RX_STREAM_DATA_READ);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_reset_delivers_to_peer) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    static const uint8_t msg[] = "partial";
    EXPECT_EQ(qlite_send(&p.client, cs, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));
    qlite_test_pair_pump(&p, 10, NULL);

    EXPECT_EQ(qlite_stream_close(&p.client, cs, 42), QLITE_OK);
    EXPECT_EQ(cs->tx_state, QL_TX_STREAM_RESET_SENT);

    qlite_test_pair_pump(&p, 10, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);
    EXPECT_EQ(ss->rx_state, QL_RX_STREAM_RESET_RCVD);
    EXPECT_EQ(ss->reset_error_code, (ql_app_error_t)42);

    uint8_t out[64];
    int n = qlite_recv(&p.server, ss, out, sizeof(out));
    EXPECT_EQ(n, QLITE_ERR_CLOSED);
    EXPECT_EQ(ss->rx_state, QL_RX_STREAM_RESET_READ);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_peer_initiated_stream_is_auto_created) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *ss_out = NULL;
    EXPECT_EQ(qlite_stream_open(&p.server, true, &ss_out), QLITE_OK);
    EXPECT_EQ(ql_stream_find(&p.client, ss_out->id), NULL); /* not yet known to client */

    static const uint8_t msg[] = "server speaks first";
    EXPECT_EQ(qlite_send(&p.server, ss_out, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));

    qlite_test_pair_pump(&p, 20, NULL);

    ql_stream_t *cs_in = ql_stream_find(&p.client, ss_out->id);
    EXPECT_NE(cs_in, NULL);

    uint8_t out[64];
    int n = qlite_recv(&p.client, cs_in, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(msg) - 1));
    EXPECT_EQ(memcmp(out, msg, (size_t)n), 0);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 3 — chunk 4.4  Flow control
 * ========================================================================= */

TEST(test_stream_flow_control_caps_delivery_at_recv_limit) {
    ql_transport_params_t tp                  = qlite_test_default_tp();
    tp.initial_max_stream_data_bidi_remote    = 64; /* what the client may send on its own streams */
    tp.initial_max_stream_data_bidi_local     = 64;

    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, &tp);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    uint8_t big[1000];
    memset(big, 0x42, sizeof(big));
    EXPECT_EQ(qlite_send(&p.client, cs, big, sizeof(big)), (int)sizeof(big));

    /* Peer never calls qlite_recv, so its recv window never grows past
     * the initial 64-byte limit -> the sender must stay capped there too. */
    qlite_test_pair_pump(&p, 60, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);
    EXPECT_LE(ss->rx_tail, (uint64_t)64);
    EXPECT_LE(cs->fc.send_offset, (uint64_t)64);
    EXPECT(cs->fc.send_blocked);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_flow_control_window_grows_as_consumed) {
    ql_transport_params_t tp               = qlite_test_default_tp();
    tp.initial_max_stream_data_bidi_remote = 256;
    tp.initial_max_stream_data_bidi_local  = 256;

    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, &tp);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);

    uint8_t big[2000];
    memset(big, 0x55, sizeof(big));
    EXPECT_EQ(qlite_send(&p.client, cs, big, sizeof(big)), (int)sizeof(big));

    ql_stream_t *ss = NULL;
    uint8_t drained[2000];
    size_t off = 0;

    /* Alternate pumping and draining so the receiver's window-update
     * logic (chunk 4.4.3) gets a chance to raise the limit and let the
     * rest of the data through. */
    for (int round = 0; round < 40 && off < sizeof(big); round++) {
        qlite_test_pair_pump(&p, 5, NULL);
        if (!ss) {
            ss = ql_stream_find(&p.server, cs->id);
        }
        if (ss) {
            for (;;) {
                int n = qlite_recv(&p.server, ss, drained + off, sizeof(drained) - off);
                if (n <= 0) {
                    break;
                }
                off += (size_t)n;
            }
        }
    }

    EXPECT_EQ(off, sizeof(big));
    EXPECT_EQ(memcmp(drained, big, sizeof(big)), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_conn_level_flow_control_caps_across_streams) {
    ql_transport_params_t tp = qlite_test_default_tp();
    tp.initial_max_data      = 100; /* connection-wide cap, tighter than any per-stream limit */

    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, &tp);

    ql_stream_t *a = NULL, *b = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &a), QLITE_OK);
    EXPECT_EQ(qlite_stream_open(&p.client, true, &b), QLITE_OK);

    uint8_t chunk[80];
    memset(chunk, 0x11, sizeof(chunk));
    EXPECT_EQ(qlite_send(&p.client, a, chunk, sizeof(chunk)), (int)sizeof(chunk));
    EXPECT_EQ(qlite_send(&p.client, b, chunk, sizeof(chunk)), (int)sizeof(chunk));

    qlite_test_pair_pump(&p, 60, NULL);

    /* Combined, the two streams wanted 160 bytes but the connection-level
     * limit is 100 -> total delivered across both must not exceed it. */
    ql_stream_t *sa = ql_stream_find(&p.server, a->id);
    ql_stream_t *sb = ql_stream_find(&p.server, b->id);
    uint64_t delivered = (sa ? sa->rx_tail : 0) + (sb ? sb->rx_tail : 0);
    EXPECT_LE(delivered, (uint64_t)100);
    EXPECT(p.client.fc.send_blocked);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 4 — chunk 4.3  Reassembly, direct unit tests (no network — pushes
 * frames straight at ql_stream_rx_push to isolate the out-of-order logic
 * from everything the wire/handshake could also get wrong).
 * ========================================================================= */

TEST(test_stream_rx_push_out_of_order_reassembles) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t s;
    ql_stream_init(&s, 0x00, &p.client);
    s.fc.recv_limit = 1u << 20;

    const uint8_t part1[] = "Hello, ";
    const uint8_t part2[] = "world!";

    /* Second half arrives first. */
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, sizeof(part1) - 1, part2, sizeof(part2) - 1, false),
              QLITE_OK);
    EXPECT_EQ(s.rx_tail, (uint64_t)0); /* still a gap at the front */

    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 0, part1, sizeof(part1) - 1, false), QLITE_OK);
    EXPECT_EQ(s.rx_tail, (uint64_t)(sizeof(part1) - 1 + sizeof(part2) - 1));

    uint8_t out[32];
    int n = qlite_recv(&p.client, &s, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(part1) - 1 + sizeof(part2) - 1));
    EXPECT_EQ(memcmp(out, "Hello, world!", (size_t)n), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_rx_push_duplicate_bytes_are_idempotent) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t s;
    ql_stream_init(&s, 0x00, &p.client);
    s.fc.recv_limit = 1u << 20;

    const uint8_t data[] = "duplicate-me";
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 0, data, sizeof(data) - 1, false), QLITE_OK);
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 0, data, sizeof(data) - 1, false), QLITE_OK);
    /* Overlapping resend (offset 3, extends a bit past what we have). */
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 3, data + 3, sizeof(data) - 1 - 3, false), QLITE_OK);

    EXPECT_EQ(s.rx_tail, (uint64_t)(sizeof(data) - 1));

    uint8_t out[32];
    int n = qlite_recv(&p.client, &s, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(data) - 1));
    EXPECT_EQ(memcmp(out, data, (size_t)n), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_rx_push_final_size_mismatch_rejected) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t s;
    ql_stream_init(&s, 0x00, &p.client);
    s.fc.recv_limit = 1u << 20;

    const uint8_t data[] = "0123456789";
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 0, data, sizeof(data) - 1, true), QLITE_OK);
    EXPECT(s.fc.final_size_known);
    EXPECT_EQ(s.fc.final_size, (uint64_t)(sizeof(data) - 1));

    /* Data beyond the already-established final size must be rejected. */
    EXPECT_LT(ql_stream_rx_push(&p.client, &s, sizeof(data) - 1, data, 4, false), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_stream_rx_push_respects_flow_control_limit) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t s;
    ql_stream_init(&s, 0x00, &p.client);
    s.fc.recv_limit = 8;

    const uint8_t data[] = "this is definitely more than eight bytes";
    EXPECT_EQ(ql_stream_rx_push(&p.client, &s, 0, data, sizeof(data) - 1, false), QLITE_ERR_FC);

    qlite_test_pair_teardown(&p);
}

#endif /* QL_STREAM_TEST_H */
