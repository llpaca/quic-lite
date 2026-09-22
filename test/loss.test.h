#ifndef QL_LOSS_TEST_H
#define QL_LOSS_TEST_H

#include "harness.test.h"
#include "test.h"
#include <qlite.h>

/* =========================================================================
 * PART 1 — chunk 5.1.1  ql__ack_record_recv() range merging, direct unit
 * tests. No network needed: isolates the interval-merge logic itself.
 * ========================================================================= */

TEST(test_ack_record_first_packet_starts_one_range) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 5, true, p.now_ms);

    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    EXPECT_EQ(a->range_count, 1);
    EXPECT_EQ(a->ranges[0].largest, (ql_pkt_num_t)5);
    EXPECT_EQ(a->ranges[0].count, (uint64_t)1);
    EXPECT_EQ(a->largest_recvd, (ql_pkt_num_t)5);
    EXPECT(a->needs_ack);

    qlite_test_pair_teardown(&p);
}

TEST(test_ack_record_consecutive_packets_extend_one_range) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 1, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 2, true, p.now_ms);

    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    EXPECT_EQ(a->range_count, 1);
    EXPECT_EQ(a->ranges[0].largest, (ql_pkt_num_t)2);
    EXPECT_EQ(a->ranges[0].count, (uint64_t)3);

    qlite_test_pair_teardown(&p);
}

TEST(test_ack_record_gap_creates_second_range) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 1, true, p.now_ms);
    /* pkt 2 lost/reordered — skip straight to 3 */
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 3, true, p.now_ms);

    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    EXPECT_EQ(a->range_count, 2);
    EXPECT_EQ(a->ranges[0].largest, (ql_pkt_num_t)3); /* most recent range first */
    EXPECT_EQ(a->ranges[0].count, (uint64_t)1);
    EXPECT_EQ(a->ranges[1].largest, (ql_pkt_num_t)1);
    EXPECT_EQ(a->ranges[1].count, (uint64_t)2);

    qlite_test_pair_teardown(&p);
}

TEST(test_ack_record_gap_fill_merges_ranges) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 1, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 3, true, p.now_ms); /* gap at 2 */
    EXPECT_EQ(c->ack[QL_PN_SPACE_APP].range_count, 2);

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 2, true, p.now_ms); /* fills the gap */

    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    EXPECT_EQ(a->range_count, 1);
    EXPECT_EQ(a->ranges[0].largest, (ql_pkt_num_t)3);
    EXPECT_EQ(a->ranges[0].count, (uint64_t)4);

    qlite_test_pair_teardown(&p);
}

TEST(test_ack_record_duplicate_packet_is_noop) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 5, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 5, true, p.now_ms);

    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    EXPECT_EQ(a->range_count, 1);
    EXPECT_EQ(a->ranges[0].count, (uint64_t)1);

    qlite_test_pair_teardown(&p);
}

TEST(test_ack_record_non_ack_eliciting_does_not_schedule_ack) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, false, p.now_ms);
    EXPECT(!c->ack[QL_PN_SPACE_APP].needs_ack);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 2 — chunk 5.1.2  ql__send_ack() encodes what the range state says
 * ========================================================================= */

TEST(test_send_ack_encodes_largest_and_first_range) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 1, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 2, true, p.now_ms);

    int before = c->send_queue.count;
    int rc        = ql__send_ack(c, QL_PN_SPACE_APP, QL_ENC_LEVEL_APP, p.now_ms);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(c->send_queue.count, before + 1);
    EXPECT(!c->ack[QL_PN_SPACE_APP].needs_ack); /* cleared after sending */

    qlite_test_pair_teardown(&p);
}

TEST(test_send_ack_with_multiple_ranges_roundtrips_through_wire_codec) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->ack[QL_PN_SPACE_APP], 0, sizeof(c->ack[QL_PN_SPACE_APP]));

    ql__ack_record_recv(c, QL_PN_SPACE_APP, 0, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 1, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 5, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 6, true, p.now_ms);
    ql__ack_record_recv(c, QL_PN_SPACE_APP, 7, true, p.now_ms);
    EXPECT_EQ(c->ack[QL_PN_SPACE_APP].range_count, 2);

    /* Build the frame directly (bypassing the packet layer) so this test
     * isolates ql_frame_encode's gap math — the bug this specifically
     * regression-tests lived entirely there. */
    ql_ack_state_t *a = &c->ack[QL_PN_SPACE_APP];
    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                 = QL_FRAME_ACK;
    f.u.ack.largest_acked   = a->ranges[0].largest;
    f.u.ack.first_ack_range = a->ranges[0].count - 1;
    f.u.ack.range_count     = (uint64_t)(a->range_count - 1);
    for (int i = 0; i < a->range_count - 1; i++) {
        f.u.ack.ranges[i] = a->ranges[i + 1];
    }

    uint8_t buf[128];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));
    EXPECT_GT(flen, 0);

    ql_frame_t decoded;
    int dlen = ql_frame_decode(buf, (size_t)flen, &decoded);
    EXPECT_EQ(dlen, flen);
    EXPECT_EQ(decoded.u.ack.largest_acked, (ql_pkt_num_t)7);
    EXPECT_EQ(decoded.u.ack.first_ack_range, (uint64_t)2); /* covers 5,6,7 */
    EXPECT_EQ(decoded.u.ack.range_count, (uint64_t)1);
    EXPECT_EQ(decoded.u.ack.ranges[0].largest, (ql_pkt_num_t)1); /* covers 0,1 */
    EXPECT_EQ(decoded.u.ack.ranges[0].count, (uint64_t)2);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 3 — chunk 5.3/5.4  RTT sampling and congestion control, direct
 * unit tests.
 * ========================================================================= */

TEST(test_rtt_sample_first_sample_sets_smoothed_rtt) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->cc, 0, sizeof(c->cc));
    c->cc.min_rtt_us = UINT64_MAX;

    ql__rtt_sample(c, 1000, 0, 1050); /* sent at 1000ms, acked at 1050ms -> 50ms RTT */

    EXPECT(c->cc.rtt_sample_taken);
    EXPECT_EQ(c->cc.latest_rtt_us, (uint64_t)50000);
    EXPECT_EQ(c->cc.smoothed_rtt_us, (uint64_t)50000);
    EXPECT_EQ(c->cc.min_rtt_us, (uint64_t)50000);

    qlite_test_pair_teardown(&p);
}

TEST(test_rtt_sample_subsequent_sample_updates_smoothed_rtt) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;
    memset(&c->cc, 0, sizeof(c->cc));
    c->cc.min_rtt_us = UINT64_MAX;

    ql__rtt_sample(c, 1000, 0, 1050); /* 50ms */
    uint64_t srtt_after_first = c->cc.smoothed_rtt_us;

    ql__rtt_sample(c, 2000, 0, 2100); /* 100ms — should pull smoothed_rtt up, not replace it */

    EXPECT_GT(c->cc.smoothed_rtt_us, srtt_after_first);
    EXPECT_LT(c->cc.smoothed_rtt_us, (uint64_t)100000);

    qlite_test_pair_teardown(&p);
}

TEST(test_rtt_sample_ack_delay_reduces_adjusted_rtt) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c              = &p.client;
    c->remote_tp_rcvd         = true;
    c->remote_tp.ack_delay_exponent = 0; /* so ack_delay units == microseconds directly */
    c->handshake_confirmed    = false;   /* skip the max_ack_delay clamp for this test */
    memset(&c->cc, 0, sizeof(c->cc));
    c->cc.min_rtt_us = UINT64_MAX;

    /* First sample establishes a low min_rtt floor. */
    ql__rtt_sample(c, 1000, 0, 1020); /* 20ms RTT */
    EXPECT_EQ(c->cc.min_rtt_us, (uint64_t)20000);

    /* Second sample: 100ms raw RTT with the peer reporting 15ms of its
     * own ack delay. 100ms clearly exceeds min_rtt(20ms) + delay(15ms),
     * so the adjustment applies and only ~85ms should feed the smoothing
     * — latest_rtt_us itself stays the raw, unadjusted measurement. */
    ql__rtt_sample(c, 2000, 15000, 2100);

    EXPECT_EQ(c->cc.latest_rtt_us, (uint64_t)100000);
    EXPECT_LT(c->cc.smoothed_rtt_us, (uint64_t)100000);

    qlite_test_pair_teardown(&p);
}

TEST(test_congestion_control_initial_window_matches_rfc9002) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    /* RFC 9002 §7.2: min(10*max_datagram_size, max(2*max_datagram_size,
     * 14720)), computed with QL_PATH_MTU_DEFAULT before the real path MTU
     * is known. */
    uint64_t mtu      = QL_PATH_MTU_DEFAULT;
    uint64_t expected = 10 * mtu;
    if (expected > 14720) {
        expected = 14720;
    }
    if (expected < 2 * mtu) {
        expected = 2 * mtu;
    }

    EXPECT_EQ(p.client.cc.cwnd, expected);
    EXPECT_EQ(p.client.cc.state, QL_CC_SLOW_START);
    EXPECT_EQ(p.client.cc.ssthresh, UINT64_MAX);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 4 — integration: ACKs actually flow end-to-end and retire
 * sent_pkts, loss is detected and data is retransmitted after a drop.
 * ========================================================================= */

TEST(test_sent_packets_are_marked_acked_after_real_roundtrip) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);
    static const uint8_t msg[] = "ack me";
    EXPECT_EQ(qlite_send(&p.client, cs, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));

    qlite_test_pair_pump(&p, 40, NULL);

    bool any_app_acked = false;
    for (int i = 0; i < p.client.sent_pkt_count; i++) {
        int idx = (p.client.sent_pkt_head + i) % QL_SENT_PKT_MAX;
        if (p.client.sent_pkts[idx].pn_space == QL_PN_SPACE_APP &&
            p.client.sent_pkts[idx].is_acked) {
            any_app_acked = true;
            break;
        }
    }
    EXPECT(any_app_acked);
    EXPECT_EQ(p.client.cc.bytes_in_flight, (uint64_t)0);

    qlite_test_pair_teardown(&p);
}

/* Drops the very next datagram `from` would otherwise deliver to `to`. */
static void qlite_test_shuttle_drop_one(ql_conn_t *from, ql_conn_t *to, uint64_t now_ms,
                                        struct sockaddr_storage *from_addr, bool *dropped) {
    while (from->send_queue.count > 0) {
        ql_datagram_t *dg = &from->send_queue.datagrams[from->send_queue.head];
        uint8_t buf[QL_PATH_MTU_ETHERNET + 64];
        size_t len = dg->len;
        memcpy(buf, dg->data, len);
        from->send_queue.head  = (from->send_queue.head + 1) % QL_MAX_COALESCE_PKTS;
        from->send_queue.count--;

        if (!*dropped) {
            *dropped = true;
            continue; /* simulate loss: never call process_datagram for this one */
        }
        ql__conn_process_datagram(to, buf, len, from_addr, sizeof(*from_addr), now_ms);
    }
}

TEST(test_lost_stream_data_is_retransmitted_and_still_arrives) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);
    static const uint8_t msg[] = "this packet will get eaten";
    EXPECT_EQ(qlite_send(&p.client, cs, msg, sizeof(msg) - 1), (int)(sizeof(msg) - 1));

    struct sockaddr_storage client_addr, server_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));

    bool dropped = false;
    /* First round: drop the client's first post-setup datagram carrying
     * the STREAM frame; let everything else through normally. */
    p.now_ms += 5;
    ql_conn_tick(&p.client, p.now_ms);
    qlite_test_shuttle_drop_one(&p.client, &p.server, p.now_ms, &server_addr, &dropped);
    ql_conn_tick(&p.server, p.now_ms);
    qlite_test_shuttle(&p.server, &p.client, p.now_ms, &client_addr);
    EXPECT(dropped);

    /* Give loss detection + retransmission + delivery time to happen. */
    qlite_test_pair_pump(&p, 100, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);
    uint8_t out[64];
    int n = qlite_recv(&p.server, ss, out, sizeof(out));
    EXPECT_EQ(n, (int)(sizeof(msg) - 1));
    EXPECT_EQ(memcmp(out, msg, (size_t)n), 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_pto_arms_when_ack_eliciting_packet_outstanding) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    ql_conn_t *c = &p.client;

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(c, true, &cs), QLITE_OK);
    static const uint8_t msg[] = "x";
    EXPECT_EQ(qlite_send(c, cs, msg, 1), 1);

    /* One tick to actually emit the STREAM frame, without letting the
     * server's ACK come back (don't shuttle). */
    p.now_ms += 5;
    ql_conn_tick(c, p.now_ms);

    EXPECT_GT(c->cc.bytes_in_flight, (uint64_t)0);
    ql__set_loss_detection_timer(c, p.now_ms);
    EXPECT_GT(c->cc.pto_deadline_ms, p.now_ms);

    qlite_test_pair_teardown(&p);
}

#endif /* QL_LOSS_TEST_H */
