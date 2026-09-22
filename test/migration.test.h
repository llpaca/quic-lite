#ifndef QL_MIGRATION_TEST_H
#define QL_MIGRATION_TEST_H

#include "harness.test.h"
#include "test.h"
#include <qlite.h>

/* =========================================================================
 * PART 1 — chunk 6.1  CID issuance and retirement
 * ========================================================================= */

TEST(test_cid_issuance_grows_peer_cid_table) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    /* The default TP's active_cid_limit is 4, so each side should have
     * issued a few extra CIDs (beyond the one handed out at handshake
     * time) that the peer learned about via NEW_CONNECTION_ID. */
    qlite_test_pair_pump(&p, 40, NULL);

    EXPECT_GT(p.client.local_cid_count, 1);
    EXPECT_GT(p.server.local_cid_count, 1);
    EXPECT_GT(p.client.remote_cid_count, 0); /* learned about server's extra CIDs */
    EXPECT_GT(p.server.remote_cid_count, 0);

    qlite_test_pair_teardown(&p);
}

TEST(test_cid_issuance_respects_active_cid_limit) {
    ql_transport_params_t tp = qlite_test_default_tp();
    tp.active_cid_limit      = 2;

    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, &tp);
    qlite_test_pair_pump(&p, 40, NULL);

    EXPECT_LE(p.client.local_cid_count, 2);
    EXPECT_LE(p.server.local_cid_count, 2);

    qlite_test_pair_teardown(&p);
}

TEST(test_new_connection_id_frame_roundtrips_through_wire_codec) {
    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                        = QL_FRAME_NEW_CONNECTION_ID;
    f.u.new_cid.sequence_num       = 3;
    f.u.new_cid.retire_prior_to    = 1;
    f.u.new_cid.cid.len            = 8;
    memset(f.u.new_cid.cid.data, 0xAB, 8);
    memset(f.u.new_cid.stateless_reset_token.data, 0xCD, QL_RESET_TOKEN_LEN);

    uint8_t buf[64];
    int n = ql_frame_encode(&f, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    ql_frame_t decoded;
    int dn = ql_frame_decode(buf, (size_t)n, &decoded);
    EXPECT_EQ(dn, n);
    EXPECT_EQ(decoded.u.new_cid.sequence_num, (uint64_t)3);
    EXPECT_EQ(decoded.u.new_cid.retire_prior_to, (uint64_t)1);
    EXPECT_EQ(decoded.u.new_cid.cid.len, (uint8_t)8);
    EXPECT_EQ(memcmp(decoded.u.new_cid.cid.data, f.u.new_cid.cid.data, 8), 0);
    EXPECT_EQ(memcmp(decoded.u.new_cid.stateless_reset_token.data,
                     f.u.new_cid.stateless_reset_token.data, QL_RESET_TOKEN_LEN),
              0);
}

TEST(test_retire_connection_id_marks_local_cid_retired) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);
    qlite_test_pair_pump(&p, 40, NULL); /* let a few extra CIDs get issued */

    EXPECT_GT(p.server.remote_cid_count, 0);
    uint64_t victim_seq = p.server.remote_cids[0].sequence_num;

    /* Server asks to retire one of the client's issued CIDs. */
    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                    = QL_FRAME_RETIRE_CONNECTION_ID;
    f.u.retire_cid.sequence_num = victim_seq;
    uint8_t buf[16];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));
    EXPECT_GT(flen, 0);

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    bool ack_eliciting = false;
    int rc = ql__process_frames(&p.client, QL_ENC_LEVEL_APP, buf, (size_t)flen, p.now_ms, &addr,
                                sizeof(addr), &ack_eliciting);
    EXPECT_GE(rc, 0);

    bool found_retired = false;
    for (int i = 0; i < p.client.local_cid_count; i++) {
        if (p.client.local_cids[i].sequence_num == victim_seq) {
            EXPECT(p.client.local_cids[i].is_retired);
            found_retired = true;
        }
    }
    EXPECT(found_retired);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 2 — chunk 6.2  PATH_CHALLENGE / PATH_RESPONSE
 * ========================================================================= */

TEST(test_path_challenge_frame_roundtrips_through_wire_codec) {
    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type = QL_FRAME_PATH_CHALLENGE;
    for (int i = 0; i < QL_PATH_DATA_LEN; i++) {
        f.u.path_challenge.data.data[i] = (uint8_t)(0x10 + i);
    }

    uint8_t buf[16];
    int n = ql_frame_encode(&f, buf, sizeof(buf));
    EXPECT_EQ(n, 1 + QL_PATH_DATA_LEN);

    ql_frame_t decoded;
    int dn = ql_frame_decode(buf, (size_t)n, &decoded);
    EXPECT_EQ(dn, n);
    EXPECT_EQ(memcmp(decoded.u.path_challenge.data.data, f.u.path_challenge.data.data,
                     QL_PATH_DATA_LEN),
              0);
}

TEST(test_path_challenge_is_echoed_as_path_response) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type = QL_FRAME_PATH_CHALLENGE;
    for (int i = 0; i < QL_PATH_DATA_LEN; i++) {
        f.u.path_challenge.data.data[i] = (uint8_t)(0xE0 + i);
    }
    uint8_t buf[16];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    int before = p.server.send_queue.count;

    bool ack_eliciting = false;
    int rc = ql__process_frames(&p.server, QL_ENC_LEVEL_APP, buf, (size_t)flen, p.now_ms, &addr,
                                sizeof(addr), &ack_eliciting);
    EXPECT_GE(rc, 0);
    EXPECT_EQ(p.server.send_queue.count, before + 1);

    /* The queued datagram should be addressed back to `addr` and, once
     * decoded with the client's read key (the actual intended
     * recipient's key — same secret, independently derived), contain a
     * PATH_RESPONSE with the same 8 bytes. */
    int idx           = (p.server.send_queue.tail - 1 + QL_MAX_COALESCE_PKTS) % QL_MAX_COALESCE_PKTS;
    ql_datagram_t *dg = &p.server.send_queue.datagrams[idx];
    EXPECT_EQ(memcmp(&dg->dest, &addr, sizeof(addr)), 0);

    ql_pkt_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.h.shdr.dst_cid.len = p.server.local_cid.len;
    uint8_t payload[512];
    int dn = ql_pkt_decode(dg->data, dg->len, &p.client.keys[QL_ENC_LEVEL_APP].read, &hdr, payload,
                           sizeof(payload));
    EXPECT_GE(dn, 0);

    ql_frame_t decoded;
    int fn = ql_frame_decode(hdr.payload, hdr.payload_len, &decoded);
    EXPECT_GT(fn, 0);
    EXPECT_EQ(decoded.type, QL_FRAME_PATH_RESPONSE);
    EXPECT_EQ(memcmp(decoded.u.path_response.data.data, f.u.path_challenge.data.data,
                     QL_PATH_DATA_LEN),
              0);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 3 — chunk 6.3  Passive migration detection
 * ========================================================================= */

TEST(test_migration_from_new_address_is_validated_and_promoted) {
    qlite_test_pair_t p;
    qlite_test_pair_setup_ex(&p, NULL, true /* enable_migration */);

    struct sockaddr_storage client_addr, server_addr, new_client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&new_client_addr, 0, sizeof(new_client_addr));
    client_addr.ss_family     = AF_INET;
    server_addr.ss_family     = AF_INET;
    new_client_addr.ss_family = AF_INET;
    ((struct sockaddr_in *)&client_addr)->sin_port     = htons(11111);
    ((struct sockaddr_in *)&server_addr)->sin_port     = htons(22222);
    ((struct sockaddr_in *)&new_client_addr)->sin_port = htons(33333);

    /* Normal traffic first, from the "original" client address, so the
     * server's active_path actually gets pinned to it. */
    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);
    EXPECT_EQ(qlite_send(&p.client, cs, (const uint8_t *)"before", 6), 6);

    for (int i = 0; i < 10; i++) {
        p.now_ms += 5;
        ql_conn_tick(&p.client, p.now_ms);
        qlite_test_shuttle(&p.client, &p.server, p.now_ms, &client_addr);
        ql_conn_tick(&p.server, p.now_ms);
        qlite_test_shuttle(&p.server, &p.client, p.now_ms, &server_addr);
    }
    EXPECT_EQ(memcmp(&p.server.active_path.peer_addr, &client_addr, sizeof(client_addr)), 0);

    /* Now the "client" sends from a new address. */
    EXPECT_EQ(qlite_send(&p.client, cs, (const uint8_t *)"after", 5), 5);
    for (int i = 0; i < 20; i++) {
        p.now_ms += 5;
        ql_conn_tick(&p.client, p.now_ms);
        qlite_test_shuttle(&p.client, &p.server, p.now_ms, &new_client_addr);
        ql_conn_tick(&p.server, p.now_ms);
        /* The server's replies (including PATH_CHALLENGE) go wherever the
         * datagram that prompted them came from; deliver them back to the
         * client via a fixed, always-reachable dummy address. */
        qlite_test_shuttle(&p.server, &p.client, p.now_ms, &server_addr);
    }

    EXPECT_EQ(memcmp(&p.server.active_path.peer_addr, &new_client_addr, sizeof(new_client_addr)),
              0);

    qlite_test_pair_teardown(&p);
}

/* =========================================================================
 * PART 4 — chunk 6.4  Key update
 * ========================================================================= */

TEST(test_key_update_changes_app_keys_but_not_hp_key) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    uint8_t old_write_key[QL_AEAD_KEY_MAX_LEN], old_hp_key[QL_HP_KEY_MAX_LEN];
    memcpy(old_write_key, p.client.keys[QL_ENC_LEVEL_APP].write.key, QL_AEAD_KEY_MAX_LEN);
    memcpy(old_hp_key, p.client.keys[QL_ENC_LEVEL_APP].write.hp, QL_HP_KEY_MAX_LEN);
    bool old_phase = p.client.key_update.current_phase;

    EXPECT_EQ(qlite_key_update(&p.client), QLITE_OK);

    EXPECT_NE(memcmp(old_write_key, p.client.keys[QL_ENC_LEVEL_APP].write.key,
                     p.client.keys[QL_ENC_LEVEL_APP].write.key_len),
              0);
    /* RFC 9001 §6.4 — header protection key must NOT change. */
    EXPECT_EQ(memcmp(old_hp_key, p.client.keys[QL_ENC_LEVEL_APP].write.hp,
                     p.client.keys[QL_ENC_LEVEL_APP].write.hp_len),
              0);
    EXPECT_NE(p.client.key_update.current_phase, old_phase);

    qlite_test_pair_teardown(&p);
}

TEST(test_key_update_data_still_decrypts_correctly_on_peer) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);
    EXPECT_EQ(qlite_send(&p.client, cs, (const uint8_t *)"before-update", 13), 13);
    qlite_test_pair_pump(&p, 20, NULL);

    EXPECT_EQ(qlite_key_update(&p.client), QLITE_OK);

    EXPECT_EQ(qlite_send(&p.client, cs, (const uint8_t *)"after-update", 12), 12);
    qlite_test_pair_pump(&p, 40, NULL);

    ql_stream_t *ss = ql_stream_find(&p.server, cs->id);
    EXPECT_NE(ss, NULL);
    uint8_t out[64];
    size_t off = 0;
    for (;;) {
        int n = qlite_recv(&p.server, ss, out + off, sizeof(out) - off);
        if (n <= 0) {
            break;
        }
        off += (size_t)n;
    }
    EXPECT_EQ(off, (size_t)25);
    EXPECT_EQ(memcmp(out, "before-updateafter-update", 25), 0);

    /* Server should have reactively followed the client's key update. */
    EXPECT_EQ(p.server.key_update.current_phase, p.client.key_update.current_phase);

    qlite_test_pair_teardown(&p);
}

TEST(test_key_update_before_first_ack_is_rejected) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_key_update(&p.client), QLITE_OK);
    /* Immediately again, before the peer could possibly have acked the
     * packet sent in the new phase — must be refused per RFC 9001 §6.1. */
    EXPECT_EQ(qlite_key_update(&p.client), QLITE_ERR_AGAIN);

    qlite_test_pair_teardown(&p);
}

TEST(test_key_update_allowed_again_after_ack) {
    qlite_test_pair_t p;
    qlite_test_pair_setup(&p, NULL);

    EXPECT_EQ(qlite_key_update(&p.client), QLITE_OK);

    /* Force at least one APP-level packet to actually go out (and get
     * acked) in the new phase — nothing guarantees the tick loop sends
     * anything on its own with no application data pending. */
    ql_stream_t *cs = NULL;
    EXPECT_EQ(qlite_stream_open(&p.client, true, &cs), QLITE_OK);
    EXPECT_EQ(qlite_send(&p.client, cs, (const uint8_t *)"x", 1), 1);

    qlite_test_pair_pump(&p, 40, NULL);

    EXPECT_EQ(qlite_key_update(&p.client), QLITE_OK);

    qlite_test_pair_teardown(&p);
}

#endif /* QL_MIGRATION_TEST_H */
