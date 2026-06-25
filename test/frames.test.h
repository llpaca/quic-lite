#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <qlite.h>

// int ql_tests_run = 0;

/* =========================================================================
 * ql_frame_encode / ql_frame_decode tests
 * ========================================================================= */

TEST(test_frame_ping_roundtrip) {
    uint8_t buf[4];
    ql_frame_t enc, dec;

    enc.type = QL_FRAME_PING;
    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_EQ(n, 1);
    EXPECT_EQ(buf[0], 0x01);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, 1);
    EXPECT_EQ(dec.type, QL_FRAME_PING);
}

TEST(test_frame_padding_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;

    enc.type             = QL_FRAME_PADDING;
    enc.u.padding.length = 8;
    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_EQ(n, 8);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(dec.type, QL_FRAME_PADDING);
    EXPECT_EQ(dec.u.padding.length, (size_t)8);
    (void)m;
}

TEST(test_frame_reset_stream_roundtrip) {
    uint8_t buf[32];
    ql_frame_t enc, dec;

    enc.type                      = QL_FRAME_RESET_STREAM;
    enc.u.reset_stream.stream_id  = 7;
    enc.u.reset_stream.error_code = 0xDEAD;
    enc.u.reset_stream.final_size = 999999;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.type,                      QL_FRAME_RESET_STREAM);
    EXPECT_EQ(dec.u.reset_stream.stream_id,  (ql_stream_id_t)7);
    EXPECT_EQ(dec.u.reset_stream.error_code, (ql_app_error_t)0xDEAD);
    EXPECT_EQ(dec.u.reset_stream.final_size, (uint64_t)999999);
}

TEST(test_frame_stop_sending_roundtrip) {
    uint8_t buf[32];
    ql_frame_t enc, dec;

    enc.type                       = QL_FRAME_STOP_SENDING;
    enc.u.stop_sending.stream_id   = 4;
    enc.u.stop_sending.error_code  = 42;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.stop_sending.stream_id,  (ql_stream_id_t)4);
    EXPECT_EQ(dec.u.stop_sending.error_code, (ql_app_error_t)42);
}

TEST(test_frame_crypto_roundtrip) {
    uint8_t buf[64];
    static const uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    ql_frame_t enc, dec;

    enc.type           = QL_FRAME_CRYPTO;
    enc.u.crypto.offset = 128;
    enc.u.crypto.length = sizeof(data);
    enc.u.crypto.data   = data;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.crypto.offset, (uint64_t)128);
    EXPECT_EQ(dec.u.crypto.length, (uint64_t)sizeof(data));
    EXPECT(memcmp(dec.u.crypto.data, data, sizeof(data)) == 0);
}

TEST(test_frame_stream_with_all_flags) {
    uint8_t buf[64];
    static const uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    ql_frame_t enc, dec;

    enc.type               = QL_FRAME_STREAM_OFF_LEN_FIN;
    enc.u.stream.stream_id = 12;
    enc.u.stream.offset    = 512;
    enc.u.stream.length    = sizeof(payload);
    enc.u.stream.data      = payload;
    enc.u.stream.has_offset = true;
    enc.u.stream.has_length = true;
    enc.u.stream.fin        = true;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.stream.stream_id,  (ql_stream_id_t)12);
    EXPECT_EQ(dec.u.stream.offset,     (uint64_t)512);
    EXPECT_EQ(dec.u.stream.length,     (uint64_t)sizeof(payload));
    EXPECT_EQ(dec.u.stream.has_offset, true);
    EXPECT_EQ(dec.u.stream.has_length, true);
    EXPECT_EQ(dec.u.stream.fin,        true);
    EXPECT(memcmp(dec.u.stream.data, payload, sizeof(payload)) == 0);
}

TEST(test_frame_stream_no_offset_no_length) {
    /* OFF=0 LEN=0: data runs to end of packet, offset is implicitly 0 */
    uint8_t buf[32];
    static const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    ql_frame_t enc, dec;

    enc.type                = QL_FRAME_STREAM;
    enc.u.stream.stream_id  = 0;
    enc.u.stream.offset     = 0;
    enc.u.stream.length     = sizeof(payload);
    enc.u.stream.data       = payload;
    enc.u.stream.has_offset = false;
    enc.u.stream.has_length = false;
    enc.u.stream.fin        = false;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.stream.has_offset, false);
    EXPECT_EQ(dec.u.stream.has_length, false);
    EXPECT_EQ(dec.u.stream.length,     (uint64_t)sizeof(payload));
    EXPECT(memcmp(dec.u.stream.data, payload, sizeof(payload)) == 0);
}

TEST(test_frame_max_data_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;

    enc.type                   = QL_FRAME_MAX_DATA;
    enc.u.max_data.maximum_data = 1000000;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.max_data.maximum_data, (uint64_t)1000000);
}

TEST(test_frame_max_stream_data_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;

    enc.type                               = QL_FRAME_MAX_STREAM_DATA;
    enc.u.max_stream_data.stream_id        = 3;
    enc.u.max_stream_data.maximum_stream_data = 65536;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.max_stream_data.stream_id,           (ql_stream_id_t)3);
    EXPECT_EQ(dec.u.max_stream_data.maximum_stream_data, (uint64_t)65536);
}

TEST(test_frame_max_streams_bidi_roundtrip) {
    uint8_t buf[8];
    ql_frame_t enc, dec;

    enc.type                      = QL_FRAME_MAX_STREAMS_BIDI;
    enc.u.max_streams.maximum_streams = 100;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);
    EXPECT_EQ(buf[0], 0x12);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.type,                       QL_FRAME_MAX_STREAMS_BIDI);
    EXPECT_EQ(dec.u.max_streams.maximum_streams, (uint64_t)100);
}

TEST(test_frame_data_blocked_roundtrip) {
    uint8_t buf[8];
    ql_frame_t enc, dec;

    enc.type                    = QL_FRAME_DATA_BLOCKED;
    enc.u.data_blocked.data_limit = 4096;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.data_blocked.data_limit, (uint64_t)4096);
}

TEST(test_frame_stream_data_blocked_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;

    enc.type                                   = QL_FRAME_STREAM_DATA_BLOCKED;
    enc.u.stream_data_blocked.stream_id        = 8;
    enc.u.stream_data_blocked.stream_data_limit = 2048;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.stream_data_blocked.stream_id,         (ql_stream_id_t)8);
    EXPECT_EQ(dec.u.stream_data_blocked.stream_data_limit, (uint64_t)2048);
}

TEST(test_frame_new_connection_id_roundtrip) {
    uint8_t buf[64];
    ql_frame_t enc, dec;

    enc.type                    = QL_FRAME_NEW_CONNECTION_ID;
    enc.u.new_cid.sequence_num  = 5;
    enc.u.new_cid.retire_prior_to = 3;
    enc.u.new_cid.cid.len       = 8;
    memset(enc.u.new_cid.cid.data, 0xAB, 8);
    memset(enc.u.new_cid.stateless_reset_token.data, 0xCD, QL_RESET_TOKEN_LEN);

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.new_cid.sequence_num,    (uint64_t)5);
    EXPECT_EQ(dec.u.new_cid.retire_prior_to, (uint64_t)3);
    EXPECT_EQ(dec.u.new_cid.cid.len,         (uint8_t)8);
    EXPECT(memcmp(dec.u.new_cid.cid.data,
                  enc.u.new_cid.cid.data, 8) == 0);
    EXPECT(memcmp(dec.u.new_cid.stateless_reset_token.data,
                  enc.u.new_cid.stateless_reset_token.data,
                  QL_RESET_TOKEN_LEN) == 0);
}

TEST(test_frame_retire_connection_id_roundtrip) {
    uint8_t buf[8];
    ql_frame_t enc, dec;

    enc.type                    = QL_FRAME_RETIRE_CONNECTION_ID;
    enc.u.retire_cid.sequence_num = 9;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.retire_cid.sequence_num, (uint64_t)9);
}

TEST(test_frame_path_challenge_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;
    static const uint8_t challenge[8] = {1,2,3,4,5,6,7,8};

    enc.type = QL_FRAME_PATH_CHALLENGE;
    memcpy(enc.u.path_challenge.data.data, challenge, 8);

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_EQ(n, 9); /* 1 type byte + 8 data bytes */

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT(memcmp(dec.u.path_challenge.data.data, challenge, 8) == 0);
}

TEST(test_frame_path_response_roundtrip) {
    uint8_t buf[16];
    ql_frame_t enc, dec;
    static const uint8_t resp[8] = {8,7,6,5,4,3,2,1};

    enc.type = QL_FRAME_PATH_RESPONSE;
    memcpy(enc.u.path_response.data.data, resp, 8);

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_EQ(n, 9);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT(memcmp(dec.u.path_response.data.data, resp, 8) == 0);
}

TEST(test_frame_connection_close_transport_roundtrip) {
    uint8_t buf[64];
    static const uint8_t reason[] = "bad frame";
    ql_frame_t enc, dec;

    enc.type                       = QL_FRAME_CONNECTION_CLOSE;
    enc.u.conn_close.is_app        = false;
    enc.u.conn_close.error_code    = QL_ERR_PROTOCOL_VIOLATION;
    enc.u.conn_close.frame_type    = QL_FRAME_STREAM;
    enc.u.conn_close.reason_length = sizeof(reason) - 1;
    enc.u.conn_close.reason_phrase = reason;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.conn_close.is_app,        false);
    EXPECT_EQ(dec.u.conn_close.error_code,    QL_ERR_PROTOCOL_VIOLATION);
    EXPECT_EQ(dec.u.conn_close.frame_type,    QL_FRAME_STREAM);
    EXPECT_EQ(dec.u.conn_close.reason_length, (uint64_t)(sizeof(reason) - 1));
    EXPECT(memcmp(dec.u.conn_close.reason_phrase, reason,
                  sizeof(reason) - 1) == 0);
}

TEST(test_frame_connection_close_app_roundtrip) {
    uint8_t buf[64];
    static const uint8_t reason[] = "app error";
    ql_frame_t enc, dec;

    enc.type                       = QL_FRAME_CONNECTION_CLOSE_APP;
    enc.u.conn_close.is_app        = true;
    enc.u.conn_close.app_error_code = 0xFF;
    enc.u.conn_close.reason_length = sizeof(reason) - 1;
    enc.u.conn_close.reason_phrase = reason;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.conn_close.is_app,         true);
    EXPECT_EQ(dec.u.conn_close.app_error_code,  (ql_app_error_t)0xFF);
    EXPECT_EQ(dec.u.conn_close.reason_length,   (uint64_t)(sizeof(reason) - 1));
    EXPECT(memcmp(dec.u.conn_close.reason_phrase, reason,
                  sizeof(reason) - 1) == 0);
}

TEST(test_frame_handshake_done_roundtrip) {
    uint8_t buf[4];
    ql_frame_t enc, dec;

    enc.type = QL_FRAME_HANDSHAKE_DONE;
    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_EQ(n, 1);
    EXPECT_EQ(buf[0], 0x1E);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, 1);
    EXPECT_EQ(dec.type, QL_FRAME_HANDSHAKE_DONE);
}

TEST(test_frame_ack_no_ranges_roundtrip) {
    uint8_t buf[32];
    ql_frame_t enc, dec;

    enc.type                  = QL_FRAME_ACK;
    enc.u.ack.largest_acked   = 100;
    enc.u.ack.ack_delay       = 50;
    enc.u.ack.range_count     = 0;
    enc.u.ack.first_ack_range = 9;   /* acks packets 91–100 */
    enc.u.ack.has_ecn         = false;

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.ack.largest_acked,   (ql_pkt_num_t)100);
    EXPECT_EQ(dec.u.ack.ack_delay,       (uint64_t)50);
    EXPECT_EQ(dec.u.ack.range_count,     (uint64_t)0);
    EXPECT_EQ(dec.u.ack.first_ack_range, (uint64_t)9);
    EXPECT_EQ(dec.u.ack.has_ecn,         false);
}

TEST(test_frame_ack_with_ranges_roundtrip) {
    uint8_t buf[64];
    ql_frame_t enc, dec;

    /*
     * Acknowledge two blocks:
     *   block 0: packets 90–100  (first_ack_range = 10, covers 11 pkts)
     *   block 1: packets 80–85   (gap=3 means 3 unacked between blocks,
     *                             range_len=5 means 6 pkts)
     */
    enc.type                  = QL_FRAME_ACK;
    enc.u.ack.largest_acked   = 100;
    enc.u.ack.ack_delay       = 0;
    enc.u.ack.range_count     = 1;
    enc.u.ack.first_ack_range = 10;
    enc.u.ack.has_ecn         = false;
    enc.u.ack.ranges[0].largest = 3;   /* gap value on the wire */
    enc.u.ack.ranges[0].count   = 5;   /* range_len value: count-1 written */

    int n = ql_frame_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_frame_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(m, n);
    EXPECT_EQ(dec.u.ack.range_count,       (uint64_t)1);
    EXPECT_EQ(dec.u.ack.first_ack_range,   (uint64_t)10);
    /* decoded range: largest = 100 - 10 - 3 - 2 = 85, count = 5+1 = 6 */
    EXPECT_EQ(dec.u.ack.ranges[0].largest, (ql_pkt_num_t)85);
    EXPECT_EQ(dec.u.ack.ranges[0].count,   (uint64_t)5); // to be noted that this passes on 5(as we begin cnt with 0)
}

TEST(test_frame_decode_buf_too_small) {
    /* truncated RESET_STREAM — only the type byte */
    uint8_t buf[1] = {0x04};
    ql_frame_t dec;
    int m = ql_frame_decode(buf, 1, &dec);
    EXPECT_LT(m, 0);
}

TEST(test_frame_decode_unknown_type) {
    uint8_t buf[2] = {0x7F, 0x00}; /* 0x7F is not a valid frame type */
    ql_frame_t dec;
    int m = ql_frame_decode(buf, sizeof(buf), &dec);
    EXPECT_LT(m, 0);
}

// int main(void){
//     RUN_TEST(test_frame_ping_roundtrip);
//     RUN_TEST(test_frame_padding_roundtrip);
//     RUN_TEST(test_frame_reset_stream_roundtrip);
//     RUN_TEST(test_frame_stop_sending_roundtrip);
//     RUN_TEST(test_frame_crypto_roundtrip);
//     RUN_TEST(test_frame_stream_with_all_flags);
//     RUN_TEST(test_frame_stream_no_offset_no_length);
//     RUN_TEST(test_frame_max_data_roundtrip);
//     RUN_TEST(test_frame_max_stream_data_roundtrip);
//     RUN_TEST(test_frame_max_streams_bidi_roundtrip);
//     RUN_TEST(test_frame_data_blocked_roundtrip);
//     RUN_TEST(test_frame_stream_data_blocked_roundtrip);
//     RUN_TEST(test_frame_new_connection_id_roundtrip);
//     RUN_TEST(test_frame_retire_connection_id_roundtrip);
//     RUN_TEST(test_frame_path_challenge_roundtrip);
//     RUN_TEST(test_frame_path_response_roundtrip);
//     RUN_TEST(test_frame_connection_close_transport_roundtrip);
//     RUN_TEST(test_frame_connection_close_app_roundtrip);
//     RUN_TEST(test_frame_handshake_done_roundtrip);
//     RUN_TEST(test_frame_ack_no_ranges_roundtrip);
//     RUN_TEST(test_frame_ack_with_ranges_roundtrip);
//     RUN_TEST(test_frame_decode_buf_too_small);
//     RUN_TEST(test_frame_decode_unknown_type);

//     ql_test_summary();
//     return 0;
// }