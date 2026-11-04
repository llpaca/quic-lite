#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <qlite.h>

// int ql_tests_run = 0;

/* =========================================================================
 * ql_tp_encode / ql_tp_decode tests
 * ========================================================================= */

TEST(test_tp_roundtrip_basic) {
    uint8_t buf[256];
    ql_transport_params_t enc, dec;
    memset(&enc, 0, sizeof(enc));

    enc.max_idle_timeout_ms                 = 30000;
    enc.initial_max_data                    = 1048576;
    enc.initial_max_stream_data_bidi_local  = 65536;
    enc.initial_max_stream_data_bidi_remote = 65536;
    enc.initial_max_stream_data_uni         = 32768;
    enc.initial_max_streams_bidi            = 100;
    enc.initial_max_streams_uni             = 100;
    enc.ack_delay_exponent                  = 3;
    enc.max_ack_delay_ms                    = 25;
    enc.active_cid_limit                    = 8;

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    int m = ql_tp_decode(buf, (size_t)n, &dec);
    EXPECT_GT(m, 0);

    EXPECT_EQ(dec.max_idle_timeout_ms, (uint64_t)30000);
    EXPECT_EQ(dec.initial_max_data, (uint64_t)1048576);
    EXPECT_EQ(dec.initial_max_stream_data_bidi_local, (uint64_t)65536);
    EXPECT_EQ(dec.initial_max_stream_data_bidi_remote, (uint64_t)65536);
    EXPECT_EQ(dec.initial_max_stream_data_uni, (uint64_t)32768);
    EXPECT_EQ(dec.initial_max_streams_bidi, (uint64_t)100);
    EXPECT_EQ(dec.initial_max_streams_uni, (uint64_t)100);
    EXPECT_EQ(dec.active_cid_limit, (uint64_t)8);
}

TEST(test_tp_defaults_after_decode) {
    /* encode an empty param set — decode should give RFC defaults */
    uint8_t buf[64];
    ql_transport_params_t enc, dec;
    memset(&enc, 0, sizeof(enc));

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_GE(n, 0);

    ql_tp_decode(buf, (size_t)n, &dec);

    EXPECT_EQ(dec.max_udp_payload_size, (uint64_t)QL_MAX_UDP_PAYLOAD_DEFAULT);
    EXPECT_EQ(dec.ack_delay_exponent, (uint64_t)QL_DEFAULT_ACK_DELAY_EXP);
    EXPECT_EQ(dec.max_ack_delay_ms, (uint64_t)QL_DEFAULT_MAX_ACK_DELAY_MS);
    EXPECT_EQ(dec.active_cid_limit, (uint64_t)QL_DEFAULT_ACTIVE_CID_LIMIT);
}

TEST(test_tp_disable_migration) {
    uint8_t buf[64];
    ql_transport_params_t enc, dec;
    memset(&enc, 0, sizeof(enc));

    enc.disable_active_migration = true;

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    ql_tp_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(dec.disable_active_migration, true);
}

TEST(test_tp_stateless_reset_token) {
    uint8_t buf[64];
    ql_transport_params_t enc, dec;
    memset(&enc, 0, sizeof(enc));

    enc.has_stateless_reset_token = true;
    memset(enc.stateless_reset_token.data, 0xAB, QL_RESET_TOKEN_LEN);

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    ql_tp_decode(buf, (size_t)n, &dec);
    EXPECT_EQ(dec.has_stateless_reset_token, true);
    EXPECT(memcmp(dec.stateless_reset_token.data, enc.stateless_reset_token.data,
                  QL_RESET_TOKEN_LEN) == 0);
}

TEST(test_tp_cid_fields) {
    uint8_t buf[128];
    ql_transport_params_t enc, dec;
    memset(&enc, 0, sizeof(enc));

    enc.original_dst_cid.len = 8;
    memset(enc.original_dst_cid.data, 0x11, 8);
    enc.initial_src_cid.len = 8;
    memset(enc.initial_src_cid.data, 0x22, 8);
    enc.has_retry_src_cid = true;
    enc.retry_src_cid.len = 8;
    memset(enc.retry_src_cid.data, 0x33, 8);

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_GT(n, 0);

    ql_tp_decode(buf, (size_t)n, &dec);

    EXPECT_EQ(dec.original_dst_cid.len, (uint8_t)8);
    EXPECT(memcmp(dec.original_dst_cid.data, enc.original_dst_cid.data, 8) == 0);
    EXPECT_EQ(dec.initial_src_cid.len, (uint8_t)8);
    EXPECT(memcmp(dec.initial_src_cid.data, enc.initial_src_cid.data, 8) == 0);
    EXPECT_EQ(dec.has_retry_src_cid, true);
    EXPECT_EQ(dec.retry_src_cid.len, (uint8_t)8);
    EXPECT(memcmp(dec.retry_src_cid.data, enc.retry_src_cid.data, 8) == 0);
}

TEST(test_tp_buf_too_small) {
    uint8_t buf[1];
    ql_transport_params_t enc;
    memset(&enc, 0, sizeof(enc));
    enc.initial_max_data = 1048576;

    int n = ql_tp_encode(&enc, buf, sizeof(buf));
    EXPECT_LT(n, 0);
}

TEST(test_tp_invalid_payload_size) {
    /* max_udp_payload_size below 1200 must be rejected on decode */
    uint8_t buf[16];
    size_t pos = 0;

    /* hand-craft: id=0x03, len=1, value=63 (below 1200) */
    buf[pos++] = 0x03; /* QL_TP_MAX_UDP_PAYLOAD_SIZE, 1-byte varint */
    buf[pos++] = 0x01; /* length = 1 */
    buf[pos++] = 0x3F; /* value = 63 */

    ql_transport_params_t dec;
    int m = ql_tp_decode(buf, pos, &dec);
    EXPECT_LT(m, 0);
}

TEST(test_tp_reject_duplicate_tp_id) {
    ql_transport_params_t t;

    /* same id, different values */
    static const uint8_t dup_diff_value[] = {0x04, 0x01, 0x05, 0x04, 0x01, 0x07};
    /* same id, same value: still a duplicate */
    static const uint8_t dup_same_value[] = {0x04, 0x01, 0x05, 0x04, 0x01, 0x05};
    /* duplicate separated by another parameter */
    static const uint8_t dup_not_adjacent[] = {0x04, 0x01, 0x05, 0x0A, 0x01,
                                               0x03, 0x04, 0x01, 0x07};
    /* duplicate of a parameter that carries no value */
    static const uint8_t dup_empty_param[] = {0x0C, 0x00, 0x0C, 0x00};

    EXPECT_LT(ql_tp_decode(dup_diff_value, sizeof(dup_diff_value), &t), 0);
    EXPECT_LT(ql_tp_decode(dup_same_value, sizeof(dup_same_value), &t), 0);
    EXPECT_LT(ql_tp_decode(dup_not_adjacent, sizeof(dup_not_adjacent), &t), 0);
    EXPECT_LT(ql_tp_decode(dup_empty_param, sizeof(dup_empty_param), &t), 0);

    /* control: unique ids must still decode */
    static const uint8_t unique_ids[] = {0x04, 0x01, 0x05, 0x0A, 0x01, 0x03};
    EXPECT_EQ(ql_tp_decode(unique_ids, sizeof(unique_ids), &t), (int)sizeof(unique_ids));
    EXPECT_EQ(t.initial_max_data, (uint64_t)5);
    EXPECT_EQ(t.ack_delay_exponent, (uint64_t)3);
}

// int main(void){

//     RUN_TEST(test_tp_roundtrip_basic);
//     RUN_TEST(test_tp_defaults_after_decode);
//     RUN_TEST(test_tp_disable_migration);
//     RUN_TEST(test_tp_stateless_reset_token);
//     RUN_TEST(test_tp_cid_fields);
//     RUN_TEST(test_tp_buf_too_small);
//     RUN_TEST(test_tp_invalid_payload_size);

//     ql_test_summary();
//     return 0;
// }