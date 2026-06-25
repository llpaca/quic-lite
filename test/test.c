#include "test.h"
#include "frames.test.h"
#include "variant.test.h"
#include "tp.test.h"

int ql_tests_run = 0;


int main(void){
    /* frames test*/
    RUN_TEST(test_frame_ping_roundtrip);
    RUN_TEST(test_frame_padding_roundtrip);
    RUN_TEST(test_frame_reset_stream_roundtrip);
    RUN_TEST(test_frame_stop_sending_roundtrip);
    RUN_TEST(test_frame_crypto_roundtrip);
    RUN_TEST(test_frame_stream_with_all_flags);
    RUN_TEST(test_frame_stream_no_offset_no_length);
    RUN_TEST(test_frame_max_data_roundtrip);
    RUN_TEST(test_frame_max_stream_data_roundtrip);
    RUN_TEST(test_frame_max_streams_bidi_roundtrip);
    RUN_TEST(test_frame_data_blocked_roundtrip);
    RUN_TEST(test_frame_stream_data_blocked_roundtrip);
    RUN_TEST(test_frame_new_connection_id_roundtrip);
    RUN_TEST(test_frame_retire_connection_id_roundtrip);
    RUN_TEST(test_frame_path_challenge_roundtrip);
    RUN_TEST(test_frame_path_response_roundtrip);
    RUN_TEST(test_frame_connection_close_transport_roundtrip);
    RUN_TEST(test_frame_connection_close_app_roundtrip);
    RUN_TEST(test_frame_handshake_done_roundtrip);
    RUN_TEST(test_frame_ack_no_ranges_roundtrip);
    RUN_TEST(test_frame_ack_with_ranges_roundtrip);
    RUN_TEST(test_frame_decode_buf_too_small);
    RUN_TEST(test_frame_decode_unknown_type);

    /* variants test*/
    RUN_TEST(test_encode_rfc_examples);
    RUN_TEST(test_decode_rfc_examples);
    RUN_TEST(test_boundary_values);
    RUN_TEST(test_random_roundtrip);
    RUN_TEST(test_decode_errors);
    RUN_TEST(test_pkt_num_encode_decode);
    RUN_TEST(test_pkt_num_decode_wrap);

    /* tp enc/dec*/
    RUN_TEST(test_tp_roundtrip_basic);
    RUN_TEST(test_tp_defaults_after_decode);
    RUN_TEST(test_tp_disable_migration);
    RUN_TEST(test_tp_stateless_reset_token);
    RUN_TEST(test_tp_cid_fields);
    RUN_TEST(test_tp_buf_too_small);
    RUN_TEST(test_tp_invalid_payload_size);

    ql_test_summary();
    return 0;
}