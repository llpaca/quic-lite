#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "frames.test.h"
#include "variant.test.h"
#include "tp.test.h"
#include "udp.test.h"
#include "crypto.test.h"
#include "cid.test.h"
#include "tls.test.h"
#include "harness.test.h"
#include "stream.test.h"
#include "loss.test.h"
#include "migration.test.h"
#include "close.test.h"

int ql_tests_run = 0;

int main(void) {
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

    /* udp socket/send/recv */
    RUN_TEST(test_udp_socket_bind_any_ephemeral_port);
    RUN_TEST(test_udp_socket_bind_specific_loopback);
    RUN_TEST(test_udp_socket_is_nonblocking);
    RUN_TEST(test_udp_socket_rejects_bad_address);
    RUN_TEST(test_udp_socket_two_sockets_get_distinct_ports);

    RUN_TEST(test_udp_recv_returns_again_when_empty);
    /** @todo we need a null arg handler*/
    // RUN_TEST(test_udp_recv_rejects_null_args);
    // RUN_TEST(test_udp_send_rejects_null_buf);
    RUN_TEST(test_udp_send_rejects_zero_len);
    RUN_TEST(test_udp_send_returns_full_length_on_success);
    RUN_TEST(test_udp_send_recv_roundtrip);
    RUN_TEST(test_udp_recv_reports_correct_source_address);
    RUN_TEST(test_udp_recv_again_after_drain);
    RUN_TEST(test_now_ms_is_nonzero);
    RUN_TEST(test_now_ms_is_monotonic_nondecreasing);
    RUN_TEST(test_now_ms_advances_after_sleep);

    /* crypto - aead & header_pkt*/
    /* AEAD */
    RUN_TEST(test_aead_seal_basic);
    RUN_TEST(test_aead_seal_open_roundtrip);
    RUN_TEST(test_aead_pkt_num_uniqueness);
    RUN_TEST(test_aead_tampered_ciphertext_rejected);
    RUN_TEST(test_aead_tampered_tag_rejected);
    RUN_TEST(test_aead_tampered_aad_rejected);
    RUN_TEST(test_aead_wrong_pkt_num_rejected);
    RUN_TEST(test_aead_empty_plaintext);
    RUN_TEST(test_aead_buf_too_small_seal);
    RUN_TEST(test_aead_buf_too_small_open);
    RUN_TEST(test_aead_null_key_rejected);
    RUN_TEST(test_aead_key_not_set_rejected);
    RUN_TEST(test_aead_256_roundtrip);
    RUN_TEST(test_aead_rfc9001_vectors);
    /* Header Protection */
    RUN_TEST(test_hp_protect_remove_roundtrip_long);
    RUN_TEST(test_hp_protect_remove_roundtrip_short);
    RUN_TEST(test_hp_idempotent_double_remove);
    RUN_TEST(test_hp_different_samples_different_masks);
    RUN_TEST(test_hp_null_args_rejected);
    RUN_TEST(test_hp_rfc9001_vectors);

    /* cid generate/cmp */
    RUN_TEST(test_cid_generate_sets_len);
    RUN_TEST(test_cid_generate_max_len);
    RUN_TEST(test_cid_generate_zero_len);
    RUN_TEST(test_cid_generate_rejects_over_max_len);
    RUN_TEST(test_cid_generate_null_ptr_does_not_crash);
    RUN_TEST(test_cid_generate_two_calls_differ);
    RUN_TEST(test_cid_generate_zeroes_unused_tail_bytes);
    RUN_TEST(test_cid_generate_not_all_zero_bytes);
    RUN_TEST(test_cid_cmp_equal_cids);
    RUN_TEST(test_cid_cmp_self);
    RUN_TEST(test_cid_cmp_different_content_same_len);
    RUN_TEST(test_cid_cmp_different_lengths_never_equal);
    RUN_TEST(test_cid_cmp_zero_length_cids_equal);
    RUN_TEST(test_cid_cmp_differs_only_in_last_byte);
    RUN_TEST(test_cid_cmp_null_args);
    RUN_TEST(test_cid_cmp_max_len_roundtrip);

    /* tls callback wiring — chunk 3.2 */
    RUN_TEST(test_tls_provide_data_forwards_bytes_and_level);
    RUN_TEST(test_tls_provide_data_propagates_engine_error);
    RUN_TEST(test_tls_provide_data_levels_are_independent);
    RUN_TEST(test_tls_get_data_forwards_queued_bytes);
    RUN_TEST(test_tls_get_data_empty_returns_zero);
    RUN_TEST(test_tls_get_data_drains_across_multiple_small_reads);
    RUN_TEST(test_tls_install_keys_populates_and_marks_set);
    RUN_TEST(test_tls_install_keys_called_once_per_level_across_full_flow);
    RUN_TEST(test_tls_handshake_done_delegates_to_engine);
    RUN_TEST(test_tls_mock_handshake_end_to_end);
    RUN_TEST(test_tls_init_wires_all_seven_callbacks);
    RUN_TEST(test_tls_init_role_sets_correct_ssl_state);
    RUN_TEST(test_tls_init_null_args_rejected);
    RUN_TEST(test_tls_free_is_safe_on_null_and_zeroed);
    RUN_TEST(test_tls_real_handshake_end_to_end_via_quictls);

    /* harness self-check — chunk 3-7 integration bootstrap */
    RUN_TEST(test_harness_pair_reaches_connected_state);

    /* streams & flow control — chunk 4.x */
    RUN_TEST(test_stream_open_assigns_correct_id_and_type);
    RUN_TEST(test_stream_open_increments_sequentially_by_four);
    RUN_TEST(test_stream_open_fresh_stream_starts_ready);
    RUN_TEST(test_stream_find_locates_open_stream);
    RUN_TEST(test_stream_open_respects_peer_max_streams_limit);
    RUN_TEST(test_stream_send_recv_roundtrip_small);
    RUN_TEST(test_stream_send_recv_roundtrip_multi_packet);
    RUN_TEST(test_stream_fin_delivers_eof);
    RUN_TEST(test_stream_reset_delivers_to_peer);
    RUN_TEST(test_stream_peer_initiated_stream_is_auto_created);
    RUN_TEST(test_stream_flow_control_caps_delivery_at_recv_limit);
    RUN_TEST(test_stream_flow_control_window_grows_as_consumed);
    RUN_TEST(test_conn_level_flow_control_caps_across_streams);
    RUN_TEST(test_stream_rx_push_out_of_order_reassembles);
    RUN_TEST(test_stream_rx_push_duplicate_bytes_are_idempotent);
    RUN_TEST(test_stream_rx_push_final_size_mismatch_rejected);
    RUN_TEST(test_stream_rx_push_respects_flow_control_limit);

    /* loss detection & congestion control — chunk 5.x */
    RUN_TEST(test_ack_record_first_packet_starts_one_range);
    RUN_TEST(test_ack_record_consecutive_packets_extend_one_range);
    RUN_TEST(test_ack_record_gap_creates_second_range);
    RUN_TEST(test_ack_record_gap_fill_merges_ranges);
    RUN_TEST(test_ack_record_duplicate_packet_is_noop);
    RUN_TEST(test_ack_record_non_ack_eliciting_does_not_schedule_ack);
    RUN_TEST(test_send_ack_encodes_largest_and_first_range);
    RUN_TEST(test_send_ack_with_multiple_ranges_roundtrips_through_wire_codec);
    RUN_TEST(test_rtt_sample_first_sample_sets_smoothed_rtt);
    RUN_TEST(test_rtt_sample_subsequent_sample_updates_smoothed_rtt);
    RUN_TEST(test_rtt_sample_ack_delay_reduces_adjusted_rtt);
    RUN_TEST(test_congestion_control_initial_window_matches_rfc9002);
    RUN_TEST(test_sent_packets_are_marked_acked_after_real_roundtrip);
    RUN_TEST(test_lost_stream_data_is_retransmitted_and_still_arrives);
    RUN_TEST(test_pto_arms_when_ack_eliciting_packet_outstanding);

    /* migration, key update, CID rotation — chunk 6.x */
    RUN_TEST(test_cid_issuance_grows_peer_cid_table);
    RUN_TEST(test_cid_issuance_respects_active_cid_limit);
    RUN_TEST(test_new_connection_id_frame_roundtrips_through_wire_codec);
    RUN_TEST(test_retire_connection_id_marks_local_cid_retired);
    RUN_TEST(test_path_challenge_frame_roundtrips_through_wire_codec);
    RUN_TEST(test_path_challenge_is_echoed_as_path_response);
    RUN_TEST(test_migration_from_new_address_is_validated_and_promoted);
    RUN_TEST(test_key_update_changes_app_keys_but_not_hp_key);
    RUN_TEST(test_key_update_data_still_decrypts_correctly_on_peer);
    RUN_TEST(test_key_update_before_first_ack_is_rejected);
    RUN_TEST(test_key_update_allowed_again_after_ack);

    /* close, listener/accept, stateless reset — chunk 7.x */
    RUN_TEST(test_close_transitions_self_to_closing);
    RUN_TEST(test_close_delivers_connection_close_to_peer);
    RUN_TEST(test_close_app_error_delivers_app_code_to_peer);
    RUN_TEST(test_close_fires_on_close_callback_on_peer);
    RUN_TEST(test_closing_state_retransmits_close_pkt_via_socket);
    RUN_TEST(test_draining_state_sends_nothing);
    RUN_TEST(test_drain_timer_expiry_signals_conn_tick_done);
    RUN_TEST(test_idle_timeout_closes_silently);
    RUN_TEST(test_double_close_is_a_noop);
    RUN_TEST(test_conn_free_releases_stream_list);
    RUN_TEST(test_listener_accepts_real_client_connection);
    RUN_TEST(test_listener_sends_stateless_reset_for_unknown_short_header);

    ql_test_summary();
    return 0;
}