/**
 * @file    qlite.h
 * @brief   quic-lite — single-header QUIC v1 type definitions (RFC 9000/9001/9002)
 * LICENSE  MIT
 * DATE     2026-06-17
 *
 * PRIMARY RFC REFERENCES
 *   RFC 9000  QUIC: A UDP-Based Multiplexed and Secure Transport
 *   RFC 9001  Using TLS to Secure QUIC
 *   RFC 9002  QUIC Loss Detection and Congestion Control
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L // NOLINT(bugprone-reserved-identifier)
#endif
#ifndef QLITE_H
#define QLITE_H

/* Platform / Compiler Gaurds */

#if defined(__cplusplus)
extern "C" {
#endif

/* C standard headers */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* POSIX — needed in implementation but declared here so all TUs agree */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

/* dependcies*/
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

/* helpers*/
/* Write Varint — encodes val, advances pos, returns error on overflow */
#define WV(val)                                                           \
    do {                                                                  \
        int _n = ql_varint_encode(buf + pos, cap - pos, (uint64_t)(val)); \
        if (_n < 0)                                                       \
            return _n;                                                    \
        pos += (size_t)_n;                                                \
    } while (0)
/* Write Bytes — copies raw bytes, advances pos, returns error on overflow */
#define WB(ptr, len)                  \
    do {                              \
        size_t _l = (size_t)(len);    \
        if (pos + _l > cap)           \
            return QLITE_ERR_BUF;     \
        memcpy(buf + pos, (ptr), _l); \
        pos += _l;                    \
    } while (0)

#define TP_VARINT(id, val)                                    \
    do {                                                      \
        if (tp_write_varint(buf, &pos, cap, (id), (val)) < 0) \
            return QLITE_ERR_BUF;                             \
    } while (0)
#define TP_BYTES(id, data, len)                                      \
    do {                                                             \
        if (tp_write_bytes(buf, &pos, cap, (id), (data), (len)) < 0) \
            return QLITE_ERR_BUF;                                    \
    } while (0)
#define TP_CID(id, cid)                                    \
    do {                                                   \
        if (tp_write_cid(buf, &pos, cap, (id), (cid)) < 0) \
            return QLITE_ERR_BUF;                          \
    } while (0)

#define RV(field)                                             \
    do {                                                      \
        ql_varint_t _v;                                       \
        int _n = ql_varint_decode(buf + pos, len - pos, &_v); \
        if (_n < 0 || pos + (size_t)_n > len)                 \
            return QLITE_ERR_BUF;                             \
        (field) = (__typeof__(field))_v;                      \
        pos += (size_t)_n;                                    \
    } while (0)

#define RB(dst, n)                    \
    do {                              \
        size_t _l = (size_t)(n);      \
        if (pos + _l > len)           \
            return QLITE_ERR_BUF;     \
        memcpy((dst), buf + pos, _l); \
        pos += _l;                    \
    } while (0)

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
 * QUIC variable-length integer (varint).  Wire encoding uses 2 MSBs of the
 * first byte to signal total byte-width:
 *
 *   prefix 00 → 1 byte  (6-bit value,  max 63)
 *   prefix 01 → 2 bytes (14-bit value, max 16 383)
 *   prefix 10 → 4 bytes (30-bit value, max 1 073 741 823)
 *   prefix 11 → 8 bytes (62-bit value, max 4 611 686 018 427 387 903)
 *
 * 16 Table 1.
 */
typedef uint64_t ql_varint_t;
#define QL_VARINT_MAX UINT64_C(4611686018427387903) /* 2^62 − 1  16 */
#define QL_VARINT_1B_MAX UINT64_C(63)
#define QL_VARINT_2B_MAX UINT64_C(16383)
#define QL_VARINT_4B_MAX UINT64_C(1073741823)

/* Minimum encoded sizes for varints — useful for buffer-size assertions */
#define QL_VARINT_1B_SIZE 1
#define QL_VARINT_2B_SIZE 2
#define QL_VARINT_4B_SIZE 4
#define QL_VARINT_8B_SIZE 8

/* Stream ID 2.1 — 62-bit, lower 2 bits encode initiator + direction */
typedef uint64_t ql_stream_id_t;

/* Packet number 12.3 — 62-bit per-packet-number-space counter */
typedef uint64_t ql_pkt_num_t;

/*
 * Sentinel "no packet number yet received" value.
 * Must not collide with any valid packet number (0 .. 2^62-1).
 */
#define QL_PKT_NUM_NONE UINT64_MAX

/* Connection ID 5.1 — opaque, 1–20 bytes; len=0 means zero-length CID */
#define QL_CID_MAX_LEN 20
typedef struct {
    uint8_t data[QL_CID_MAX_LEN];
    uint8_t len; /* 0 = zero-length (5.1) */
} ql_cid_t;

/* Stateless Reset Token 10.3.2 — exactly 16 bytes */
#define QL_RESET_TOKEN_LEN 16
typedef struct {
    uint8_t data[QL_RESET_TOKEN_LEN];
} ql_reset_token_t;

/* Path validation data 19.17–19.18 — exactly 8 bytes */
#define QL_PATH_DATA_LEN 8
typedef struct {
    uint8_t data[QL_PATH_DATA_LEN];
} ql_path_data_t;

/*
 * One contiguous ACK range: acknowledges all packets in
 * [largest − (count − 1), largest].
 */
typedef struct {
    ql_pkt_num_t largest;
    uint64_t count; /* number of contiguous packet numbers */
} ql_ack_range_t;

/* 15 — QUIC version identifiers */
#define QL_VERSION_1 UINT32_C(0x00000001)             /* QUIC v1 */
#define QL_VERSION_NEGOTIATION UINT32_C(0x00000000)   /* Version Negotiation 17.2.1 */
#define QL_VERSION_RESERVED_MASK UINT32_C(0x0A0A0A0A) /* 6.3 force version-neg */

/* 14.1 — Datagram / MTU limits */
#define QL_MIN_INITIAL_DATAGRAM_SIZE 1200 /* client Initial MUST be >= 1200 bytes */
#define QL_MIN_UDP_PAYLOAD_SIZE 1200      /* 14.1 path minimum */
#define QL_MAX_UDP_PAYLOAD_DEFAULT 65527  /* 18.2 tp default */
#define QL_PATH_MTU_DEFAULT 1200          /* conservative initial MTU */
#define QL_PATH_MTU_ETHERNET 1472         /* 1500 - 20(IP) - 8(UDP) */

/* 13.2 — ACK tracking */
#define QL_ACK_RANGE_MAX 64      /* max ACK ranges we track in one frame */
#define QL_ACK_DELAY_THRESHOLD 2 /* send ACK after this many ack-eliciting pkts */
#define QL_ACK_TIMEOUT_MS 25     /* max ACK delay when not in threshold path */

/* RFC 9002 6.1 / 6.2 — loss detection constants */
#define QL_LOSS_PACKET_THRESHOLD 3        /* kPacketThreshold */
#define QL_LOSS_TIME_THRESHOLD_NUM 9      /* kTimeThreshold = 9/8 */
#define QL_LOSS_TIME_THRESHOLD_DEN 8
#define QL_TIMER_GRANULARITY_MS 1         /* kGranularity */
#define QL_INITIAL_RTT_US 500000          /* kInitialRtt = 500ms, used before any sample */

/* Key material sizes (RFC 9001) */
#define QL_AEAD_KEY_MAX_LEN 32 /* AES-256-GCM key */
#define QL_AEAD_IV_MAX_LEN 12  /* AEAD nonce / IV */
#define QL_HP_KEY_MAX_LEN 32   /* header-protection key */
#define QL_SECRET_MAX_LEN 48   /* HKDF secret (SHA-384 output size) */

/* 12.1 / RFC 9001 5.3 — AEAD tag is always 16 bytes */
#define QL_AEAD_TAG_LEN 16

/* RFC 9001 5.4.2 — Header-protection sample is always 16 bytes,
 * taken starting 4 bytes after the start of the encoded packet number */
#define QL_HP_SAMPLE_LEN 16
#define QL_HP_SAMPLE_OFFSET 4 /* bytes after start of pkt-num field */

/* 12.2 — Coalescing: max datagrams we'll pack before flushing */
#define QL_MAX_COALESCE_PKTS 8

/* Send ring sizes — must be powers of 2 */
#define QL_SENT_PKT_MAX 4096     /* sent-packet tracking ring */
#define QL_STREAM_BUF_SIZE 65536 /* per-stream tx/rx ring */
#define QL_OUTBUF_SIZE 65536     /* assembled-datagram output queue */
#define QL_CRYPTO_BUF_SIZE 16384 /* per-level CRYPTO reorder buffer */
#define QL_CONN_FC_WINDOW_DEFAULT (QL_STREAM_BUF_SIZE * 4) /* connection-level recv window step (4.4.3) */

/* Server limits */
#define QL_SERVER_MAX_CONNS 1024
#define QL_MAX_CIDS 8      /* connection IDs we issue/track 5.1 */
#define QL_MAX_VERSIONS 16 /* Version Negotiation list */

/* 21.3 — Anti-amplification limit: 3x received bytes before addr validation */
#define QL_AMPLIFICATION_FACTOR 3

/*
 * 8.1 — A Retry token carries:
 *   - the original client address (for anti-spoofing)
 *   - a timestamp (for anti-replay 8.1.4)
 * We store an opaque encrypted blob limited to 256 bytes.
 */
#define QL_TOKEN_MAX_LEN 256

typedef struct {
    uint8_t data[QL_TOKEN_MAX_LEN];
    size_t len;
    uint64_t issued_at_ms; /* wall-clock when we generated this token */
} ql_token_t;

/*
 * 21.3 — Anti-amplification: server MUST NOT send more than
 * QL_AMPLIFICATION_FACTOR × bytes_received until address is validated.
 */
typedef struct {
    bool validated;          /* true once address confirmed */
    uint64_t bytes_received; /* from unvalidated peer address */
    uint64_t bytes_sent;     /* to unvalidated peer address */
} ql_addr_valid_t;

/*
 * Transport ERR codes  20.1
 */
typedef enum {
    QL_ERR_NO_ERROR                  = 0x00,
    QL_ERR_INTERNAL_ERROR            = 0x01,
    QL_ERR_CONNECTION_REFUSED        = 0x02,
    QL_ERR_FLOW_CONTROL_ERROR        = 0x03,
    QL_ERR_STREAM_LIMIT_ERROR        = 0x04,
    QL_ERR_STREAM_STATE_ERROR        = 0x05,
    QL_ERR_FINAL_SIZE_ERROR          = 0x06,
    QL_ERR_FRAME_ENCODING_ERROR      = 0x07,
    QL_ERR_TRANSPORT_PARAMETER_ERROR = 0x08,
    QL_ERR_CONNECTION_ID_LIMIT_ERROR = 0x09,
    QL_ERR_PROTOCOL_VIOLATION        = 0x0A,
    QL_ERR_INVALID_TOKEN             = 0x0B,
    QL_ERR_APPLICATION_ERROR         = 0x0C,
    QL_ERR_CRYPTO_BUFFER_EXCEEDED    = 0x0D,
    QL_ERR_KEY_UPDATE_ERROR          = 0x0E,
    QL_ERR_AEAD_LIMIT_REACHED        = 0x0F,
    QL_ERR_NO_VIABLE_PATH            = 0x10,
    /*
     * 20.1 — TLS alert codes 6 RFC 9001.
     * CRYPTO_ERROR base: 0x0100 + TLS alert value.
     */
    QL_ERR_CRYPTO_ERROR_BASE = 0x0100,
} ql_transport_error_t;

typedef enum {
    QLITE_OK             = 0,
    QLITE_ERR_AGAIN      = -1,  /* would block — try again */
    QLITE_ERR_BUF        = -2,  /* destination buffer too small */
    QLITE_ERR_PROTO      = -3,  /* protocol violation */
    QLITE_ERR_CRYPTO     = -4,  /* AEAD authentication failure / TLS error */
    QLITE_ERR_STREAM     = -5,  /* invalid stream state transition */
    QLITE_ERR_FC         = -6,  /* flow-control limit exceeded */
    QLITE_ERR_ARGS       = -7,  /* invalid arguments */
    QLITE_ERR_NOMEM      = -8,  /* allocation failure */
    QLITE_ERR_CLOSED     = -9,  /* connection or stream already closed */
    QLITE_ERR_INTERNAL   = -10, /* internal / unexpected error */
    QLITE_ERR_WOULDBLOCK = -11, /* non-blocking socket would block */
} qlite_err_t;

/* Application-protocol error codes 20.2 — opaque 62-bit integer */
typedef uint64_t ql_app_error_t;

/* =========================================================================
 * PACKET NUMBER SPACES  12.3 / 12.5
 * ACK frames only acknowledge packets within the same space.
 * ========================================================================= */
typedef enum {
    QL_PN_SPACE_INITIAL   = 0,
    QL_PN_SPACE_HANDSHAKE = 1,
    QL_PN_SPACE_APP       = 2, /* 1-RTT / Application data */
    QL_PN_SPACE_COUNT     = 3,
} ql_pn_space_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html?#name-frame-types-and-formats
 */
typedef enum {
    /* 19.1  */ QL_FRAME_PADDING      = 0x00,
    /* 19.2  */ QL_FRAME_PING         = 0x01,
    /* 19.3  */ QL_FRAME_ACK          = 0x02, /* no ECN counts  */
    /* 19.3  */ QL_FRAME_ACK_ECN      = 0x03, /* with ECN counts */
    /* 19.4  */ QL_FRAME_RESET_STREAM = 0x04,
    /* 19.5  */ QL_FRAME_STOP_SENDING = 0x05,
    /* 19.6  */ QL_FRAME_CRYPTO       = 0x06,
    /* 19.7  */ QL_FRAME_NEW_TOKEN    = 0x07,
    /* 19.8 — STREAM flags OR'd into 0x08 */
    /* 19.8  */ QL_FRAME_STREAM               = 0x08, /* OFF=0,LEN=0,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_FIN           = 0x09, /* OFF=0,LEN=0,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_LEN           = 0x0A, /* OFF=0,LEN=1,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_LEN_FIN       = 0x0B, /* OFF=0,LEN=1,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_OFF           = 0x0C, /* OFF=1,LEN=0,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_FIN       = 0x0D, /* OFF=1,LEN=0,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_LEN       = 0x0E, /* OFF=1,LEN=1,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_LEN_FIN   = 0x0F, /* OFF=1,LEN=1,FIN=1 */
    /* 19.9  */ QL_FRAME_MAX_DATA             = 0x10,
    /* 19.10 */ QL_FRAME_MAX_STREAM_DATA      = 0x11,
    /* 19.11 */ QL_FRAME_MAX_STREAMS_BIDI     = 0x12,
    /* 19.11 */ QL_FRAME_MAX_STREAMS_UNI      = 0x13,
    /* 19.12 */ QL_FRAME_DATA_BLOCKED         = 0x14,
    /* 19.13 */ QL_FRAME_STREAM_DATA_BLOCKED  = 0x15,
    /* 19.14 */ QL_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
    /* 19.14 */ QL_FRAME_STREAMS_BLOCKED_UNI  = 0x17,
    /* 19.15 */ QL_FRAME_NEW_CONNECTION_ID    = 0x18,
    /* 19.16 */ QL_FRAME_RETIRE_CONNECTION_ID = 0x19,
    /* 19.17 */ QL_FRAME_PATH_CHALLENGE       = 0x1A,
    /* 19.18 */ QL_FRAME_PATH_RESPONSE        = 0x1B,
    /* 19.19 */ QL_FRAME_CONNECTION_CLOSE     = 0x1C, /* transport error */
    /* 19.19 */ QL_FRAME_CONNECTION_CLOSE_APP = 0x1D, /* app-layer error */
    /* 19.20 */ QL_FRAME_HANDSHAKE_DONE       = 0x1E,
} ql_frame_type_t;

/* 19.8 — STREAM frame bit-flags (within 0x08..0x0F) */
#define QL_STREAM_FLAG_FIN 0x01u
#define QL_STREAM_FLAG_LEN 0x02u
#define QL_STREAM_FLAG_OFF 0x04u

/* 18.2 — Transport parameter defaults */
#define QL_DEFAULT_ACK_DELAY_EXP 3 /* 2^3 = 8 µs units */
#define QL_DEFAULT_MAX_ACK_DELAY_MS 25
#define QL_DEFAULT_ACTIVE_CID_LIMIT 2
/*
 *      TRANSPORT PARAMETERS  7.4 / 18.2
 *      Exchanged inside the TLS handshake ClientHello / EncryptedExtensions.
 */

typedef enum {
    QL_TP_ORIGINAL_DST_CID                    = 0x00,
    QL_TP_MAX_IDLE_TIMEOUT                    = 0x01, /* varint, ms */
    QL_TP_STATELESS_RESET_TOKEN               = 0x02, /* 16 bytes */
    QL_TP_MAX_UDP_PAYLOAD_SIZE                = 0x03, /* varint, >= 1200 */
    QL_TP_INITIAL_MAX_DATA                    = 0x04,
    QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 0x05,
    QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
    QL_TP_INITIAL_MAX_STREAM_DATA_UNI         = 0x07,
    QL_TP_INITIAL_MAX_STREAMS_BIDI            = 0x08,
    QL_TP_INITIAL_MAX_STREAMS_UNI             = 0x09,
    QL_TP_ACK_DELAY_EXPONENT                  = 0x0A, /* default 3 */
    QL_TP_MAX_ACK_DELAY                       = 0x0B, /* varint, ms, default 25 */
    QL_TP_DISABLE_ACTIVE_MIGRATION            = 0x0C, /* empty presence = true */
    QL_TP_PREFERRED_ADDRESS                   = 0x0D, /* server only */
    QL_TP_ACTIVE_CONNECTION_ID_LIMIT          = 0x0E, /* varint, >= 2 */
    QL_TP_INITIAL_SOURCE_CID                  = 0x0F,
    QL_TP_RETRY_SOURCE_CID                    = 0x10,
} ql_tp_id_t;

/*
    A PADDING frame (type=0x00) has no semantic value.
    PADDING frames can be used to increase the size of a packet.
    Padding can be used to increase an Initial packet to the
    minimum required size or to provide protection against traffic
    analysis for protected packets
*/
typedef struct {
    size_t length; /* number of zero bytes emitted or consumed */
} ql_frame_padding_t;

/*
    Endpoints can use PING frames (type=0x01) to verify that their
    peers are still alive or to check reachability to the peer.
*/
typedef struct {
    uint8_t _dummy;
} ql_frame_ping_t;

/* ACK / ACK_ECN
    Receivers send ACK frames (types 0x02 and 0x03) to inform senders
    of packets they have received and processed. The ACK frame contains
    one or more ACK Ranges. ACK Ranges identify acknowledged packets.
    If the frame type is 0x03, ACK frames also contain the cumulative
    count of QUIC packets with associated ECN marks received on the
    connection up until this point. QUIC implementations MUST properly
    handle both types, and, if they have enabled ECN for packets they
    send, they SHOULD use the information in the ECN section to manage
    their congestion state.
*/
typedef struct {
    ql_pkt_num_t largest_acked;
    uint64_t ack_delay;       /* in 2^ack_delay_exponent µs units */
    uint64_t range_count;     /* additional ACK range pairs */
    uint64_t first_ack_range; /* acked packets below largest_acked */
    ql_ack_range_t ranges[QL_ACK_RANGE_MAX];
    /* 19.3.2 — ECN counts, present only in ACK_ECN frame */
    uint64_t ect0_count;
    uint64_t ect1_count;
    uint64_t ecn_ce_count;
    bool has_ecn;
} ql_frame_ack_t;

/*
    An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly
    terminate the sending part of a stream.
    After sending a RESET_STREAM, an endpoint ceases transmission
    and retransmission of STREAM frames on the identified stream.
    A receiver of RESET_STREAM can discard any data that it already
    received on that stream.
    An endpoint that receives a RESET_STREAM frame for a send-only
    stream MUST terminate the connection with error STREAM_STATE_ERROR.
*/
typedef struct {
    ql_stream_id_t stream_id;
    ql_app_error_t error_code;
    uint64_t final_size; /* byte offset of stream end */
} ql_frame_reset_stream_t;

/*
    An endpoint uses a STOP_SENDING frame (type=0x05) to communicate
    that incoming data is being discarded on receipt per application
    request. STOP_SENDING requests that a peer cease transmission on
    a stream.
    A STOP_SENDING frame can be sent for streams in the "Recv" or
    "Size Known" states; see Section 3.2. Receiving a STOP_SENDING
    frame for a locally initiated stream that has not yet been created
    MUST be treated as a connection error of type STREAM_STATE_ERROR.
    An endpoint that receives a STOP_SENDING frame for a receive-only
    stream MUST terminate the connection with error STREAM_STATE_ERROR.
*/
typedef struct {
    ql_stream_id_t stream_id;
    ql_app_error_t error_code;
} ql_frame_stop_sending_t;

/*
    A CRYPTO frame (type=0x06) is used to transmit cryptographic handshake
    messages. It can be sent in all packet types except 0-RTT. The CRYPTO
    frame offers the cryptographic protocol an in-order stream of bytes.
    CRYPTO frames are functionally identical to STREAM frames, except that
    they do not bear a stream identifier; they are not flow controlled;
    and they do not carry markers for optional offset, optional length,
    and the end of the stream.
*/
typedef struct {
    uint64_t offset;
    uint64_t length;
    const uint8_t *data; /* points into decode buffer — not owned */
} ql_frame_crypto_t;

/*
    A server sends a NEW_TOKEN frame (type=0x07) to provide the client
    with a token to send in the header of an Initial packet for a future
    connection.
*/
typedef struct {
    uint64_t token_length;
    const uint8_t *token; /* points into decode buffer — not owned */
} ql_frame_new_token_t;

/*
    STREAM frames implicitly create a stream and carry stream data.
    The Type field in the STREAM frame takes the form 0b00001XXX
    (or the set of values from 0x08 to 0x0f). The three low-order
    bits of the frame type determine the fields that are present in
    the frame:
        The OFF bit (0x04) in the frame type is set to indicate that
    there is an Offset field present. When set to 1, the Offset field
    is present. When set to 0, the Offset field is absent and the
    Stream Data starts at an offset of 0 (that is, the frame contains
    the first bytes of the stream, or the end of a stream that includes
    no data).
        The LEN bit (0x02) in the frame type is set to indicate that
    there is a Length field present. If this bit is set to 0, the
    Length field is absent and the Stream Data field extends to t
    he end of the packet. If this bit is set to 1, the Length field
    is present.
        The FIN bit (0x01) indicates that the frame
*/
typedef struct {
    ql_stream_id_t stream_id;
    uint64_t offset;     /* present only if has_offset; else 0 */
    uint64_t length;     /* present only if has_length */
    const uint8_t *data; /* points into decode buffer — not owned */
    bool has_offset;     /* OFF bit */
    bool has_length;     /* LEN bit */
    bool fin;            /* FIN bit */
} ql_frame_stream_t;

typedef struct {
    uint64_t maximum_data;
} ql_frame_max_data_t;

typedef struct {
    ql_stream_id_t stream_id;
    uint64_t maximum_stream_data;
} ql_frame_max_stream_data_t;

typedef struct {
    uint64_t maximum_streams;
} ql_frame_max_streams_t;

/*
    A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes
    to send data but is unable to do so due to connection-level flow control;
    see Section 4. DATA_BLOCKED frames can be used as input to tuning of
    flow control algorithms;
*/
typedef struct {
    uint64_t data_limit; /* connection-level limit we're blocked at */
} ql_frame_data_blocked_t;

/*
    A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it
    wishes to send data but is unable to do so due to stream-level flow
    control. This frame is analogous to DATA_BLOCKED
*/
typedef struct {
    ql_stream_id_t stream_id;
    uint64_t stream_data_limit;
} ql_frame_stream_data_blocked_t;

/*
    A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17)
    when it wishes to open a stream but is unable to do so due to the
    maximum stream limit set by its peer; A STREAMS_BLOCKED
    frame of type 0x16 is used to indicate reaching the bidirectional
    stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to
    indicate reaching the unidirectional stream limit.
*/
typedef struct {
    uint64_t stream_limit;
} ql_frame_streams_blocked_t;

/*
    An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide
    its peer with alternative connection IDs that can be used to break
    linkability when migrating connections;
*/
typedef struct {
    uint64_t sequence_num;
    uint64_t retire_prior_to;
    ql_cid_t cid;
    ql_reset_token_t stateless_reset_token;
} ql_frame_new_cid_t;

/*
    An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to
    indicate that it will no longer use a connection ID that was
    issued by its peer. This includes the connection ID provided
    during the handshake. Sending a RETIRE_CONNECTION_ID frame also
    serves as a request to the peer to send additional connection
    IDs for future use; New connection IDs can be
    delivered to a peer using the NEW_CONNECTION_ID frame
*/
typedef struct {
    uint64_t sequence_num;
} ql_frame_retire_cid_t;

/*
    Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check
    reachability to the peer and for path validation during
    connection migration.
*/
typedef struct {
    ql_path_data_t data; /* 8 random bytes */
} ql_frame_path_challenge_t;

/*
    A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE frame.
*/
typedef struct {
    ql_path_data_t data; /* verbatim echo of the PATH_CHALLENGE data */
} ql_frame_path_response_t;

/*
    An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d)
    to notify its peer that the connection is being closed. The
    CONNECTION_CLOSE frame with a type of 0x1c is used to signal
    errors at only the QUIC layer, or the absence of errors
    (with the NO_ERROR code). The CONNECTION_CLOSE frame with a
    type of 0x1d is used to signal an error with the application
    that uses QUIC.
*/
typedef struct {
    ql_transport_error_t error_code; /* transport close: 20.1 code */
    ql_app_error_t app_error_code;   /* app close: opaque error code */
    ql_frame_type_t frame_type;      /* causal frame type (0x1C only) */
    uint64_t reason_length;
    const uint8_t *reason_phrase; /* UTF-8, not null-terminated */
    bool is_app;                  /* true → 0x1D, false → 0x1C */
} ql_frame_conn_close_t;

/*
    The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal
    confirmation of the handshake to the client.
*/
typedef struct {
    uint8_t _dummy;
} ql_frame_handshake_done_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4-6
 */
typedef struct {
    ql_frame_type_t type;
    union {
        ql_frame_padding_t padding;
        ql_frame_ping_t ping;
        ql_frame_ack_t ack;
        ql_frame_reset_stream_t reset_stream;
        ql_frame_stop_sending_t stop_sending;
        ql_frame_crypto_t crypto;
        ql_frame_new_token_t new_token;
        ql_frame_stream_t stream;
        ql_frame_max_data_t max_data;
        ql_frame_max_stream_data_t max_stream_data;
        ql_frame_max_streams_t max_streams;
        ql_frame_data_blocked_t data_blocked;
        ql_frame_stream_data_blocked_t stream_data_blocked;
        ql_frame_streams_blocked_t streams_blocked;
        ql_frame_new_cid_t new_cid;
        ql_frame_retire_cid_t retire_cid;
        ql_frame_path_challenge_t path_challenge;
        ql_frame_path_response_t path_response;
        ql_frame_conn_close_t conn_close;
        ql_frame_handshake_done_t handshake_done;
    } u;
} ql_frame_t;

/*
 * One directional key set for a single encryption level.
 * Holds the AEAD key, the per-packet IV (nonce base), and the
 * header-protection key (hp).
 */
typedef struct {
    uint8_t key[QL_AEAD_KEY_MAX_LEN];
    uint8_t iv[QL_AEAD_IV_MAX_LEN];
    uint8_t hp[QL_HP_KEY_MAX_LEN];
    uint8_t key_len;
    uint8_t iv_len;
    uint8_t hp_len;
    bool is_set;
} ql_keys_t;

/* Read + write keys for one encryption level */
typedef struct {
    ql_keys_t read;  /* decryption */
    ql_keys_t write; /* encryption */
} ql_key_pair_t;

/*
 * Key update state — RFC 9001 6.
 * We keep both the current and next key phases so we can decrypt
 * packets that arrive using the new phase before we've fully rotated.
 */
typedef struct {
    ql_key_pair_t current;   /* keys for the active phase */
    ql_key_pair_t next;      /* keys derived ready for next phase */
    bool current_phase;      /* 0 or 1 — matches key_phase bit */
    bool update_pending;     /* we've triggered an update, not sent yet */
    bool peer_updated;       /* we saw the peer's key_phase flip */
    uint64_t update_sent_pn; /* first pkt-num sent with new key */

    /* Raw next-generation traffic secrets, stashed between prepare and
     * promote so promotion can chain be->pending[APP]'s bookkeeping
     * forward without needing a fourth HKDF pass (chunk 6.4). */
    uint8_t next_read_secret[QL_SECRET_MAX_LEN];
    size_t next_read_secret_len;
    uint8_t next_write_secret[QL_SECRET_MAX_LEN];
    size_t next_write_secret_len;
} ql_key_update_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html?#name-packet-formats
 */
typedef enum {
    QL_PKT_VERSION_NEGOTIATION = 0, /* 17.2.1 — special, no type bits */
    QL_PKT_INITIAL             = 1, /* 17.2.2 — long header, type 0x00 */
    QL_PKT_0RTT                = 2, /* 17.2.3 — long header, type 0x01 */
    QL_PKT_HANDSHAKE           = 3, /* 17.2.4 — long header, type 0x02 */
    QL_PKT_RETRY               = 4, /* 17.2.5 — long header, type 0x03 */
    QL_PKT_1RTT                = 5, /* 17.3.1 — short header */
} ql_pkt_type_t;

/* Long-header first-byte bit masks 17.2 */
#define QL_LONG_HDR_FORM 0x80u      /* bit 7 = 1 → long header */
#define QL_LONG_HDR_FIXED_BIT 0x40u /* MUST be 1 */
#define QL_LONG_HDR_TYPE_MASK 0x30u /* bits 4-5: long-header packet type */
#define QL_LONG_HDR_TYPE_SHIFT 4
#define QL_LONG_HDR_RESERVED_MASK 0x0Cu /* MUST be 0 after header protection */
#define QL_LONG_HDR_PKT_NUM_MASK 0x03u  /* encoded pkt-num length − 1 */

/* Short (1-RTT) header first-byte bit masks 17.3 */
#define QL_SHORT_HDR_FORM 0x00u          /* bit 7 = 0 → short header */
#define QL_SHORT_HDR_FIXED_BIT 0x40u     /* MUST be 1 */
#define QL_SHORT_HDR_SPIN_BIT 0x20u      /* 17.4 latency spin */
#define QL_SHORT_HDR_RESERVED_MASK 0x18u /* MUST be 0 after header protection */
#define QL_SHORT_HDR_KEY_PHASE 0x04u     /* key-update phase bit RFC 9001 5.4 */
#define QL_SHORT_HDR_PKT_NUM_MASK 0x03u  /* encoded pkt-num length − 1 */

/* Test first byte: long or short? */
#define QL_PKT_IS_LONG(first_byte) (((first_byte) & 0x80u) != 0)
#define QL_PKT_IS_SHORT(first_byte) (((first_byte) & 0x80u) == 0)

/* 17.1 — Maximum packet-number field length in bytes */
#define QL_PKT_NUM_MAX_ENCODED_LEN 4

/* Long header (Initial, 0-RTT, Handshake, Retry) 17.2 */
/*
    Long headers are used for packets that are sent prior to the
    establishment of 1-RTT keys. Once 1-RTT keys are available,
    a sender switches to sending packets using the short header
*/
typedef struct {
    ql_pkt_type_t pkt_type;
    uint8_t first_byte;
    uint32_t version;
    ql_cid_t dst_cid;
    ql_cid_t src_cid;
    /* Initial only 17.2.2 */
    uint8_t token[QL_TOKEN_MAX_LEN];
    size_t token_len;
    /* Retry only 17.2.5 — AES-128-GCM tag, 16 bytes */
    uint8_t retry_integrity_tag[QL_AEAD_TAG_LEN];
    bool is_retry;
    /* Present in Initial, 0-RTT, Handshake (not Retry, not VN) */
    uint64_t length;      /* payload length varint */
    ql_pkt_num_t pkt_num; /* decoded full packet number */
    uint8_t pkt_num_len;  /* encoded width: 1–4 bytes */
} ql_long_hdr_t;

/* Short (1-RTT) header 17.3.1 */
typedef struct {
    uint8_t first_byte;
    ql_cid_t dst_cid;
    ql_pkt_num_t pkt_num;
    uint8_t pkt_num_len;
    bool spin_bit;  /* 17.4 */
    bool key_phase; /* RFC 9001 5.4 */
} ql_short_hdr_t;

/* Unified view after parsing */
typedef struct {
    bool is_long;
    union {
        ql_long_hdr_t lhdr;
        ql_short_hdr_t shdr;
    } h;
    /* Decrypted payload slice within the datagram buffer (AEAD tag removed) */
    const uint8_t *payload;
    size_t payload_len;
} ql_pkt_hdr_t;

/* 17.2.1 — Version Negotiation Packet */
typedef struct {
    ql_cid_t dst_cid;
    ql_cid_t src_cid;
    uint32_t versions[QL_MAX_VERSIONS];
    int version_count;
} ql_ver_neg_pkt_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-servers-preferred-address
 */
/* 9.6.1 / 18.2 — server's preferred address */
typedef struct {
    uint8_t ipv4[4];
    uint16_t ipv4_port;
    uint8_t ipv6[16];
    uint16_t ipv6_port;
    ql_cid_t cid;
    ql_reset_token_t reset_token;
} ql_preferred_addr_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
 */
/* Full set of negotiated transport parameters for one peer */
typedef struct {
    uint64_t max_idle_timeout_ms;  /* 0 = disabled */
    uint64_t max_udp_payload_size; /* default 65527 */
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t ack_delay_exponent; /* default 3 */
    uint64_t max_ack_delay_ms;   /* default 25 */
    uint64_t active_cid_limit;   /* >= 2 */
    bool disable_active_migration;

    ql_cid_t original_dst_cid;
    ql_cid_t initial_src_cid;
    ql_cid_t retry_src_cid;
    bool has_retry_src_cid;

    bool has_stateless_reset_token;
    ql_reset_token_t stateless_reset_token;

    bool has_preferred_addr;
    ql_preferred_addr_t preferred_addr;
} ql_transport_params_t;

/**
 * @link: https://datatracker.ietf.org/doc/html/rfc9000#name-stream-types-and-identifier
 */
typedef enum {
    QL_STREAM_TYPE_CLIENT_BIDI = 0x00, /* client-initiated bidirectional  2.1 */
    QL_STREAM_TYPE_SERVER_BIDI = 0x01, /* server-initiated bidirectional  2.1 */
    QL_STREAM_TYPE_CLIENT_UNI  = 0x02, /* client-initiated unidirectional 2.1 */
    QL_STREAM_TYPE_SERVER_UNI  = 0x03, /* server-initiated unidirectional 2.1 */
} ql_stream_type_t;

/* Full ACK state per packet-number space */
typedef struct {
    ql_pkt_num_t largest_recvd;      /* 19.3 Largest Acknowledged field */
    ql_pkt_num_t largest_acked_sent; /* last largest we put in an ACK frame */
    uint64_t ack_delay_us;           /* our local ACK delay to report */
    ql_ack_range_t ranges[QL_ACK_RANGE_MAX];
    int range_count;
    int ack_eliciting_recvd;       /* count since last ACK sent */
    bool needs_ack;                /* true when we must send ACK soon */
    uint64_t ack_send_deadline_ms; /* when we MUST send the ACK by */
    /* 19.3.2 — ECN counts */
    uint64_t ecn_ect0;
    uint64_t ecn_ect1;
    uint64_t ecn_ce;
    bool ecn_enabled;
} ql_ack_state_t;

/* 3.1 — Sending stream states */
/**
 * @link: https://datatracker.ietf.org/doc/html/rfc9000#name-stream-states
 */
typedef enum {
    QL_TX_STREAM_READY      = 0, /* created, data buffered, not yet sent */
    QL_TX_STREAM_SEND       = 1, /* STREAM frames being sent */
    QL_TX_STREAM_DATA_SENT  = 2, /* FIN sent, awaiting ACK */
    QL_TX_STREAM_DATA_RCVD  = 3, /* FIN ACKed — terminal */
    QL_TX_STREAM_RESET_SENT = 4, /* RESET_STREAM sent */
    QL_TX_STREAM_RESET_RCVD = 5, /* RESET_STREAM ACKed — terminal */
} ql_tx_stream_state_t;

/* 3.2 — Receiving stream states */
typedef enum {
    QL_RX_STREAM_RECV       = 0, /* receiving data */
    QL_RX_STREAM_SIZE_KNOWN = 1, /* FIN received, final size known */
    QL_RX_STREAM_DATA_RCVD  = 2, /* all data received, not yet consumed */
    QL_RX_STREAM_DATA_READ  = 3, /* all data consumed by app — terminal */
    QL_RX_STREAM_RESET_RCVD = 4, /* RESET_STREAM received */
    QL_RX_STREAM_RESET_READ = 5, /* reset consumed by app — terminal */
} ql_rx_stream_state_t;

/* Per-stream flow control 4.1 */
typedef struct {
    uint64_t send_limit;    /* peer's advertised MAX_STREAM_DATA */
    uint64_t send_offset;   /* bytes we have sent so far */
    uint64_t recv_limit;    /* our MAX_STREAM_DATA advertised to peer */
    uint64_t recv_consumed; /* bytes consumed (read) by the application */
    uint64_t recv_offset;   /* highest byte offset received */
    uint64_t final_size;    /* set when FIN or RESET_STREAM seen 4.5 */
    bool final_size_known;
    /* Data-blocked signalling 19.13 */
    bool send_blocked;   /* we are blocked by send_limit */
    uint64_t blocked_at; /* limit value we sent DATA_BLOCKED at */
} ql_stream_fc_t;

/* Connection-level flow control 4.1 */
typedef struct {
    uint64_t send_limit;    /* peer's MAX_DATA */
    uint64_t send_offset;   /* total bytes sent across all streams */
    uint64_t recv_limit;    /* our MAX_DATA advertised to peer */
    uint64_t recv_consumed; /* total bytes consumed across all streams */
    /* Data-blocked signalling 19.12 */
    bool send_blocked;
    uint64_t blocked_at;
} ql_conn_fc_t;

/* =========================================================================
 * CRYPTO (TLS) REORDER BUFFER  7.5
 * CRYPTO frames may arrive out of order; we must reassemble in order
 * before feeding into TLS.  RFC mandates >= 4096 bytes per level.
 * ========================================================================= */

typedef struct {
    uint8_t buf[QL_CRYPTO_BUF_SIZE];
    uint64_t rx_offset; /* next expected byte from peer */
    uint64_t tx_offset; /* next byte offset to send to peer */
    uint64_t tx_sent_offset; /* of those, how many have gone out in CRYPTO frames */
    uint64_t tx_acked_offset; /* of those, how many the peer has confirmed (chunk 5.1) */
    bool has_data;      /* non-empty */
} ql_crypto_buf_t;

/*
 * Inbound CRYPTO-frame reassembly state (chunk 3.3). Kept separate from
 * ql_crypto_buf_t above: that struct's `buf`/`tx_offset` are already used
 * by ql_conn_tick() as TX-side staging for outbound handshake bytes, so
 * reusing it here for RX would let the two directions clobber each other.
 */
typedef struct {
    uint8_t buf[QL_CRYPTO_BUF_SIZE];            /* reassembled bytes, indexed by absolute stream offset */
    uint8_t received[QL_CRYPTO_BUF_SIZE / 8];   /* bitmap: bit set if buf[offset] has been written */
    uint64_t rx_offset;                          /* next contiguous offset, already delivered to TLS */
    uint64_t highest_offset;                     /* highest (offset+len) seen so far, for the flush scan bound */
} ql_crypto_rx_t;

typedef struct ql_stream {
    ql_stream_id_t id;
    ql_stream_type_t type;
    ql_tx_stream_state_t tx_state;
    ql_rx_stream_state_t rx_state;

    /* Flow control */
    ql_stream_fc_t fc;

    /* Send-side ring buffer */
    uint8_t tx_buf[QL_STREAM_BUF_SIZE];
    uint64_t tx_head;         /* next write position (app → buffer) */
    uint64_t tx_tail;         /* next send position (buffer → wire) */
    uint64_t tx_acked_offset; /* highest ACKed send offset */

    /* Receive-side ring buffer */
    uint8_t rx_buf[QL_STREAM_BUF_SIZE];
    uint64_t rx_head; /* next app-read position */
    uint64_t rx_tail; /* next write by receive path */
    uint8_t rx_received[QL_STREAM_BUF_SIZE / 8]; /* out-of-order bitmap, indexed mod buffer size (4.3.2) */
    uint64_t rx_highest_offset;                  /* highest (offset+len) seen so far */

    /* Error codes */
    ql_app_error_t reset_error_code; /* RESET_STREAM / STOP_SENDING code */

    /* Priority hint for scheduling (2.3 — application-defined) */
    uint32_t priority;

    /* Intrusive singly-linked list within ql_conn_t */
    struct ql_stream *next;
} ql_stream_t;

/* =========================================================================
 *     ENCRYPTION LEVELS  RFC 9001 4
 *     Controls which CRYPTO-frame data belongs to which TLS flight,
 *     and which AEAD keys are used to protect packets.
 * ========================================================================= */
typedef enum {
    QL_ENC_LEVEL_INITIAL    = 0, /* AEAD_AES_128_GCM, fixed salt 5.2 RFC9001 */
    QL_ENC_LEVEL_EARLY_DATA = 1, /* 0-RTT keys (client-only write) */
    QL_ENC_LEVEL_HANDSHAKE  = 2, /* Handshake keys */
    QL_ENC_LEVEL_APP        = 3, /* 1-RTT keys */
    QL_ENC_LEVEL_COUNT      = 4,
} ql_enc_level_t;

typedef struct ql_conn ql_conn_t; /* forward declaration */

/*
 * Feed inbound CRYPTO-frame bytes into the TLS engine at the given level.
 * Returns 0 on success, <0 on fatal TLS error.
 */
typedef int (*ql_tls_provide_data_fn)(void *tls_ctx, ql_enc_level_t level, const uint8_t *data,
                                      size_t len);

/*
 * Pull outbound CRYPTO bytes from the TLS engine for the given level.
 * Writes into buf (capacity cap).  Returns bytes written, 0 if none, <0 error.
 */
typedef int (*ql_tls_get_data_fn)(void *tls_ctx, ql_enc_level_t level, uint8_t *buf, size_t cap);

/*
 * Called when TLS signals new read/write keys are available at a level.
 * Implementation should derive AEAD + HP keys and fill *keys_out.
 */
typedef int (*ql_tls_set_keys_fn)(void *tls_ctx, ql_enc_level_t level, ql_key_pair_t *keys_out);

/* Returns true once TLS handshake is complete (server has sent Finished). */
typedef bool (*ql_tls_is_done_fn)(void *tls_ctx);

/* Returns the negotiated ALPN string, or NULL. */
typedef const char *(*ql_tls_get_alpn_fn)(void *tls_ctx);

/* Push our encoded QUIC transport parameters into the TLS extension 7.4. */
typedef int (*ql_tls_set_tp_fn)(void *tls_ctx, const uint8_t *tp_buf, size_t tp_len);

/* Pull the peer's encoded transport parameters from the TLS extension 7.4. */
typedef int (*ql_tls_get_peer_tp_fn)(void *tls_ctx, uint8_t *tp_buf, size_t cap);

/* All TLS callbacks plus the opaque context pointer */
typedef struct {
    void *tls_ctx;
    ql_tls_provide_data_fn provide_data;
    ql_tls_get_data_fn get_data;
    ql_tls_set_keys_fn set_keys;
    ql_tls_is_done_fn is_done;
    ql_tls_get_alpn_fn get_alpn;
    ql_tls_set_tp_fn set_tp;
    ql_tls_get_peer_tp_fn get_peer_tp;
} ql_tls_t;

typedef enum {
    QL_CONN_IDLE      = 0,
    QL_CONN_INITIAL   = 1, /* Initial packets exchanged */
    QL_CONN_HANDSHAKE = 2, /* TLS Handshake in progress */
    QL_CONN_CONNECTED = 3, /* 1-RTT keys installed, handshake confirmed */
    QL_CONN_CLOSING   = 4, /* CONNECTION_CLOSE sent, entering drain 10.2.1 */
    QL_CONN_DRAINING  = 5, /* CONNECTION_CLOSE received 10.2.2 */
    QL_CONN_CLOSED    = 6, /* terminal */
} ql_conn_state_t;

typedef enum {
    QL_ROLE_CLIENT = 0,
    QL_ROLE_SERVER = 1,
} ql_role_t;

typedef enum {
    QL_TIMER_NONE           = 0,
    QL_TIMER_IDLE           = 1, /* 10.1 */
    QL_TIMER_PTO            = 2, /* RFC 9002 6.2 */
    QL_TIMER_DRAIN          = 3, /* 10.2.2 */
    QL_TIMER_ACK_DELAY      = 4, /* 13.2.1 */
    QL_TIMER_PATH_CHALLENGE = 5, /* 8.2.4 */
} ql_timer_type_t;

typedef struct {
    ql_timer_type_t type;
    uint64_t deadline_ms; /* 0 = not armed */
    bool armed;
} ql_timer_t;

typedef enum {
    QL_PATH_UNKNOWN   = 0,
    QL_PATH_PROBING   = 1, /* PATH_CHALLENGE sent, awaiting response */
    QL_PATH_VALIDATED = 2, /* PATH_RESPONSE received */
    QL_PATH_FAILED    = 3, /* validation timed out 8.2.4 */
} ql_path_state_t;

typedef struct {
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    ql_path_state_t state;
    ql_path_data_t challenge_data; /* random 8 bytes we sent */
    uint64_t challenge_sent_at_ms;
    uint64_t mtu; /* current path MTU */
    ql_timer_t challenge_timer;
} ql_path_t;

typedef void (*ql_on_connected_fn)(ql_conn_t *conn, void *user);
typedef void (*ql_on_stream_open_fn)(ql_conn_t *conn, ql_stream_t *stream, void *user);
typedef void (*ql_on_data_fn)(ql_conn_t *conn, ql_stream_t *stream, void *user);
typedef void (*ql_on_close_fn)(ql_conn_t *conn, ql_transport_error_t err, void *user);
typedef void (*ql_on_migrate_fn)(ql_conn_t *conn, const ql_path_t *new_path, void *user);

typedef struct {
    ql_transport_params_t local_params; /* what we advertise to peer */
    ql_tls_t tls;                       /* TLS callback bundle */

    /* Event callbacks */
    ql_on_connected_fn on_connected;
    ql_on_stream_open_fn on_stream_open;
    ql_on_data_fn on_data;
    ql_on_close_fn on_close;
    ql_on_migrate_fn on_migrate;
    void *user;

    /* Tuning */
    uint64_t idle_timeout_ms;        /* 0 = use peer's value */
    bool enable_spin_bit;            /* 17.4 */
    bool enable_migration;           /* 9 */
    bool require_address_validation; /* server: require Retry 8.1 */
    bool enable_0rtt;                /* allow 0-RTT data */
} ql_config_t;

/* One row: either a local CID we issued, or a remote CID we received */
typedef struct {
    ql_cid_t cid;
    uint64_t sequence_num;    /* 19.15 */
    uint64_t retire_prior_to; /* 19.15 */
    ql_reset_token_t reset_token;
    bool is_active;
    bool is_retired;
} ql_cid_entry_t;

/* =========================================================================
 *      OUTBOUND DATAGRAM QUEUE  (coalescing + send queue)
 *      12.2 allows multiple QUIC packets in one UDP datagram.
 * ========================================================================= */

/*
 * One assembled, ready-to-send datagram.
 * Multiple QUIC packets can be coalesced into a single UDP payload
 * up to the path MTU.
 */
typedef struct {
    uint8_t data[QL_PATH_MTU_ETHERNET + 64]; /* generous upper bound */
    size_t len;
    struct sockaddr_storage dest;
    socklen_t dest_len;
} ql_datagram_t;

/* Ring of outbound datagrams waiting for the UDP socket */
typedef struct {
    ql_datagram_t datagrams[QL_MAX_COALESCE_PKTS];
    int head;
    int tail;
    int count;
} ql_send_queue_t;

/* Bitmask of retransmittable frame types for ql_sent_pkt_t.frame_flags */
#define QL_RETX_FLAG_CRYPTO (1u << 0)
#define QL_RETX_FLAG_STREAM (1u << 1)
#define QL_RETX_FLAG_RESET_STREAM (1u << 2)
#define QL_RETX_FLAG_STOP_SENDING (1u << 3)
#define QL_RETX_FLAG_MAX_DATA (1u << 4)
#define QL_RETX_FLAG_MAX_STREAM_DATA (1u << 5)
#define QL_RETX_FLAG_MAX_STREAMS (1u << 6)
#define QL_RETX_FLAG_NEW_CID (1u << 7)
#define QL_RETX_FLAG_RETIRE_CID (1u << 8)
#define QL_RETX_FLAG_PATH_CHALLENGE (1u << 9)
#define QL_RETX_FLAG_HANDSHAKE_DONE (1u << 10)
#define QL_RETX_FLAG_NEW_TOKEN (1u << 11)
#define QL_RETX_FLAG_PING (1u << 12)
#define QL_RETX_FLAG_DATA_BLOCKED (1u << 13)

typedef struct {
    ql_pkt_num_t pkt_num;
    ql_pn_space_t pn_space;
    uint64_t sent_at_ms;    /* wall-clock send time */
    size_t in_flight_bytes; /* bytes counted toward congestion window */
    bool ack_eliciting;     /* false → no ACK needed 13.2 */
    bool in_flight;         /* counted in cc.bytes_in_flight */
    bool is_lost;
    bool is_acked;
    uint32_t frame_flags; /* QL_RETX_FLAG_* bitmask */

    /* Retransmission metadata (chunk 5.2.3). This implementation sends at
     * most one CRYPTO or STREAM frame per packet, so one offset/length
     * pair unambiguously identifies exactly what needs resending. */
    ql_enc_level_t crypto_level; /* valid iff frame_flags & QL_RETX_FLAG_CRYPTO */
    uint64_t crypto_offset;
    size_t crypto_len;
    ql_stream_id_t stream_id; /* valid iff frame_flags & (QL_RETX_FLAG_STREAM|QL_RETX_FLAG_RESET_STREAM) */
    uint64_t stream_offset;
    size_t stream_len;
    bool stream_fin;
} ql_sent_pkt_t;

/**
 * CONGESTION CONTROL STATE  RFC 9002 7
 * NewReno by default; CUBIC can replace it.
 */
typedef enum {
    QL_CC_SLOW_START     = 0,
    QL_CC_CONGESTION_AVD = 1,
    QL_CC_RECOVERY       = 2,
} ql_cc_state_t;

typedef struct {
    ql_cc_state_t state;
    uint64_t cwnd;              /* congestion window, bytes */
    uint64_t ssthresh;          /* slow-start threshold, bytes */
    uint64_t bytes_in_flight;   /* unacked in-flight bytes */
    uint64_t recovery_start_pn; /* pkt-num when recovery began */

    /* RTT estimates RFC 9002 5 */
    uint64_t latest_rtt_us;
    uint64_t smoothed_rtt_us; /* SRTT */
    uint64_t rtt_var_us;      /* RTTVAR */
    uint64_t min_rtt_us;
    uint64_t first_rtt_sample_at_ms;
    bool rtt_sample_taken;

    /* PTO (Probe Timeout) timer RFC 9002 6.2 */
    uint64_t pto_deadline_ms; /* 0 = not armed */
    int pto_count;

    /* Loss detection RFC 9002 6.1 */
    uint64_t loss_time[QL_PN_SPACE_COUNT]; /* earliest loss-time per space */
    uint64_t time_of_last_sent_ack_eliciting_pkt[QL_PN_SPACE_COUNT];

    /* ECN counters RFC 9002 9.3 */
    uint64_t peer_ecn_ce_count; /* last CE count seen in peer's ACK */
} ql_cc_t;

struct ql_conn {
    ql_conn_state_t state;
    ql_role_t role;
    ql_config_t cfg;

    /* ---- Connection IDs 5.1 ---- */
    ql_cid_entry_t local_cids[QL_MAX_CIDS];
    int local_cid_count;
    ql_cid_entry_t remote_cids[QL_MAX_CIDS];
    int remote_cid_count;
    uint64_t next_cid_seq;         /* next sequence number to issue */
    uint64_t next_retire_prior_to; /* 19.15 */

    /* Active CIDs for current exchange */
    ql_cid_t local_cid;  /* we tell peer to address us with this */
    ql_cid_t remote_cid; /* we address peer with this */

    /* ---- Transport parameters ---- */
    ql_transport_params_t local_tp;
    ql_transport_params_t remote_tp;
    bool remote_tp_rcvd;

    /* ---- Packet number spaces 12.3 ---- */
    ql_pkt_num_t next_pn[QL_PN_SPACE_COUNT];       /* next to send */
    ql_pkt_num_t largest_recvd[QL_PN_SPACE_COUNT]; /* from peer */
    ql_ack_state_t ack[QL_PN_SPACE_COUNT];

    /* ---- Crypto / TLS keys ---- */
    ql_key_pair_t keys[QL_ENC_LEVEL_COUNT];
    ql_key_update_t key_update; /* RFC 9001 6 */

    /* ---- TLS engine ---- */
    ql_tls_t tls;
    bool handshake_complete;  /* TLS done, 1-RTT keys installed */
    bool handshake_confirmed; /* server: HANDSHAKE_DONE sent 4.1.2 RFC9001 */

    /* ---- CRYPTO frame reassembly buffers 7.5 ---- */
    ql_crypto_buf_t crypto[QL_ENC_LEVEL_COUNT];    /* TX-side staging, drained by ql_conn_tick() */
    ql_crypto_rx_t crypto_rx[QL_ENC_LEVEL_COUNT];  /* RX-side reassembly, chunk 3.3 */

    /* ---- Address / Retry token 8.1 ---- */
    ql_token_t token; /* outgoing: token from server's Retry / NEW_TOKEN */

    /* ---- Address validation 8 / 21.3 ---- */
    ql_addr_valid_t addr_valid;

    /* ---- Paths 9 ---- */
    ql_path_t active_path;
    ql_path_t probing_path;
    bool migration_in_progress;

    /* ---- Network socket ---- */
    int fd; /* non-blocking UDP socket */

    /* ---- Streams 2 ---- */
    ql_stream_t *stream_list;   /* singly-linked list of all open streams */
    uint64_t next_stream_id[4]; /* per QL_STREAM_TYPE_* */
    uint64_t max_streams_bidi;  /* from peer's transport params */
    uint64_t max_streams_uni;
    uint64_t open_streams_bidi;
    uint64_t open_streams_uni;

    /* ---- Connection-level flow control 4 ---- */
    ql_conn_fc_t fc;

    /* ---- Congestion control / loss detection RFC 9002 ---- */
    ql_cc_t cc;
    ql_sent_pkt_t sent_pkts[QL_SENT_PKT_MAX];
    int sent_pkt_count;
    /* Pointer to oldest unacked entry; wraps modulo QL_SENT_PKT_MAX */
    int sent_pkt_head;
    int sent_pkt_tail;

    /* ---- Timers ---- */
    ql_timer_t timer_idle;                   /* 10.1 */
    ql_timer_t timer_drain;                  /* 10.2.2 */
    ql_timer_t timer_ack[QL_PN_SPACE_COUNT]; /* 13.2.1 — per space */

    /* ---- Close state 10.2 ---- */
    bool closing;
    ql_transport_error_t close_error;
    ql_app_error_t close_app_error;
    ql_frame_type_t close_frame_type;
    uint8_t close_reason[256];
    size_t close_reason_len;
    /* Buffer the last CONNECTION_CLOSE we sent, to echo it 10.2.1 */
    uint8_t close_pkt[QL_PATH_MTU_DEFAULT];
    size_t close_pkt_len;

    /* ---- Stateless reset 10.3 ---- */
    ql_reset_token_t local_reset_token;

    /* ---- Spin bit 17.4 ---- */
    bool spin_bit;

    /* ---- Outbound datagram queue ---- */
    ql_send_queue_t send_queue;

    /* ---- Stats / diagnostics ---- */
    uint64_t bytes_sent_total;
    uint64_t bytes_received_total;
    uint64_t pkts_sent;
    uint64_t pkts_received;
    uint64_t pkts_lost;

    /* ---- Opaque user pointer ---- */
    void *user;
};

/* One outgoing-handshake-data buffer per encryption level. OpenSSL's
 * add_handshake_data callback PUSHES bytes to us; ql_tls_get_data DRAINS
 * them. Growable because flight sizes vary (client Certificate flights
 * can be several KB). */
typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
    size_t read_off; /* how much ql_tls_get_data has already drained */
} ql_tls_outbuf_t;

typedef struct {
    SSL *ssl;
    ql_role_t role;

    ql_tls_outbuf_t out[QL_ENC_LEVEL_COUNT];

    /* Most recent secrets handed to us per level, staged here until
     * ql_tls_install_keys is called and consumes them. Separate read/write
     * storage: quictls delivers both directions in ONE callback at the
     * Handshake and Application levels, so a shared buffer would clobber
     * one direction with the other. */
    struct {
        uint8_t read_secret[QL_SECRET_MAX_LEN];
        size_t read_secret_len;
        uint8_t write_secret[QL_SECRET_MAX_LEN];
        size_t write_secret_len;
        uint32_t cipher_id; /* SSL_CIPHER id, tells us AEAD + hash */
        bool read_pending;
        bool write_pending;
    } pending[QL_ENC_LEVEL_COUNT];

    /* Encoded transport parameters we're asked to send, buffered until
     * OpenSSL pulls them during the handshake. */
    uint8_t local_tp[1024];
    size_t local_tp_len;

    ql_key_pair_t initial_keys; /* derived at init time from client DCID (RFC 9001 5.2) */
} ql_tls_backend_t;

/* -------------------------------------------------------------------------
 * OSSL_ENCRYPTION_LEVEL <-> ql_enc_level_t
 * quictls defines its own enum with the same four values in the same
 * handshake order, but we translate explicitly rather than assume the
 * integer values line up across library versions.
 * ------------------------------------------------------------------------- */
static ql_enc_level_t map_from_ossl(OSSL_ENCRYPTION_LEVEL level) {
    switch (level) {
        case ssl_encryption_initial:
            return QL_ENC_LEVEL_INITIAL;
        case ssl_encryption_early_data:
            return QL_ENC_LEVEL_EARLY_DATA;
        case ssl_encryption_handshake:
            return QL_ENC_LEVEL_HANDSHAKE;
        default:
            return QL_ENC_LEVEL_APP;
    }
}

static OSSL_ENCRYPTION_LEVEL map_to_ossl(ql_enc_level_t level) {
    switch (level) {
        case QL_ENC_LEVEL_INITIAL:
            return ssl_encryption_initial;
        case QL_ENC_LEVEL_EARLY_DATA:
            return ssl_encryption_early_data;
        case QL_ENC_LEVEL_HANDSHAKE:
            return ssl_encryption_handshake;
        default:
            return ssl_encryption_application;
    }
}

/* forward decls: these are defined near the bottom of the file (~line 2663),
 * but QL_QUIC_METHOD's initializer needs them declared first. */
static int cb_set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                     const uint8_t *read_secret, const uint8_t *write_secret,
                                     size_t secret_len);
static int cb_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const uint8_t *data,
                                 size_t len);
static int cb_flush_flight(SSL *ssl);
static int cb_send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

static const SSL_QUIC_METHOD QL_QUIC_METHOD = {
    cb_set_encryption_secrets,
    cb_add_handshake_data,
    cb_flush_flight,
    cb_send_alert,
};

/**
 * PUBLIC API
 */
int ql_varint_encoded_len(ql_varint_t val) {
    if (val <= 63) return 1;
    if (val <= 16383) return 2;
    if (val <= 1073741823ULL) return 4;
    if (val <= 4611686018427387903ULL) return 8;
    return -1; /* invalid QUIC varint */
} /* returns 1/2/4/8 */
/*
    we use the first two MSB to represent the length of the integer
    2MSB	Length	Usable Bits	Range
    00	       1	 6	    0-63
    01	       2	 14	    0-16383
    10	       4	 30	    0-1073741823
    11	       8	 62	    0-4611686018427387903
*/
int ql_varint_encode(uint8_t *buf, size_t cap, ql_varint_t val) {
    int len = ql_varint_encoded_len(val);

    if (cap < (size_t)len) {
        return -1;
    }
    switch (len) {
        case 1:
            buf[0] = (uint8_t)val;
            break;

        case 2:
            buf[0] = 0x40 | ((val >> 8) & 0x3F);
            buf[1] = (uint8_t)(val & 0xFF);
            break;

        case 4:
            buf[0] = 0x80 | ((val >> 24) & 0x3F);
            for (int i = 1; i < 4; i++) {
                buf[i] = (uint8_t)((val >> (24 - 8 * i)) & 0xFF);
            }
            break;

        case 8:
            buf[0] = 0xC0 | ((val >> 56) & 0x3F);
            for (int i = 1; i < 8; i++) {
                buf[i] = (uint8_t)((val >> (56 - 8 * i)) & 0xFF);
            }
            break;
        default:
            return -1;
            break;
    }

    return len;
}
int ql_varint_decode(const uint8_t *buf, size_t len, ql_varint_t *out) {
    if (!buf || !out || len == 0) {
        return -1;
    }

    uint8_t first  = buf[0];
    uint8_t prefix = first >> 6;
    size_t vlen    = 1u << prefix;

    if (len < vlen) {
        return -1;
    }

    ql_varint_t v = first & 0x3F;

    for (size_t i = 1; i < vlen; i++) {
        v = (v << 8) | buf[i];
    }

    *out = v;
    return (int)vlen;
}

/**
 * Helpers
 */
/* Helper: write a varint-valued TP field */
static int tp_write_varint(uint8_t *buf, size_t *pos, size_t cap, ql_tp_id_t id, uint64_t val) {
    int id_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)id);
    if (id_n < 0) {
        return id_n;
    }
    *pos += (size_t)id_n;

    /* Compute value encoding to know length */
    uint8_t tmp[8];
    int val_n = ql_varint_encode(tmp, sizeof(tmp), val);
    if (val_n < 0) {
        return val_n;
    }

    int len_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)val_n);
    if (len_n < 0) {
        return len_n;
    }
    *pos += (size_t)len_n;

    if (*pos + (size_t)val_n > cap) {
        return QLITE_ERR_BUF;
    }
    memcpy(buf + *pos, tmp, (size_t)val_n);
    *pos += (size_t)val_n;
    return 0;
}

/* Helper: write a raw-bytes TP field */
static int tp_write_bytes(uint8_t *buf, size_t *pos, size_t cap, ql_tp_id_t id, const uint8_t *data,
                          size_t data_len) {
    int id_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)id);
    if (id_n < 0) {
        return id_n;
    }
    *pos += (size_t)id_n;

    int len_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)data_len);
    if (len_n < 0) {
        return len_n;
    }
    *pos += (size_t)len_n;

    if (*pos + data_len > cap) {
        return QLITE_ERR_BUF;
    }
    memcpy(buf + *pos, data, data_len);
    *pos += data_len;
    return 0;
}

/* Helper: write a CID-valued TP */
static int tp_write_cid(uint8_t *buf, size_t *pos, size_t cap, ql_tp_id_t id, const ql_cid_t *cid) {
    return tp_write_bytes(buf, pos, cap, id, cid->data, cid->len);
}

/*
 * ql_now_ms — monotonic clock in milliseconds.
 * Uses CLOCK_MONOTONIC to avoid wall-clock jumps.
 */
uint64_t ql_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

// /* Write n bytes of val into buf in big-endian order. */
static void ql__write_be(uint8_t *buf, uint64_t val, int n) {
    for (int i = n - 1; i >= 0; i--) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/* Bounds-checked varint read from buf[pos..len], advance pos. */
static int ql__read_varint(const uint8_t *buf, size_t *pos, size_t len, ql_varint_t *out) {
    if (*pos >= len) {
        return QLITE_ERR_BUF;
    }
    int n = ql_varint_decode(buf + *pos, len - *pos, out);
    if (n < 0) {
        return n;
    }
    *pos += (size_t)n;
    return n;
}

int ql_pkt_num_encode(uint8_t *buf, ql_pkt_num_t full_pn, ql_pkt_num_t largest_acked) {
    uint64_t n_unacked;
    int pn_len;

    if (full_pn <= largest_acked) {
        n_unacked = 1;
    } else {
        n_unacked = full_pn - largest_acked;
    }

    if (n_unacked < (1ULL << 7)) {
        pn_len = 1;
    } else if (n_unacked < (1ULL << 15)) {
        pn_len = 2;
    } else if (n_unacked < (1ULL << 23)) {
        pn_len = 3;
        // else pn_len = 4;
    } else if (n_unacked < (1ULL << 31)) {
        pn_len = 4;
    } else {
        return QLITE_ERR_INTERNAL;
    }

    for (int i = 0; i < pn_len; i++) {
        buf[pn_len - 1 - i] = (uint8_t)(full_pn >> (i * 8));
    }

    return pn_len;
}

ql_pkt_num_t ql_pkt_num_decode(uint64_t truncated_pn, int pn_nbits, ql_pkt_num_t largest_pn) {
    /* Next packet number we expect. */
    ql_pkt_num_t expected_pn = largest_pn + 1;

    /* Packet number reconstruction window. */
    ql_pkt_num_t pn_win  = (ql_pkt_num_t)1 << pn_nbits;
    ql_pkt_num_t pn_hwin = pn_win / 2;
    ql_pkt_num_t pn_mask = pn_win - 1;

    /* Reconstruct using expected packet number's upper bits. */
    ql_pkt_num_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    /* Candidate is too far behind. */
    if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < ((1ULL << 62) - pn_win)) {
        candidate_pn += pn_win;
    }
    /* Candidate is too far ahead. */
    else if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        candidate_pn -= pn_win;
    }

    if (candidate_pn > QL_VARINT_MAX) {
        candidate_pn -= pn_win;
    }

    return candidate_pn;
}

int ql_frame_encode(const ql_frame_t *frame, uint8_t *buf, size_t cap) {
    size_t pos = 0; // this is the cursor in buffer

    switch (frame->type) {
        case QL_FRAME_PADDING: {
            size_t pad = frame->u.padding.length;
            if (pos + pad > cap) {
                return QLITE_ERR_BUF;
            }
            memset(buf + pos, 0x00, pad);
            pos += pad;
            return (int)pos;
        }
        case QL_FRAME_PING: {
            WV(0x01);
            return (int)pos;
        }
        case QL_FRAME_ACK:
        case QL_FRAME_ACK_ECN: {
            const ql_frame_ack_t *f = &frame->u.ack;
            WV(frame->type); /* 0x02 or 0x03 */
            WV(f->largest_acked);
            WV(f->ack_delay);
            WV(f->range_count);
            WV(f->first_ack_range);

            /* 19.3.1 — each extra range is a (Gap, ACK Range Length) pair.
             * `ranges[i].largest` holds an absolute packet number (matching
             * ql_ack_range_t's doc comment and what decode reconstructs
             * below), so the gap has to be derived here — it's the inverse
             * of the decode-side reconstruction, not a value the caller
             * supplies directly. */
            ql_pkt_num_t prev_sml = f->largest_acked - f->first_ack_range;
            for (uint64_t i = 0; i < f->range_count && i < QL_ACK_RANGE_MAX; i++) {
                uint64_t range_len = f->ranges[i].count - 1;
                uint64_t gap       = prev_sml - f->ranges[i].largest - 2;
                WV(gap);
                WV(range_len);
                prev_sml = f->ranges[i].largest - range_len;
            }

            /* ECN counts only present in ACK_ECN (0x03) */
            if (f->has_ecn) {
                WV(f->ect0_count);
                WV(f->ect1_count);
                WV(f->ecn_ce_count);
            }
            return (int)pos;
        }
        case QL_FRAME_RESET_STREAM: {
            WV(0x04);
            WV(frame->u.reset_stream.stream_id);
            WV(frame->u.reset_stream.error_code);
            WV(frame->u.reset_stream.final_size);
            return (int)pos;
        }
        case QL_FRAME_STOP_SENDING: {
            WV(0x05);
            WV(frame->u.stop_sending.stream_id);
            WV(frame->u.stop_sending.error_code);
            return (int)pos;
        }
        case QL_FRAME_CRYPTO: {
            WV(0x06);
            WV(frame->u.crypto.offset);
            WV(frame->u.crypto.length);
            WB(frame->u.crypto.data, frame->u.crypto.length);
            return (int)pos;
        }
        case QL_FRAME_NEW_TOKEN: {
            WV(0x07);
            WV(frame->u.new_token.token_length);
            WB(frame->u.new_token.token, frame->u.new_token.token_length);
            return (int)pos;
        }
        /* all 8 STREAM variants fall through to same logic */
        case QL_FRAME_STREAM:
        case QL_FRAME_STREAM_FIN:
        case QL_FRAME_STREAM_LEN:
        case QL_FRAME_STREAM_LEN_FIN:
        case QL_FRAME_STREAM_OFF:
        case QL_FRAME_STREAM_OFF_FIN:
        case QL_FRAME_STREAM_OFF_LEN:
        case QL_FRAME_STREAM_OFF_LEN_FIN: {
            const ql_frame_stream_t *f = &frame->u.stream;
            uint8_t type               = 0x08 | (f->fin ? 0x01 : 0) | (f->has_length ? 0x02 : 0) |
                           (f->has_offset ? 0x04 : 0);
            WV(type);
            WV(f->stream_id);
            if (f->has_offset) {
                WV(f->offset);
            }
            if (f->has_length) {
                WV(f->length);
            }
            WB(f->data, f->length);
            return (int)pos;
        }
        case QL_FRAME_MAX_DATA:
            WV(0x10);
            WV(frame->u.max_data.maximum_data);
            return (int)pos;

        case QL_FRAME_MAX_STREAM_DATA:
            WV(0x11);
            WV(frame->u.max_stream_data.stream_id);
            WV(frame->u.max_stream_data.maximum_stream_data);
            return (int)pos;

        case QL_FRAME_MAX_STREAMS_BIDI:
        case QL_FRAME_MAX_STREAMS_UNI:
            WV(frame->type);
            WV(frame->u.max_streams.maximum_streams);
            return (int)pos;

        case QL_FRAME_DATA_BLOCKED:
            WV(0x14);
            WV(frame->u.data_blocked.data_limit);
            return (int)pos;

        case QL_FRAME_STREAM_DATA_BLOCKED:
            WV(0x15);
            WV(frame->u.stream_data_blocked.stream_id);
            WV(frame->u.stream_data_blocked.stream_data_limit);
            return (int)pos;

        case QL_FRAME_STREAMS_BLOCKED_BIDI:
        case QL_FRAME_STREAMS_BLOCKED_UNI:
            WV(frame->type);
            WV(frame->u.streams_blocked.stream_limit);
            return (int)pos;

        case QL_FRAME_NEW_CONNECTION_ID: {
            const ql_frame_new_cid_t *f = &frame->u.new_cid;
            WV(0x18);
            WV(f->sequence_num);
            WV(f->retire_prior_to);
            /* cid_len is a plain uint8 on the wire, NOT a varint */
            WB(&f->cid.len, 1);
            WB(f->cid.data, f->cid.len);
            WB(f->stateless_reset_token.data, QL_RESET_TOKEN_LEN);
            return (int)pos;
        }

        case QL_FRAME_RETIRE_CONNECTION_ID:
            WV(0x19);
            WV(frame->u.retire_cid.sequence_num);
            return (int)pos;

        case QL_FRAME_PATH_CHALLENGE:
            /* data is 8 raw bytes, NOT a varint */
            WV(0x1A);
            WB(frame->u.path_challenge.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_PATH_RESPONSE:
            WV(0x1B);
            WB(frame->u.path_response.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_CONNECTION_CLOSE: {
            const ql_frame_conn_close_t *f = &frame->u.conn_close;
            WV(0x1C);
            WV(f->error_code);
            WV(f->frame_type);
            WV(f->reason_length);
            WB(f->reason_phrase, f->reason_length);
            return (int)pos;
        }
        case QL_FRAME_CONNECTION_CLOSE_APP: {
            const ql_frame_conn_close_t *f = &frame->u.conn_close;
            /* 0x1D has no frame_type field */
            WV(0x1D);
            WV(f->app_error_code);
            WV(f->reason_length);
            WB(f->reason_phrase, f->reason_length);
            return (int)pos;
        }

        case QL_FRAME_HANDSHAKE_DONE:
            WV(0x1E);
            return (int)pos;

        default:
            return QLITE_ERR_PROTO;
    }
}

int ql_frame_decode(const uint8_t *buf, size_t len, ql_frame_t *out) {
    if (!buf || !out || len == 0) {
        return QLITE_ERR_ARGS;
    }
    size_t pos = 0;

    // step 1: read the type varint — tells us which frame this is
    ql_varint_t type_vi;
    int n = ql_varint_decode(buf, len, &type_vi);
    if (n < 0) {
        return n;
    }
    pos += n;

    memset(out, 0, sizeof(*out));
    out->type = (ql_frame_type_t)type_vi;

    switch (out->type) {
        case QL_FRAME_PADDING: {
            size_t count = 1;
            while (pos < len && buf[pos] == 0x00) {
                pos++;
                count++;
            }
            out->u.padding.length = count;
            return (int)pos;
        }

        case QL_FRAME_PING:
            return (int)pos;

        case QL_FRAME_ACK:
        case QL_FRAME_ACK_ECN: {
            ql_frame_ack_t *a = &out->u.ack;
            a->has_ecn        = (out->type == QL_FRAME_ACK_ECN);

            RV(a->largest_acked);
            RV(a->ack_delay);
            RV(a->range_count);
            RV(a->first_ack_range);

            ql_pkt_num_t prev_sml = a->largest_acked - a->first_ack_range;
            uint64_t n_ranges =
                a->range_count < QL_ACK_RANGE_MAX ? a->range_count : QL_ACK_RANGE_MAX;

            for (uint64_t i = 0; i < n_ranges; i++) {
                ql_varint_t gap, range_len;
                RV(gap);
                RV(range_len);

                ql_pkt_num_t this_largest = prev_sml - gap - 2;
                a->ranges[i].largest      = this_largest;
                a->ranges[i].count        = range_len + 1;
                prev_sml                  = this_largest - range_len; /* smallest of this range */
            }

            if (a->has_ecn) {
                RV(a->ect0_count);
                RV(a->ect1_count);
                RV(a->ecn_ce_count);
            }
            return (int)pos;
        }

        case QL_FRAME_RESET_STREAM: {
            ql_frame_reset_stream_t *f = &out->u.reset_stream;
            RV(f->stream_id);
            RV(f->error_code);
            RV(f->final_size);
            return (int)pos;
        }

        case QL_FRAME_STOP_SENDING: {
            ql_frame_stop_sending_t *f = &out->u.stop_sending;
            RV(f->stream_id);
            RV(f->error_code);
            return (int)pos;
        }

        case QL_FRAME_CRYPTO: {
            ql_frame_crypto_t *f = &out->u.crypto;
            RV(f->offset);
            RV(f->length);
            if (pos + (size_t)f->length > len) {
                return QLITE_ERR_BUF;
            }
            f->data = buf + pos; /* zero-copy: points into caller's buf */
            pos += (size_t)f->length;
            return (int)pos;
        }

        case QL_FRAME_NEW_TOKEN: {
            ql_frame_new_token_t *f = &out->u.new_token;
            RV(f->token_length);
            if (pos + (size_t)f->token_length > len) {
                return QLITE_ERR_BUF;
            }
            f->token = buf + pos; /* zero-copy */
            pos += (size_t)f->token_length;
            return (int)pos;
        }

        case QL_FRAME_STREAM:
        case QL_FRAME_STREAM_FIN:
        case QL_FRAME_STREAM_LEN:
        case QL_FRAME_STREAM_LEN_FIN:
        case QL_FRAME_STREAM_OFF:
        case QL_FRAME_STREAM_OFF_FIN:
        case QL_FRAME_STREAM_OFF_LEN:
        case QL_FRAME_STREAM_OFF_LEN_FIN: {
            ql_frame_stream_t *f = &out->u.stream;
            uint8_t flags        = (uint8_t)out->type & 0x07u;
            f->fin               = (flags & QL_STREAM_FLAG_FIN) != 0;
            f->has_length        = (flags & QL_STREAM_FLAG_LEN) != 0;
            f->has_offset        = (flags & QL_STREAM_FLAG_OFF) != 0;

            RV(f->stream_id);

            if (f->has_offset) {
                RV(f->offset); /* else offset = 0 (implicit) */
            }

            if (f->has_length) {
                RV(f->length);
                if (pos + (size_t)f->length > len) {
                    return QLITE_ERR_BUF;
                }
                f->data = buf + pos; /* zero-copy */
                pos += (size_t)f->length;
            } else {
                /* No LEN bit: data runs to end of the enclosing packet 19.8 */
                f->length = (uint64_t)(len - pos);
                f->data   = buf + pos;
                pos       = len;
            }
            return (int)pos;
        }

        case QL_FRAME_MAX_DATA:
            RV(out->u.max_data.maximum_data);
            return (int)pos;

        case QL_FRAME_MAX_STREAM_DATA: {
            ql_frame_max_stream_data_t *f = &out->u.max_stream_data;
            RV(f->stream_id);
            RV(f->maximum_stream_data);
            return (int)pos;
        }

        case QL_FRAME_MAX_STREAMS_BIDI:
        case QL_FRAME_MAX_STREAMS_UNI:
            RV(out->u.max_streams.maximum_streams);
            return (int)pos;

        case QL_FRAME_DATA_BLOCKED:
            RV(out->u.data_blocked.data_limit);
            return (int)pos;

        case QL_FRAME_STREAM_DATA_BLOCKED: {
            ql_frame_stream_data_blocked_t *f = &out->u.stream_data_blocked;
            RV(f->stream_id);
            RV(f->stream_data_limit);
            return (int)pos;
        }

        case QL_FRAME_STREAMS_BLOCKED_BIDI:
        case QL_FRAME_STREAMS_BLOCKED_UNI:
            RV(out->u.streams_blocked.stream_limit);
            return (int)pos;

        case QL_FRAME_NEW_CONNECTION_ID: {
            ql_frame_new_cid_t *f = &out->u.new_cid;
            RV(f->sequence_num);
            RV(f->retire_prior_to);
            /* CID length is a plain uint8_t on the wire, NOT a varint 19.15 */
            if (pos >= len) {
                return QLITE_ERR_BUF;
            }
            f->cid.len = buf[pos++];
            if (f->cid.len > QL_CID_MAX_LEN) {
                return QLITE_ERR_PROTO;
            }
            RB(f->cid.data, f->cid.len);
            /* Stateless Reset Token: always exactly 16 bytes 19.15 */
            RB(f->stateless_reset_token.data, QL_RESET_TOKEN_LEN);
            return (int)pos;
        }

        case QL_FRAME_RETIRE_CONNECTION_ID:
            RV(out->u.retire_cid.sequence_num);
            return (int)pos;

        case QL_FRAME_PATH_CHALLENGE:
            RB(out->u.path_challenge.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_PATH_RESPONSE:
            RB(out->u.path_response.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_CONNECTION_CLOSE:
        case QL_FRAME_CONNECTION_CLOSE_APP: {
            ql_frame_conn_close_t *f = &out->u.conn_close;
            f->is_app                = (out->type == QL_FRAME_CONNECTION_CLOSE_APP);

            if (!f->is_app) {
                RV(f->error_code);
                RV(f->frame_type);
            } else {
                RV(f->app_error_code);
            }
            RV(f->reason_length);
            if (pos + (size_t)f->reason_length > len) {
                return QLITE_ERR_BUF;
            }
            f->reason_phrase = buf + pos; /* zero-copy */
            pos += (size_t)f->reason_length;
            return (int)pos;
        }

        case QL_FRAME_HANDSHAKE_DONE:
            return (int)pos;

        default:
            return QLITE_ERR_PROTO;
    }
}

/*
 * ql_udp_socket — creates a non-blocking UDP socket bound to bind_addr:port.
 *
 * bind_addr may be NULL or "" to bind to INADDR_ANY / in6addr_any.
 * port = 0 lets the OS assign an ephemeral port.
 *
 * Returns fd >= 0 on success, or QLITE_ERR_INTERNAL on failure
 * (check errno for the OS reason).
 *
 * Steps:
 *   1. getaddrinfo to resolve bind_addr (supports IPv4 and IPv6)
 *   2. socket(AF_INET/6, SOCK_DGRAM, IPPROTO_UDP)
 *   3. SO_REUSEADDR
 *   4. O_NONBLOCK
 *   5. bind()
 */
int ql_udp_socket(const char *bind_addr, uint16_t port) {
    int fd  = -1;
    int one = 1;
    int flags;

    /*
        try ipv6 first (dual-stack on linux handles ipv4 too)
        fall back to ipv4 if ipv6 is not available
    */
    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd >= 0) {
        /* allow ipv4 client on the ipv6*/
        int ipv6_only = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));

        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port   = htons(port);

        if (bind_addr && bind_addr[0]) {
            if (inet_pton(AF_INET6, bind_addr, &addr6.sin6_addr) != 1) {
                close(fd);
                fd = -1;
                goto try_ipv4;
            }
        } else {
            addr6.sin6_addr = in6addr_any;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
            bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
            close(fd);
            fd = -1;
        } else {
            return fd;
        }
    }

try_ipv4:
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return QLITE_ERR_INTERNAL;
    }

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port   = htons(port);

    if (bind_addr && bind_addr[0]) {
        if (inet_pton(AF_INET, bind_addr, &addr4.sin_addr) != 1) {
            close(fd);
            return QLITE_ERR_INTERNAL;
        }
    } else {
        addr4.sin_addr.s_addr = INADDR_ANY;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
        close(fd);
        return QLITE_ERR_INTERNAL;
    }

    return fd;
}

/*
 * ql_udp_send — sends one UDP datagram.
 *
 * Returns bytes sent (>= 0), QLITE_ERR_WOULDBLOCK if the socket would
 * block, or QLITE_ERR_INTERNAL on a hard error.
 *
 * 14.1: if sendmsg returns EMSGSIZE the caller should lower the path MTU
 * and re-fragment — we surface this as QLITE_ERR_BUF so the caller can
 * detect it.
 */
int ql_udp_send(int fd, const struct sockaddr *addr, socklen_t addrlen, const uint8_t *buf,
                size_t len) {
    if (len <= 0) {
        return QLITE_ERR_ARGS;
    }
    ssize_t sent = sendto(fd, buf, len, 0, addr, addrlen);
    if (sent >= 0) {
        return (int)sent;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return QLITE_ERR_WOULDBLOCK;
    }
    if (errno == EMSGSIZE) {
        return QLITE_ERR_BUF;
    }
    return QLITE_ERR_INTERNAL;
}

/*
 * ql_udp_recv — receives one UDP datagram.
 *
 * Returns bytes received (>= 0), QLITE_ERR_WOULDBLOCK if no data ready,
 * or QLITE_ERR_INTERNAL on error.
 *
 * src and srclen are populated with the sender's address (may be NULL).
 */
int ql_udp_recv(int fd, uint8_t *buf, size_t cap, struct sockaddr_storage *src, socklen_t *srclen) {
    socklen_t addrlen = src ? sizeof(*src) : 0;
    ssize_t n =
        recvfrom(fd, buf, cap, 0, src ? (struct sockaddr *)src : NULL, src ? &addrlen : NULL);

    if (n >= 0) {
        if (srclen) {
            *srclen = addrlen;
        }
        return (int)n;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return QLITE_ERR_WOULDBLOCK;
    }
    return QLITE_ERR_INTERNAL;
}

/* RFC 9001 5.3 — build per-packet nonce by XOR-ing IV with packet number */
static void ql__build_nonce(const ql_keys_t *key, ql_pkt_num_t pkt_num, uint8_t *nonce) {
    memcpy(nonce, key->iv, key->iv_len);
    /* packet number is big-endian in the rightmost bytes */
    for (int i = 0; i < 8; i++) {
        nonce[key->iv_len - 1 - i] ^= (uint8_t)(pkt_num >> (8 * i));
    }
}

/* AEAD seal / open (RFC 9001 5.3) */
int ql_aead_seal(const ql_keys_t *key, ql_pkt_num_t pkt_num, const uint8_t *aad, size_t aad_len,
                 const uint8_t *plaintext, size_t pt_len, uint8_t *out, size_t cap) {
    if (!key || !key->is_set || !out) {
        return QLITE_ERR_ARGS;
    }
    if (cap < pt_len + QL_AEAD_TAG_LEN) {
        return QLITE_ERR_BUF;
    }

    uint8_t nonce[QL_AEAD_IV_MAX_LEN];
    ql__build_nonce(key, pkt_num, nonce);

    const EVP_CIPHER *cipher = (key->key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QLITE_ERR_INTERNAL;
    }

    int ret  = QLITE_ERR_CRYPTO;
    int outl = 0, outl2 = 0;

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        goto done;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, key->iv_len, NULL)) {
        goto done;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key->key, nonce)) {
        goto done;
    }
    if (aad_len && !EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len)) {
        goto done;
    }
    if (!EVP_EncryptUpdate(ctx, out, &outl, plaintext, (int)pt_len)) {
        goto done;
    }
    if (!EVP_EncryptFinal_ex(ctx, out + outl, &outl2)) {
        goto done;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QL_AEAD_TAG_LEN, out + outl + outl2)) {
        goto done;
    }

    ret = outl + outl2 + QL_AEAD_TAG_LEN;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int ql_aead_open(const ql_keys_t *key, ql_pkt_num_t pkt_num, const uint8_t *aad, size_t aad_len,
                 const uint8_t *ciphertext, size_t ct_len, uint8_t *out, size_t cap) {
    if (!key || !key->is_set || !ciphertext || !out) {
        return QLITE_ERR_ARGS;
    }
    if (ct_len < QL_AEAD_TAG_LEN) {
        return QLITE_ERR_PROTO;
    }

    size_t pt_len = ct_len - QL_AEAD_TAG_LEN;
    if (cap < pt_len) {
        return QLITE_ERR_BUF;
    }

    uint8_t nonce[QL_AEAD_IV_MAX_LEN];
    ql__build_nonce(key, pkt_num, nonce);

    const EVP_CIPHER *cipher = (key->key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QLITE_ERR_INTERNAL;
    }

    int ret  = QLITE_ERR_CRYPTO;
    int outl = 0, outl2 = 0;

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        goto done;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, key->iv_len, NULL)) {
        goto done;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key->key, nonce)) {
        goto done;
    }
    if (aad_len && !EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len)) {
        goto done;
    }
    if (!EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)pt_len)) {
        goto done;
    }
    /* set expected tag (last 16 bytes of ciphertext) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, QL_AEAD_TAG_LEN,
                             (void *)(ciphertext + pt_len))) {
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, out + outl, &outl2) <= 0) {
        goto done;
    }

    ret = outl + outl2;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * RFC 9001 5.4.3 — Header protection using AES-ECB.
 * mask = AES-ECB(hp_key, sample)[0:5]
 * For long headers: first_byte mask = mask[0] & 0x0F
 * For short headers: first_byte mask = mask[0] & 0x1F
 * pkt_num bytes: XOR with mask[1..pkt_num_len]
 *
 * hdr layout expected: hdr[0] = first_byte, hdr[hdr_len - pkt_num_len ..] = pkt_num bytes
 * We detect long vs short by the high bit of hdr[0].
 */
static int ql__hp_apply(const ql_keys_t *key, uint8_t *hdr, size_t hdr_len, const uint8_t *sample,
                        bool protect) {
    if (!key || !key->is_set || !hdr || !sample || hdr_len < 2) {
        return QLITE_ERR_ARGS;
    }

    /* AES-ECB on one 16-byte block via EVP — no deprecated AES_* symbols */
    uint8_t mask[16];
    int mask_len = 0;

    const EVP_CIPHER *ecb = (key->hp_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return QLITE_ERR_INTERNAL;
    }

    int ret = QLITE_ERR_CRYPTO;

    if (!EVP_EncryptInit_ex(ctx, ecb, NULL, key->hp, NULL)) {
        goto done;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); /* single exact block, no padding */
    if (!EVP_EncryptUpdate(ctx, mask, &mask_len, sample, 16)) {
        goto done;
    }
    /* no EVP_EncryptFinal needed — padding disabled, block is already complete */

    {
        uint8_t first = hdr[0];
        bool is_long  = (first & 0x80) != 0;
        uint8_t pn_len;

        if (protect) {
            pn_len = (first & 0x03) + 1;
        } else {
            uint8_t first_unmasked = first ^ (mask[0] & (is_long ? 0x0F : 0x1F));
            pn_len                 = (first_unmasked & 0x03) + 1;
        }

        if (hdr_len < (size_t)(1 + pn_len)) {
            ret = QLITE_ERR_BUF;
            goto done;
        }

        hdr[0] ^= mask[0] & (is_long ? 0x0F : 0x1F);

        uint8_t *pn = hdr + hdr_len - pn_len;
        for (uint8_t i = 0; i < pn_len; i++) {
            pn[i] ^= mask[1 + i];
        }
    }

    ret = QLITE_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Header protection (RFC 9001 5.4) */
int ql_hp_protect(const ql_keys_t *key, uint8_t *hdr, size_t hdr_len, const uint8_t *sample) {
    return ql__hp_apply(key, hdr, hdr_len, sample, true);
}

int ql_hp_remove(const ql_keys_t *key, uint8_t *hdr, size_t hdr_len, const uint8_t *sample) {
    return ql__hp_apply(key, hdr, hdr_len, sample, false);
}

/* -------------------------------------------------------------------------
 * RFC 8446 7.1 HKDF-Expand-Label, reused by RFC 9001 5.1 for
 * "quic key" / "quic iv" / "quic hp" derivation from a TLS secret.
 *
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *       HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * HkdfLabel = struct {
 *     uint16 length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;   // empty for QUIC key derivation
 * };
 * ------------------------------------------------------------------------- */
int hkdf_expand_label(const EVP_MD *md, const uint8_t *secret, size_t secret_len,
                      const char *label, /* WITHOUT "tls13 " prefix */
                      uint8_t *out, size_t out_len) {
    uint8_t hkdf_label[2 + 1 + 6 + 64 + 1]; /* generous fixed bound */
    size_t pos            = 0;
    size_t label_len      = strlen(label);
    const char prefix[]   = "tls13 ";
    size_t full_label_len = sizeof(prefix) - 1 + label_len;

    if (full_label_len > 255 || out_len > 0xFFFF) {
        return -1;
    }

    hkdf_label[pos++] = (uint8_t)(out_len >> 8);
    hkdf_label[pos++] = (uint8_t)(out_len & 0xFF);
    hkdf_label[pos++] = (uint8_t)full_label_len;
    memcpy(hkdf_label + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    memcpy(hkdf_label + pos, label, label_len);
    pos += label_len;
    hkdf_label[pos++] = 0x00; /* empty Context */

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "HKDF", NULL);
    if (!pctx) {
        return -1;
    }

    int rc = -1;
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secret_len) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label, (int)pos) <= 0) {
        goto out;
    }
    {
        size_t outl = out_len;
        if (EVP_PKEY_derive(pctx, out, &outl) <= 0 || outl != out_len) {
            goto out;
        }
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int ql_pkt_encode(const ql_pkt_hdr_t *hdr, const ql_keys_t *key, const uint8_t *payload,
                  size_t payload_len, uint8_t *out, size_t cap) {
    if (!hdr || !key || !out) {
        return QLITE_ERR_ARGS;
    }
    /* header -> ql_aead_seal() -> ql_hp_protect() */
    size_t pos = 0;

    if (hdr->is_long) {
        /* long header*/
        const ql_long_hdr_t *lh = &hdr->h.lhdr;
        // first byte
        if (pos >= cap) {
            return QLITE_ERR_BUF;
        }
        out[pos++] = lh->first_byte;

        if (pos + 4 > cap) {
            return QLITE_ERR_BUF;
        }
        ql__write_be(out + pos, lh->version, 4);
        pos += 4;

        /* DCID LENGTH + DCID*/
        if (pos + 1 + lh->dst_cid.len > cap) {
            return QLITE_ERR_BUF;
        }
        out[pos++] = lh->dst_cid.len;
        memcpy(out + pos, lh->dst_cid.data, lh->dst_cid.len);
        pos += lh->dst_cid.len;

        /* SCID length + SCID */
        if (pos + 1 + lh->src_cid.len > cap) {
            return QLITE_ERR_BUF;
        }
        out[pos++] = lh->src_cid.len;
        memcpy(out + pos, lh->src_cid.data, lh->src_cid.len);
        pos += lh->src_cid.len;

        /* Initial: token length + token */
        if (lh->pkt_type == QL_PKT_INITIAL) {
            int vn = ql_varint_encode(out + pos, cap - pos, lh->token_len);
            if (vn < 0) {
                return QLITE_ERR_BUF;
            }
            pos += (size_t)vn;
            if (pos + lh->token_len > cap) {
                return QLITE_ERR_BUF;
            }
            memcpy(out + pos, lh->token, lh->token_len);
            pos += lh->token_len;
        }

        /* Length (payload + AEAD tag), leave space: encode as 2-byte varint */
        size_t length_field_pos  = pos;
        uint64_t pkt_payload_len = payload_len + QL_AEAD_TAG_LEN;
        if (pkt_payload_len > QL_VARINT_2B_MAX) {
            return QLITE_ERR_BUF;
        }
        if (pos + 2 > cap) {
            return QLITE_ERR_BUF;
        }
        /* Always encode as 2-byte varint so the field is fixed-width */
        out[pos]     = 0x40 | (uint8_t)((pkt_payload_len >> 8) & 0x3F);
        out[pos + 1] = (uint8_t)(pkt_payload_len & 0xFF);
        pos += 2;

        /* Packet number — always encode as minimum width */
        size_t pn_pos = pos;
        int pn_len    = ql_pkt_num_encode(
            out + pos, lh->pkt_num, QL_PKT_NUM_NONE /* simplified: chunk 2 passes largest_acked */);
        if (pn_len < 0) {
            return pn_len;
        }
        pos += (size_t)pn_len;

        /* Patch first byte's pkt-num-length field (bits 0–1) */
        out[length_field_pos - 1 /* first_byte */] =
            (out[0] & ~QL_LONG_HDR_PKT_NUM_MASK) | (uint8_t)(pn_len - 1);
        (void)pn_pos;

    } else {
        /* short header*/
        const ql_short_hdr_t *sh = &hdr->h.shdr;
        if (pos >= cap) {
            return QLITE_ERR_BUF;
        }
        out[pos++] = sh->first_byte;

        /* DCID (Length known from the conn, no length prefix 17.3)*/
        if (pos + sh->dst_cid.len > cap) {
            return QLITE_ERR_BUF;
        }
        memcpy(out + pos, sh->dst_cid.data, sh->dst_cid.len);
        pos += sh->dst_cid.len;

        /* pkt num*/
        int pn_len = ql_pkt_num_encode(out + pos, sh->pkt_num, QL_PKT_NUM_NONE);
        if (pn_len < 0) {
            return pn_len;
        }
        pos += (size_t)pn_len;
    }

    if (pos + payload_len + QL_AEAD_TAG_LEN > cap) {
        return QLITE_ERR_BUF;
    }

    int sealed = ql_aead_seal(key, 0, out, pos, payload, payload_len, out + pos, cap - pos);
    if (sealed < 0) {
        return sealed;
    }
    pos += (size_t)sealed;

    const uint8_t *sample = out + pos - QL_AEAD_TAG_LEN - payload_len + QL_HP_SAMPLE_OFFSET;

    int hp = ql_hp_protect(key, out, pos, sample);
    if (hp < 0) {
        return hp;
    }

    return (int)pos;
}

/*
 * Scratch buffer big enough to hold an unprotected header (first byte +
 * version + two CIDs + token + length field + max 4-byte pkt-num):
 * 1 + 4 + (1+20) + (1+20) + 2 + QL_TOKEN_MAX_LEN + 2 + 4 = 311, rounded up.
 */
#define QL_PKT_HDR_SCRATCH_MAX 320

/*
 * ql_pkt_decode — RFC 9000 17 / RFC 9001 5.4 (§2.5.7)
 *
 * `ql_hp_remove()` alone can't be used here: it assumes the caller already
 * knows the true packet-number length (it derives the pkt-num's position as
 * hdr_len - pn_len), but on receive that length is exactly what header
 * protection is hiding. So this function performs the two-step removal
 * described in RFC 9001 5.4.1 directly: sample at a fixed offset, unmask
 * the first byte to learn pn_len, then unmask only those pn_len bytes.
 *
 * Short-header packets don't self-describe their DCID length (17.3.1), so
 * the caller must pre-populate hdr_out->h.shdr.dst_cid.len with the
 * expected local CID length before calling when a short header is
 * expected. This value is read before hdr_out is cleared.
 */
int ql_pkt_decode(const uint8_t *buf, size_t len, const ql_keys_t *key, ql_pkt_hdr_t *hdr_out,
                  uint8_t *payload_out, size_t cap) {
    if(!buf || !key || !key->is_set || !hdr_out || !payload_out) return QLITE_ERR_ARGS;
    if(len < 2) return QLITE_ERR_BUF;

    uint8_t first_byte_raw = buf[0];
    bool is_long           = QL_PKT_IS_LONG(first_byte_raw);

    /* Short header carries no DCID length; caller supplies the expected
     * length via hdr_out before we wipe the struct. */
    uint8_t expected_dcid_len = is_long ? 0 : hdr_out->h.shdr.dst_cid.len;

    memset(hdr_out, 0, sizeof(*hdr_out));
    hdr_out->is_long = is_long;

    size_t pos = 1;
    size_t pn_start; /* offset of first (still-protected) pkt-num byte */

    if (is_long) {
        ql_long_hdr_t *lh = &hdr_out->h.lhdr;

        if (pos + 4 > len) {
            return QLITE_ERR_BUF;
        }
        lh->version =
            ((uint32_t)buf[pos] << 24) | ((uint32_t)buf[pos + 1] << 16) |
            ((uint32_t)buf[pos + 2] << 8) | (uint32_t)buf[pos + 3];
        pos += 4;

        if (pos >= len) {
            return QLITE_ERR_BUF;
        }
        uint8_t dcid_len = buf[pos++];
        if (dcid_len > QL_CID_MAX_LEN || pos + dcid_len > len) {
            return QLITE_ERR_PROTO;
        }
        lh->dst_cid.len = dcid_len;
        memcpy(lh->dst_cid.data, buf + pos, dcid_len);
        pos += dcid_len;

        if (pos >= len) {
            return QLITE_ERR_BUF;
        }
        uint8_t scid_len = buf[pos++];
        if (scid_len > QL_CID_MAX_LEN || pos + scid_len > len) {
            return QLITE_ERR_PROTO;
        }
        lh->src_cid.len = scid_len;
        memcpy(lh->src_cid.data, buf + pos, scid_len);
        pos += scid_len;

        if (lh->version == QL_VERSION_NEGOTIATION) {
            /* Not a decodable (AEAD-protected) packet — caller should route
             * to ql_vn_decode() instead. Report as a protocol condition
             * rather than guessing at a payload. */
            return QLITE_ERR_PROTO;
        }

        uint8_t type_bits = (uint8_t)((first_byte_raw & QL_LONG_HDR_TYPE_MASK) >> QL_LONG_HDR_TYPE_SHIFT);
        switch (type_bits) {
            case 0: lh->pkt_type = QL_PKT_INITIAL; break;
            case 1: lh->pkt_type = QL_PKT_0RTT; break;
            case 2: lh->pkt_type = QL_PKT_HANDSHAKE; break;
            default: lh->pkt_type = QL_PKT_RETRY; break;
        }
        lh->first_byte = first_byte_raw;

        if (lh->pkt_type == QL_PKT_RETRY) {
            /* No length / pkt-num field. Everything up to the trailing
             * 16-byte integrity tag is the Retry token. Not AEAD-protected
             * here — caller verifies the tag separately (chunk 2.4). */
            if (len < pos + QL_AEAD_TAG_LEN) {
                return QLITE_ERR_BUF;
            }
            size_t tag_pos   = len - QL_AEAD_TAG_LEN;
            size_t token_len = tag_pos - pos;
            if (token_len > QL_TOKEN_MAX_LEN) {
                return QLITE_ERR_PROTO;
            }
            memcpy(lh->token, buf + pos, token_len);
            lh->token_len = token_len;
            memcpy(lh->retry_integrity_tag, buf + tag_pos, QL_AEAD_TAG_LEN);
            lh->is_retry     = true;
            hdr_out->payload = NULL;
            hdr_out->payload_len = 0;
            return (int)len;
        }

        if (lh->pkt_type == QL_PKT_INITIAL) {
            ql_varint_t token_len_vi;
            int vn = ql_varint_decode(buf + pos, len - pos, &token_len_vi);
            if (vn < 0) {
                return QLITE_ERR_BUF;
            }
            pos += (size_t)vn;
            if (token_len_vi > QL_TOKEN_MAX_LEN || pos + token_len_vi > len) {
                return QLITE_ERR_PROTO;
            }
            memcpy(lh->token, buf + pos, (size_t)token_len_vi);
            lh->token_len = (size_t)token_len_vi;
            pos += (size_t)token_len_vi;
        }

        ql_varint_t length_vi;
        int ln = ql_varint_decode(buf + pos, len - pos, &length_vi);
        if (ln < 0) {
            return QLITE_ERR_BUF;
        }
        pos += (size_t)ln;
        if (length_vi < 1 || pos + length_vi > len) {
            return QLITE_ERR_PROTO;
        }
        lh->length = length_vi;
        pn_start   = pos;
    } else {
        ql_short_hdr_t *sh = &hdr_out->h.shdr;
        sh->first_byte      = first_byte_raw;

        uint8_t dcid_len = expected_dcid_len;
        if (dcid_len > QL_CID_MAX_LEN || pos + dcid_len > len) {
            return QLITE_ERR_BUF;
        }
        sh->dst_cid.len = dcid_len;
        memcpy(sh->dst_cid.data, buf + pos, dcid_len);
        pos += dcid_len;
        pn_start = pos;
    }

    /* ---- Header protection removal (RFC 9001 5.4.1 / 5.4.2) ---- */
    if (pn_start + QL_HP_SAMPLE_OFFSET + QL_HP_SAMPLE_LEN > len) {
        return QLITE_ERR_BUF;
    }
    const uint8_t *sample = buf + pn_start + QL_HP_SAMPLE_OFFSET;

    uint8_t mask[16];
    {
        const EVP_CIPHER *ecb = (key->hp_len == 16) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
        EVP_CIPHER_CTX *mctx  = EVP_CIPHER_CTX_new();
        if (!mctx) {
            return QLITE_ERR_INTERNAL;
        }
        int mlen = 0;
        int ok   = EVP_EncryptInit_ex(mctx, ecb, NULL, key->hp, NULL);
        if (ok) {
            EVP_CIPHER_CTX_set_padding(mctx, 0);
            ok = EVP_EncryptUpdate(mctx, mask, &mlen, sample, 16);
        }
        EVP_CIPHER_CTX_free(mctx);
        if (!ok) {
            return QLITE_ERR_CRYPTO;
        }
    }

    uint8_t unmasked_first = first_byte_raw ^ (mask[0] & (is_long ? 0x0F : 0x1F));
    uint8_t pn_len          = (unmasked_first & 0x03) + 1;

    if (pn_start + pn_len > len) {
        return QLITE_ERR_BUF;
    }

    uint8_t pn_bytes[QL_PKT_NUM_MAX_ENCODED_LEN];
    memcpy(pn_bytes, buf + pn_start, pn_len);
    for (uint8_t i = 0; i < pn_len; i++) {
        pn_bytes[i] ^= mask[1 + i];
    }

    uint64_t truncated_pn = 0;
    for (uint8_t i = 0; i < pn_len; i++) {
        truncated_pn = (truncated_pn << 8) | pn_bytes[i];
    }
    /* No per-space "largest acked" context is available at this layer
     * (mirrors the simplification already made in ql_pkt_encode); the
     * caller reconciles against real per-space state if it needs to. */
    ql_pkt_num_t full_pn = ql_pkt_num_decode(truncated_pn, pn_len * 8, QL_PKT_NUM_NONE);

    /* ---- Reassemble the unmasked header to use as AEAD AAD ---- */
    size_t hdr_len = pn_start + pn_len;
    if (hdr_len > QL_PKT_HDR_SCRATCH_MAX) {
        return QLITE_ERR_BUF;
    }
    uint8_t scratch[QL_PKT_HDR_SCRATCH_MAX];
    memcpy(scratch, buf, hdr_len);
    scratch[0] = unmasked_first;
    memcpy(scratch + pn_start, pn_bytes, pn_len);

    /* Patch decoded fields now that we know the real pkt-num length. */
    if (is_long) {
        hdr_out->h.lhdr.first_byte   = unmasked_first;
        hdr_out->h.lhdr.pkt_num      = full_pn;
        hdr_out->h.lhdr.pkt_num_len  = pn_len;
    } else {
        hdr_out->h.shdr.first_byte  = unmasked_first;
        hdr_out->h.shdr.pkt_num     = full_pn;
        hdr_out->h.shdr.pkt_num_len = pn_len;
        hdr_out->h.shdr.spin_bit    = (unmasked_first & QL_SHORT_HDR_SPIN_BIT) != 0;
        hdr_out->h.shdr.key_phase   = (unmasked_first & QL_SHORT_HDR_KEY_PHASE) != 0;
    }

    /* ---- Locate ciphertext and AEAD-open ---- */
    const uint8_t *ciphertext;
    size_t ct_len;
    if (is_long) {
        /* `length` (already validated to fit in the datagram) covers
         * pkt-num + payload + AEAD tag, measured from pn_start. */
        ct_len     = (size_t)hdr_out->h.lhdr.length - pn_len;
        ciphertext = buf + hdr_len;
    } else {
        /* Short header has no explicit length; this call decodes exactly
         * one datagram's worth (no coalescing at 1-RTT). */
        if (hdr_len > len) {
            return QLITE_ERR_BUF;
        }
        ct_len     = len - hdr_len;
        ciphertext = buf + hdr_len;
    }

    int pt_len = ql_aead_open(key, full_pn, scratch, hdr_len, ciphertext, ct_len, payload_out, cap);
    if (pt_len < 0) {
        return pt_len;
    }

    hdr_out->payload     = payload_out;
    hdr_out->payload_len = (size_t)pt_len;

    return (int)(hdr_len + ct_len);
}

/*
 * ql_vn_encode / ql_vn_decode — Version Negotiation packet (§17.2.1, 2.5.8)
 *
 * Not AEAD-protected, not header-protected: the server echoes the client's
 * CIDs and lists the versions it supports. Wire format:
 *   first byte (0x80 | arbitrary lower 7 bits — unused/random per §17.2.1),
 *   4-byte version field forced to 0,
 *   DCID len + DCID, SCID len + SCID,
 *   then a flat list of 4-byte supported versions filling the rest.
 */
int ql_vn_encode(const ql_ver_neg_pkt_t *vn, uint8_t *buf, size_t cap) {
    if (!vn || !buf) {
        return QLITE_ERR_ARGS;
    }
    if (vn->dst_cid.len > QL_CID_MAX_LEN || vn->src_cid.len > QL_CID_MAX_LEN) {
        return QLITE_ERR_ARGS;
    }
    if (vn->version_count < 0 || vn->version_count > QL_MAX_VERSIONS) {
        return QLITE_ERR_ARGS;
    }

    size_t pos = 0;
    size_t need = 1 + 4 + 1 + vn->dst_cid.len + 1 + vn->src_cid.len +
                  (size_t)vn->version_count * 4;
    if (need > cap) {
        return QLITE_ERR_BUF;
    }

    /* Bit 7 must be 1 (long-header form); the rest of the byte is
     * unspecified by the RFC, so we set the fixed bit for hygiene. */
    buf[pos++] = QL_LONG_HDR_FORM | QL_LONG_HDR_FIXED_BIT;

    ql__write_be(buf + pos, QL_VERSION_NEGOTIATION, 4);
    pos += 4;

    buf[pos++] = vn->dst_cid.len;
    memcpy(buf + pos, vn->dst_cid.data, vn->dst_cid.len);
    pos += vn->dst_cid.len;

    buf[pos++] = vn->src_cid.len;
    memcpy(buf + pos, vn->src_cid.data, vn->src_cid.len);
    pos += vn->src_cid.len;

    for (int i = 0; i < vn->version_count; i++) {
        ql__write_be(buf + pos, vn->versions[i], 4);
        pos += 4;
    }

    return (int)pos;
}

int ql_vn_decode(const uint8_t *buf, size_t len, ql_ver_neg_pkt_t *out) {
    if (!buf || !out) {
        return QLITE_ERR_ARGS;
    }
    if (len < 1 + 4 + 1 + 1) {
        return QLITE_ERR_BUF;
    }
    if (!QL_PKT_IS_LONG(buf[0])) {
        return QLITE_ERR_PROTO;
    }

    memset(out, 0, sizeof(*out));
    size_t pos = 1;

    uint32_t version = ((uint32_t)buf[pos] << 24) | ((uint32_t)buf[pos + 1] << 16) |
                        ((uint32_t)buf[pos + 2] << 8) | (uint32_t)buf[pos + 3];
    pos += 4;
    if (version != QL_VERSION_NEGOTIATION) {
        return QLITE_ERR_PROTO;
    }

    if (pos >= len) {
        return QLITE_ERR_BUF;
    }
    uint8_t dcid_len = buf[pos++];
    if (dcid_len > QL_CID_MAX_LEN || pos + dcid_len > len) {
        return QLITE_ERR_PROTO;
    }
    out->dst_cid.len = dcid_len;
    memcpy(out->dst_cid.data, buf + pos, dcid_len);
    pos += dcid_len;

    if (pos >= len) {
        return QLITE_ERR_BUF;
    }
    uint8_t scid_len = buf[pos++];
    if (scid_len > QL_CID_MAX_LEN || pos + scid_len > len) {
        return QLITE_ERR_PROTO;
    }
    out->src_cid.len = scid_len;
    memcpy(out->src_cid.data, buf + pos, scid_len);
    pos += scid_len;

    size_t remaining = len - pos;
    if (remaining % 4 != 0) {
        return QLITE_ERR_PROTO;
    }
    int count = (int)(remaining / 4);
    if (count > QL_MAX_VERSIONS) {
        count = QL_MAX_VERSIONS; /* keep only what we can store; not an error */
    }
    for (int i = 0; i < count; i++) {
        out->versions[i] =
            ((uint32_t)buf[pos] << 24) | ((uint32_t)buf[pos + 1] << 16) |
            ((uint32_t)buf[pos + 2] << 8) | (uint32_t)buf[pos + 3];
        pos += 4;
    }
    out->version_count = count;

    return (int)pos;
}

/* Transport-parameter encode/decode 18 */
int ql_tp_encode(const ql_transport_params_t *tp, uint8_t *buf, size_t cap) {
    if (!tp || !buf) {
        return QLITE_ERR_ARGS;
    }
    size_t pos = 0;

    if (tp->max_idle_timeout_ms) {
        TP_VARINT(QL_TP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout_ms);
    }

    if (tp->max_udp_payload_size && tp->max_udp_payload_size != QL_MAX_UDP_PAYLOAD_DEFAULT) {
        TP_VARINT(QL_TP_MAX_UDP_PAYLOAD_SIZE, tp->max_udp_payload_size);
    }

    if (tp->initial_max_data) {
        TP_VARINT(QL_TP_INITIAL_MAX_DATA, tp->initial_max_data);
    }

    if (tp->initial_max_stream_data_bidi_local) {
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, tp->initial_max_stream_data_bidi_local);
    }

    if (tp->initial_max_stream_data_bidi_remote) {
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                  tp->initial_max_stream_data_bidi_remote);
    }

    if (tp->initial_max_stream_data_uni) {
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);
    }

    if (tp->initial_max_streams_bidi) {
        TP_VARINT(QL_TP_INITIAL_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);
    }

    if (tp->initial_max_streams_uni) {
        TP_VARINT(QL_TP_INITIAL_MAX_STREAMS_UNI, tp->initial_max_streams_uni);
    }

    if (tp->ack_delay_exponent != 0 && tp->ack_delay_exponent != QL_DEFAULT_ACK_DELAY_EXP) {
        TP_VARINT(QL_TP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);
    }

    if (tp->max_ack_delay_ms != 0 && tp->max_ack_delay_ms != QL_DEFAULT_MAX_ACK_DELAY_MS) {
        TP_VARINT(QL_TP_MAX_ACK_DELAY, tp->max_ack_delay_ms);
    }

    if (tp->active_cid_limit != 0 && tp->active_cid_limit != QL_DEFAULT_ACTIVE_CID_LIMIT) {
        TP_VARINT(QL_TP_ACTIVE_CONNECTION_ID_LIMIT, tp->active_cid_limit);
    }

    if (tp->disable_active_migration) {
        /* Empty value — just id + length=0 */
        int n = ql_varint_encode(buf + pos, cap - pos, QL_TP_DISABLE_ACTIVE_MIGRATION);
        if (n < 0 || pos + (size_t)n + 1 > cap) {
            return QLITE_ERR_BUF;
        }
        pos += (size_t)n;
        buf[pos++] = 0x00; /* length = 0 */
    }

    if (tp->has_stateless_reset_token) {
        TP_BYTES(QL_TP_STATELESS_RESET_TOKEN, tp->stateless_reset_token.data, QL_RESET_TOKEN_LEN);
    }

    if (tp->original_dst_cid.len) {
        TP_CID(QL_TP_ORIGINAL_DST_CID, &tp->original_dst_cid);
    }

    if (tp->initial_src_cid.len) {
        TP_CID(QL_TP_INITIAL_SOURCE_CID, &tp->initial_src_cid);
    }

    if (tp->has_retry_src_cid && tp->retry_src_cid.len) {
        TP_CID(QL_TP_RETRY_SOURCE_CID, &tp->retry_src_cid);
    }

    return (int)pos;
}

int ql_tp_decode(const uint8_t *buf, size_t len, ql_transport_params_t *out) {
    if (!buf || !out) {
        return QLITE_ERR_ARGS;
    }
    memset(out, 0, sizeof(*out));

    /* Apply RFC defaults */
    out->max_udp_payload_size = QL_MAX_UDP_PAYLOAD_DEFAULT;
    out->ack_delay_exponent   = QL_DEFAULT_ACK_DELAY_EXP;
    out->max_ack_delay_ms     = QL_DEFAULT_MAX_ACK_DELAY_MS;
    out->active_cid_limit     = QL_DEFAULT_ACTIVE_CID_LIMIT;

    size_t pos = 0;
    while (pos < len) {
        ql_varint_t id, tp_len;
        if (ql__read_varint(buf, &pos, len, &id) < 0) {
            return QLITE_ERR_PROTO;
        }
        if (ql__read_varint(buf, &pos, len, &tp_len) < 0) {
            return QLITE_ERR_PROTO;
        }

        size_t val_end = pos + (size_t)tp_len;
        if (val_end > len) {
            return QLITE_ERR_PROTO;
        }

        ql_varint_t v;

        switch ((ql_tp_id_t)id) {
            case QL_TP_MAX_IDLE_TIMEOUT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->max_idle_timeout_ms = v;
                break;
            case QL_TP_MAX_UDP_PAYLOAD_SIZE:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                if (v < QL_MIN_UDP_PAYLOAD_SIZE) {
                    return QLITE_ERR_PROTO;
                }
                out->max_udp_payload_size = v;
                break;
            case QL_TP_INITIAL_MAX_DATA:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_data = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_stream_data_bidi_local = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_stream_data_bidi_remote = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_UNI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_stream_data_uni = v;
                break;
            case QL_TP_INITIAL_MAX_STREAMS_BIDI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_streams_bidi = v;
                break;
            case QL_TP_INITIAL_MAX_STREAMS_UNI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_max_streams_uni = v;
                break;
            case QL_TP_ACK_DELAY_EXPONENT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                if (v > 20) {
                    return QLITE_ERR_PROTO; /* 18.2: MUST be <= 20 */
                }
                out->ack_delay_exponent = v;
                break;
            case QL_TP_MAX_ACK_DELAY:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                if (v >= (UINT64_C(1) << 14)) {
                    return QLITE_ERR_PROTO; /* 18.2 */
                }
                out->max_ack_delay_ms = v;
                break;
            case QL_TP_ACTIVE_CONNECTION_ID_LIMIT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) {
                    return QLITE_ERR_PROTO;
                }
                if (v < 2) {
                    return QLITE_ERR_PROTO; /* 18.2: MUST be >= 2 */
                }
                out->active_cid_limit = v;
                break;
            case QL_TP_DISABLE_ACTIVE_MIGRATION:
                out->disable_active_migration = true;
                break;
            case QL_TP_STATELESS_RESET_TOKEN:
                if (tp_len != QL_RESET_TOKEN_LEN) {
                    return QLITE_ERR_PROTO;
                }
                memcpy(out->stateless_reset_token.data, buf + pos, QL_RESET_TOKEN_LEN);
                out->has_stateless_reset_token = true;
                break;
            case QL_TP_ORIGINAL_DST_CID:
                if (tp_len > QL_CID_MAX_LEN) {
                    return QLITE_ERR_PROTO;
                }
                out->original_dst_cid.len = (uint8_t)tp_len;
                memcpy(out->original_dst_cid.data, buf + pos, tp_len);
                break;
            case QL_TP_INITIAL_SOURCE_CID:
                if (tp_len > QL_CID_MAX_LEN) {
                    return QLITE_ERR_PROTO;
                }
                out->initial_src_cid.len = (uint8_t)tp_len;
                memcpy(out->initial_src_cid.data, buf + pos, tp_len);
                break;
            case QL_TP_RETRY_SOURCE_CID:
                if (tp_len > QL_CID_MAX_LEN) {
                    return QLITE_ERR_PROTO;
                }
                out->retry_src_cid.len = (uint8_t)tp_len;
                memcpy(out->retry_src_cid.data, buf + pos, tp_len);
                out->has_retry_src_cid = true;
                break;
            default:
                /* 7.4.2 — unknown TP IDs MUST be ignored */
                break;
        }
        pos = val_end;
    }
    return (int)pos;
}

/*
 * ql_cid_generate — fills cid->data[0..len) with cryptographically
 * random bytes and sets cid->len. 5.1: len may be 0 (zero-length CID),
 * up to QL_CID_MAX_LEN.
 *
 * Uses getrandom(2) where available (Linux), falling back to reading
 * /dev/urandom. Zeroes the struct on failure so a caller who ignores
 * the (void) return doesn't end up with a partially-random, misleading
 * CID.
 */
/*
 * ql__fill_random — getrandom(2) where available, looping past EINTR.
 * Shared by ql_cid_generate and Phase 6's reset-token / PATH_CHALLENGE
 * data generation. Leaves the buffer untouched on hard failure; callers
 * that can't tolerate that should check the return value.
 */
static int ql__fill_random(uint8_t *buf, size_t len) {
    size_t filled = 0;
    while (filled < len) {
        ssize_t n = getrandom(buf + filled, len - filled, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return QLITE_ERR_INTERNAL;
        }
        filled += (size_t)n;
    }
    return QLITE_OK;
}
void ql_cid_generate(ql_cid_t *cid, uint8_t len) {
    if (!cid || len > QL_CID_MAX_LEN) {
        return;
    }
    memset(cid->data, 0, QL_CID_MAX_LEN);
    cid->len = 0;
    if (len == 0) {
        return; /* zero-length CID is valid; nothing to fill */
    }

    if (ql__fill_random(cid->data, len) != QLITE_OK) {
        return; /* leave cid zeroed/len=0 on hard failure */
    }
    cid->len = len;
}

/*
 * ql_cid_cmp — constant-time comparison of two connection IDs.
 * Returns 0 if equal (same length and same bytes), non-zero otherwise.
 * Length is compared in variable time (it's not secret), but the byte
 * comparison itself does not short-circuit, so it doesn't leak which
 * byte differed via timing.
 */
int ql_cid_cmp(const ql_cid_t *a, const ql_cid_t *b) {
    if (!a || !b) {
        return 1;
    }
    if (a->len != b->len) {
        return 1;
    }

    uint8_t diff = 0;
    for (uint8_t i = 0; i < a->len; i++) {
        diff |= a->data[i] ^ b->data[i];
    }
    return (int)diff;
}

/*
 * ql_conn_init — initialize a freshly allocated ql_conn_t.
 *
 *   - zero the whole struct (clears all state, timers, buffers, streams)
 *   - set role (client/server)
 *   - copy cfg into conn->cfg (transport params, TLS callbacks, tuning)
 *   - generate our initial local CID (5.1) and register it as local_cids[0]
 *   - initialize congestion control to RFC 9002 7.2 defaults
 *
 * Returns 0 on success, <0 (QLITE_ERR_*) on failure.
 */
int ql_conn_init(ql_conn_t *conn, ql_role_t role, const ql_config_t *cfg) {
    if (!conn || !cfg) {
        return QLITE_ERR_ARGS;
    }
    memset(conn, 0, sizeof(*conn));

    conn->state = QL_CONN_IDLE;
    conn->role  = role;
    conn->cfg   = *cfg; /* struct copy: params + callbacks + tuning */
    conn->fd    = -1;   /* no socket bound yet */

    /* Local transport parameters start as what the caller configured;
     * remote_tp is filled in once the peer's TP arrive over TLS. */
    conn->local_tp = cfg->local_params;

    /* 5.1 — generate our initial source connection ID and register it
     * as the first (active) entry in the local CID table. */
    ql_cid_generate(&conn->local_cid, QL_CID_MAX_LEN);
    if (conn->local_cid.len == 0) {
        return QLITE_ERR_INTERNAL; /* RNG failed */
    }

    conn->local_cids[0].cid             = conn->local_cid;
    conn->local_cids[0].sequence_num    = 0;
    conn->local_cids[0].retire_prior_to = 0;
    conn->local_cids[0].is_active       = true;
    conn->local_cids[0].is_retired      = false;
    conn->local_cid_count               = 1;
    conn->next_cid_seq                  = 1; /* next CID we issue will be seq 1 */

    /* 2.1 — next stream IDs to allocate, one counter per (initiator, dir).
     * Stream ID low bits: bit0 = initiator (0=client,1=server), bit1 = dir. */
    conn->next_stream_id[QL_STREAM_TYPE_CLIENT_BIDI] = QL_STREAM_TYPE_CLIENT_BIDI;
    conn->next_stream_id[QL_STREAM_TYPE_SERVER_BIDI] = QL_STREAM_TYPE_SERVER_BIDI;
    conn->next_stream_id[QL_STREAM_TYPE_CLIENT_UNI]  = QL_STREAM_TYPE_CLIENT_UNI;
    conn->next_stream_id[QL_STREAM_TYPE_SERVER_UNI]  = QL_STREAM_TYPE_SERVER_UNI;

    /* 12.3 — packet number spaces start at 0; largest_recvd starts at
     * "none received yet" so ACK logic doesn't treat pn 0 as already seen. */
    for (int i = 0; i < QL_PN_SPACE_COUNT; i++) {
        conn->next_pn[i]       = 0;
        conn->largest_recvd[i] = QL_PKT_NUM_NONE;
        conn->ack[i].largest_recvd = QL_PKT_NUM_NONE;
    }

    /* RFC 9002 7.2 — initial congestion control state.
     * initcwnd = min(10*max_datagram_size, max(2*max_datagram_size, 14720)),
     * computed here using the conservative default MTU since the real
     * path MTU isn't known before the handshake starts. */
    uint64_t mtu      = QL_PATH_MTU_DEFAULT;
    uint64_t initcwnd = 10 * mtu;
    if (initcwnd > 14720) {
        initcwnd = 14720;
    }
    if (initcwnd < 2 * mtu) {
        initcwnd = 2 * mtu;
    }

    conn->cc.state            = QL_CC_SLOW_START;
    conn->cc.cwnd             = initcwnd;
    conn->cc.ssthresh         = UINT64_MAX; /* 7.2: no limit until first loss */
    conn->cc.bytes_in_flight  = 0;
    conn->cc.min_rtt_us       = UINT64_MAX; /* 5.2: unset until first sample */
    conn->cc.rtt_sample_taken = false;
    conn->cc.pto_count        = 0;

    conn->sent_pkt_head = conn->sent_pkt_tail = conn->sent_pkt_count = 0;

    return QLITE_OK;
}

/* Given a raw TLS secret for a level/direction, derive the three QUIC
 * packet-protection keys per RFC 9001 §5.1. `cipher` tells us the AEAD
 * (hence key_len) and hash (for HKDF) in use — AES-128-GCM/SHA-256 for
 * TLS_AES_128_GCM_SHA256, etc. */
static int derive_ql_keys(const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len,
                          ql_keys_t *out) {
    const EVP_MD *md = EVP_sha256(); /* default; widen below for SHA-384 suite */
    size_t key_len = 16, iv_len = 12, hp_len = 16;

    uint32_t id = SSL_CIPHER_get_id(cipher) & 0xFFFF;
    /* TLS_AES_256_GCM_SHA384 = 0x1302, TLS_CHACHA20_POLY1305_SHA256 = 0x1303 */
    if (id == 0x1302) {
        md      = EVP_sha384();
        key_len = 32;
    } else if (id == 0x1303) {
        key_len = 32;
    }
    /* else: TLS_AES_128_GCM_SHA256 = 0x1301 -> defaults above */

    if (hkdf_expand_label(md, secret, secret_len, "quic key", out->key, key_len) != 0) {
        return -1;
    }
    if (hkdf_expand_label(md, secret, secret_len, "quic iv", out->iv, iv_len) != 0) {
        return -1;
    }
    if (hkdf_expand_label(md, secret, secret_len, "quic hp", out->hp, hp_len) != 0) {
        return -1;
    }

    out->key_len = (uint8_t)key_len;
    out->iv_len  = (uint8_t)iv_len;
    out->hp_len  = (uint8_t)hp_len;
    out->is_set  = true;
    return 0;
}

/* RFC 9001 §5.2 — fixed salt for QUIC v1 Initial secret derivation. */
static const uint8_t QL_INITIAL_SALT_V1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                               0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                               0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

/* Initial secrets never come through cb_set_encryption_secrets (RFC 9001
 * §5.2: "The secrets for the Initial encryption level are computed based
 * on the client's initial Destination Connection ID" -- independent of
 * the TLS key schedule). Always AEAD_AES_128_GCM_SHA256, per spec. */
static int derive_initial_keys(const uint8_t *dcid, size_t dcid_len, ql_role_t role,
                               ql_key_pair_t *out) {
    const EVP_MD *md = EVP_sha256();
    uint8_t initial_secret[EVP_MAX_MD_SIZE];

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "HKDF", NULL);
    if (!pctx) {
        return -1;
    }
    int rc = -1;
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, QL_INITIAL_SALT_V1, sizeof(QL_INITIAL_SALT_V1)) <= 0) {
        goto out;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, dcid, (int)dcid_len) <= 0) {
        goto out;
    }
    {
        size_t outl = sizeof(initial_secret);
        if (EVP_PKEY_derive(pctx, initial_secret, &outl) <= 0) {
            goto out;
        }
    }

    {
        uint8_t client_secret[32], server_secret[32];
        if (hkdf_expand_label(md, initial_secret, EVP_MD_size(md), "client in", client_secret,
                              32) != 0) {
            goto out;
        }
        if (hkdf_expand_label(md, initial_secret, EVP_MD_size(md), "server in", server_secret,
                              32) != 0) {
            goto out;
        }

        const uint8_t *my_secret   = (role == QL_ROLE_CLIENT) ? client_secret : server_secret;
        const uint8_t *peer_secret = (role == QL_ROLE_CLIENT) ? server_secret : client_secret;

        if (hkdf_expand_label(md, my_secret, 32, "quic key", out->write.key, 16) != 0) {
            goto out;
        }
        if (hkdf_expand_label(md, my_secret, 32, "quic iv", out->write.iv, 12) != 0) {
            goto out;
        }
        if (hkdf_expand_label(md, my_secret, 32, "quic hp", out->write.hp, 16) != 0) {
            goto out;
        }
        out->write.key_len = 16;
        out->write.iv_len  = 12;
        out->write.hp_len  = 16;
        out->write.is_set  = true;

        if (hkdf_expand_label(md, peer_secret, 32, "quic key", out->read.key, 16) != 0) {
            goto out;
        }
        if (hkdf_expand_label(md, peer_secret, 32, "quic iv", out->read.iv, 12) != 0) {
            goto out;
        }
        if (hkdf_expand_label(md, peer_secret, 32, "quic hp", out->read.hp, 16) != 0) {
            goto out;
        }
        out->read.key_len = 16;
        out->read.iv_len  = 12;
        out->read.hp_len  = 16;
        out->read.is_set  = true;
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* TLS*/
/* -------------------------------------------------------------------------
 * SSL_QUIC_METHOD callbacks — OpenSSL calls these DURING SSL_do_handshake().
 * They're the actual entry point for handshake bytes and derived secrets;
 * our public ql_tls_* functions are just the outward-facing shape.
 * ------------------------------------------------------------------------- */

static ql_tls_backend_t *backend_of(SSL *ssl) {
    return (ql_tls_backend_t *)SSL_get_app_data(ssl);
}

static int cb_set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                     const uint8_t *read_secret, const uint8_t *write_secret,
                                     size_t secret_len) {
    ql_tls_backend_t *be = backend_of(ssl);
    ql_enc_level_t l     = map_from_ossl(level);
    if (secret_len > QL_SECRET_MAX_LEN) {
        return 0;
    }

    /* quictls doesn't hand us the cipher directly here (unlike the old
     * 5-callback BoringSSL codepoint qlite.h was originally written
     * against) — pull it off the connection instead. */
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    be->pending[l].cipher_id = cipher ? SSL_CIPHER_get_id(cipher) : 0;

    /* At ssl_encryption_early_data only one of these is non-NULL; at
     * handshake/application BOTH arrive in this single call, which is
     * exactly why read/write need separate buffers. */
    if (read_secret) {
        memcpy(be->pending[l].read_secret, read_secret, secret_len);
        be->pending[l].read_secret_len = secret_len;
        be->pending[l].read_pending    = true;
    }
    if (write_secret) {
        memcpy(be->pending[l].write_secret, write_secret, secret_len);
        be->pending[l].write_secret_len = secret_len;
        be->pending[l].write_pending    = true;
    }
    return 1;
}

static int cb_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const uint8_t *data,
                                 size_t len) {
    ql_tls_backend_t *be = backend_of(ssl);
    ql_tls_outbuf_t *ob  = &be->out[map_from_ossl(level)];

    if (ob->len + len > ob->cap) {
        size_t new_cap = (ob->cap ? ob->cap * 2 : 4096);
        while (new_cap < ob->len + len) {
            new_cap *= 2;
        }
        uint8_t *nb = realloc(ob->buf, new_cap);
        if (!nb) {
            return 0;
        }
        ob->buf = nb;
        ob->cap = new_cap;
    }
    memcpy(ob->buf + ob->len, data, len);
    ob->len += len;
    return 1;
}

static int cb_flush_flight(SSL *ssl) {
    (void)ssl;
    return 1; /* no-op: we're not doing our own I/O buffering here */
}

static int cb_send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert) {
    (void)ssl;
    (void)level;
    /* Surface as a fatal error; caller's ql_tls_is_done / next provide_data
     * call will observe SSL_get_error() == SSL_ERROR_SSL and treat it as
     * QL_ERR_CRYPTO_ERROR_BASE + alert (§20.1). Nothing to buffer here. */
    fprintf(stderr, "[ql_tls] peer/local TLS alert: %u\n", alert);
    return 1;
}
/**
 * we declare two layers on purpose:
 * 1. ql_tls_t is a bundle of function ptrs (ql_tls_provide_data_fn,
 * ql_tls_get_data_fn, ...) plus an opaque tls_ctx.
 * this is how we avoid the hard-linking libssl in the header.
 *
 * 2. ql_tls_init/provide_data/get_data/install_keys/handshake_done are the
 * public api the rest of qlite actually call.
 */

static int impl_provide_data(void *tls_ctx, ql_enc_level_t level, const uint8_t *data, size_t len) {
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls_ctx;

    if (SSL_provide_quic_data(be->ssl, map_to_ossl(level), data, len) != 1) {
        return -1;
    }

    /* Drive the state machine forward. In_init lets us call this safely
     * both pre- and post-handshake-completion (post-handshake messages,
     * e.g. NewSessionTicket, also arrive via provide_data). */
    int rc = SSL_do_handshake(be->ssl);
    if (rc != 1) {
        int err = SSL_get_error(be->ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            return -1; /* genuine fatal error, e.g. bad Finished */
        }
    }
    return 0;
}

static int impl_get_data(void *tls_ctx, ql_enc_level_t level, uint8_t *buf, size_t cap) {
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls_ctx;
    ql_tls_outbuf_t *ob  = &be->out[level];

    size_t avail = ob->len - ob->read_off;
    size_t n     = avail < cap ? avail : cap;
    if (n == 0) {
        return 1;
    }

    memcpy(buf, ob->buf + ob->read_off, n);
    ob->read_off += n;

    /* Reclaim space once fully drained so the buffer doesn't grow unbounded
     * across a long connection with repeated key updates / post-hs msgs. */
    if (ob->read_off == ob->len) {
        ob->len      = 0;
        ob->read_off = 0;
    }

    return (int)n;
}

static int impl_set_keys(void *tls_ctx, ql_enc_level_t level, ql_key_pair_t *keys_out) {
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls_ctx;
    int rc               = 0;

    if (level == QL_ENC_LEVEL_INITIAL) {
        *keys_out = be->initial_keys;
        return be->initial_keys.read.is_set && be->initial_keys.write.is_set ? 0 : -1;
    }

    if (be->pending[level].read_pending) {
        const SSL_CIPHER *c = SSL_CIPHER_find(
            be->ssl, (const uint8_t[]){(uint8_t)(be->pending[level].cipher_id >> 8),
                                       (uint8_t)(be->pending[level].cipher_id & 0xFF)});
        rc |= derive_ql_keys(c, be->pending[level].read_secret, be->pending[level].read_secret_len,
                             &keys_out->read);
        be->pending[level].read_pending = false;
    }
    if (be->pending[level].write_pending) {
        const SSL_CIPHER *c = SSL_CIPHER_find(
            be->ssl, (const uint8_t[]){(uint8_t)(be->pending[level].cipher_id >> 8),
                                       (uint8_t)(be->pending[level].cipher_id & 0xFF)});
        rc |= derive_ql_keys(c, be->pending[level].write_secret,
                             be->pending[level].write_secret_len, &keys_out->write);
        be->pending[level].write_pending = false;
    }
    return rc == 0 ? 0 : -1;
}

static bool impl_is_done(void *tls_ctx) {
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls_ctx;
    return SSL_is_init_finished(be->ssl) != 0;
}

static const char *impl_get_alpn(void *tls_ctx) {
    ql_tls_backend_t *be   = (ql_tls_backend_t *)tls_ctx;
    const uint8_t *proto   = NULL;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(be->ssl, &proto, &proto_len);
    if (!proto || proto_len == 0) {
        return NULL;
    }
    /* NB: caller must treat as non-null-terminated if you need exact length;
     * for typical single-ALPN use this is fine as a C string in practice
     * because OpenSSL's internal storage happens to be part of a larger
     * null-terminated buffer, but don't rely on that — copy proto_len bytes. */
    return (const char *)proto;
}

static int impl_set_tp(void *tls_ctx, const uint8_t *tp_buf, size_t tp_len) {
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls_ctx;
    if (tp_len > sizeof(be->local_tp)) {
        return -1;
    }
    memcpy(be->local_tp, tp_buf, tp_len);
    be->local_tp_len = tp_len;
    return SSL_set_quic_transport_params(be->ssl, be->local_tp, be->local_tp_len) == 1 ? 0 : -1;
}

static int impl_get_peer_tp(void *tls_ctx, uint8_t *tp_buf, size_t cap) {
    ql_tls_backend_t *be   = (ql_tls_backend_t *)tls_ctx;
    const uint8_t *peer_tp = NULL;
    size_t peer_tp_len     = 0;
    SSL_get_peer_quic_transport_params(be->ssl, &peer_tp, &peer_tp_len);
    if (!peer_tp || peer_tp_len > cap) {
        return -1;
    }
    memcpy(tp_buf, peer_tp, peer_tp_len);
    return (int)peer_tp_len;
}

/* -------------------------------------------------------------------------
 * ql_tls_init — the one function that actually knows about OpenSSL.
 * `ssl_ctx` is a real SSL_CTX* the caller created and configured
 * (min/max version pinned to TLS 1.3, cert/key loaded for server role,
 * verification mode set, etc.) — qlite doesn't own certificate policy.
 * ------------------------------------------------------------------------- */
int ql_tls_init(ql_tls_t *tls, void *ssl_ctx, ql_role_t role, const uint8_t *client_dcid,
                size_t client_dcid_len) {
    if (!tls || !ssl_ctx || !client_dcid) {
        return -1;
    }

    ql_tls_backend_t *be = calloc(1, sizeof(*be));
    if (!be) {
        return -1;
    }

    be->ssl = SSL_new((SSL_CTX *)ssl_ctx);
    if (!be->ssl) {
        free(be);
        return -1;
    }

    be->role = role;
    SSL_set_app_data(be->ssl, be);
    SSL_set_quic_method(be->ssl, &QL_QUIC_METHOD);

    if (derive_initial_keys(client_dcid, client_dcid_len, role, &be->initial_keys) != 0) {
        SSL_free(be->ssl);
        free(be);
        return -1;
    }

    if (role == QL_ROLE_CLIENT) {
        SSL_set_connect_state(be->ssl);
    } else {
        SSL_set_accept_state(be->ssl);
    }

    tls->tls_ctx      = be;
    tls->provide_data = impl_provide_data;
    tls->get_data     = impl_get_data;
    tls->set_keys     = impl_set_keys;
    tls->is_done      = impl_is_done;
    tls->get_alpn     = impl_get_alpn;
    tls->set_tp       = impl_set_tp;
    tls->get_peer_tp  = impl_get_peer_tp;

    return 0;
}

void ql_tls_free(ql_tls_t *tls) {
    if (!tls || !tls->tls_ctx) {
        return;
    }
    ql_tls_backend_t *be = (ql_tls_backend_t *)tls->tls_ctx;
    SSL_free(be->ssl);
    for (int i = 0; i < QL_ENC_LEVEL_COUNT; i++) {
        free(be->out[i].buf);
    }
    free(be);
    tls->tls_ctx = NULL;
}

/* -------------------------------------------------------------------------
 * Thin public dispatchers — these are what ql_conn_tick() etc. actually
 * call. They don't know anything about OpenSSL; they just forward through
 * whatever ql_tls_init wired up above.
 * ------------------------------------------------------------------------- */
int ql_tls_provide_data(ql_tls_t *tls, ql_enc_level_t level, const uint8_t *data, size_t len) {
    return tls->provide_data(tls->tls_ctx, level, data, len);
}

int ql_tls_get_data(ql_tls_t *tls, ql_enc_level_t level, uint8_t *buf, size_t cap) {
    return tls->get_data(tls->tls_ctx, level, buf, cap);
}

int ql_tls_install_keys(ql_tls_t *tls, ql_enc_level_t level, ql_key_pair_t *keys_out) {
    return tls->set_keys(tls->tls_ctx, level, keys_out);
}

int ql_tls_get_peer_tp(ql_tls_t *tls, uint8_t *buf, size_t cap) {
    return tls->get_peer_tp(tls->tls_ctx, buf, cap);
}

bool ql_tls_handshake_done(const ql_tls_t *tls) {
    return tls->is_done(tls->tls_ctx);
}

/* -------------------------------------------------------------------------
 * ql_crypto_rx_push — CRYPTO frame reassembly (§7.5, chunk 3.3)
 *
 * Call once per received CRYPTO frame at the frame's encryption level.
 * Bytes that extend the in-order run are fed to TLS immediately (3.3.1);
 * bytes that arrive ahead of the expected offset are stashed in the
 * per-level reorder buffer (3.3.2) and drained in order as soon as the
 * gap in front of them closes (3.3.3). Total buffered span beyond
 * QL_CRYPTO_BUF_SIZE is rejected (3.3.4) — the caller should translate
 * that into a CONNECTION_CLOSE with QL_ERR_CRYPTO_BUFFER_EXCEEDED.
 * ------------------------------------------------------------------------- */
int ql_crypto_rx_push(ql_conn_t *conn, ql_enc_level_t level, uint64_t offset, const uint8_t *data,
                      size_t len) {
    if (!conn || level < 0 || level >= QL_ENC_LEVEL_COUNT || (!data && len > 0)) {
        return QLITE_ERR_ARGS;
    }
    if (len == 0) {
        return QLITE_OK;
    }

    ql_crypto_rx_t *rb = &conn->crypto_rx[level];

    uint64_t end = offset + len;
    if (end < offset /* overflow */ || end > QL_CRYPTO_BUF_SIZE) {
        return QLITE_ERR_BUF; /* 3.3.4 overflow guard */
    }

    /* Drop/trim any portion we've already delivered to TLS. */
    uint64_t start = offset;
    if (start < rb->rx_offset) {
        if (end <= rb->rx_offset) {
            return QLITE_OK; /* entirely a duplicate retransmission */
        }
        uint64_t skip = rb->rx_offset - start;
        data += skip;
        len -= (size_t)skip;
        start = rb->rx_offset;
    }

    if (end > rb->highest_offset) {
        rb->highest_offset = end;
    }

    if (start == rb->rx_offset) {
        /* 3.3.1 — in-order fast path: hand straight to TLS. */
        int rc = ql_tls_provide_data(&conn->tls, level, data, len);
        if (rc < 0) {
            return rc;
        }
        rb->rx_offset += len;
    } else {
        /* 3.3.2 — out-of-order: stash bytes, marking each as received. */
        for (size_t i = 0; i < len; i++) {
            uint64_t pos              = start + i;
            rb->buf[pos]               = data[i];
            rb->received[pos / 8]     |= (uint8_t)(1u << (pos % 8));
        }
    }

    /* 3.3.3 — gap-fill flush: drain every contiguous run now available. */
    while (rb->rx_offset < rb->highest_offset) {
        uint64_t pos = rb->rx_offset;
        if (!(rb->received[pos / 8] & (uint8_t)(1u << (pos % 8)))) {
            break; /* still a gap ahead */
        }
        uint64_t run_start = pos;
        while (rb->rx_offset < rb->highest_offset &&
               (rb->received[rb->rx_offset / 8] & (uint8_t)(1u << (rb->rx_offset % 8)))) {
            rb->rx_offset++;
        }
        size_t run_len = (size_t)(rb->rx_offset - run_start);
        int rc = ql_tls_provide_data(&conn->tls, level, rb->buf + run_start, run_len);
        if (rc < 0) {
            return rc;
        }
    }

    return QLITE_OK;
}

/* Long-header type bits <-> encryption level, and enc level -> pn space
 * (RFC 9002 §2: Initial and Handshake each get their own space; 0-RTT and
 * 1-RTT share the Application Data space). */
static ql_pn_space_t ql__level_to_pn_space(ql_enc_level_t level) {
    switch (level) {
        case QL_ENC_LEVEL_INITIAL:   return QL_PN_SPACE_INITIAL;
        case QL_ENC_LEVEL_HANDSHAKE: return QL_PN_SPACE_HANDSHAKE;
        default:                     return QL_PN_SPACE_APP;
    }
}

/*
 * ql__process_frames — walk one packet's decrypted payload, decoding and
 * routing each frame (chunk 7.3.2's per-packet half). CRYPTO frames feed
 * the handshake (chunk 3.3/3.4); most other frame types are fully
 * decodable already but their state-machine effects belong to later
 * phases (streams -> Phase 4, ACK/loss -> Phase 5, paths/keys -> Phase 6)
 * and are left as documented no-ops for now so a payload never fails to
 * parse just because we don't act on it yet.
 */
/* Forward declarations — the stream subsystem (chunk 4.x) and the loss
 * detection / congestion control subsystem (chunk 5.x) are both defined
 * further down the file, but ql__process_frames needs to call into them. */
ql_stream_t *ql_stream_find(ql_conn_t *conn, ql_stream_id_t id);
static ql_stream_t *ql__stream_get_or_create(ql_conn_t *conn, ql_stream_id_t id);
static void ql__stream_apply_reset(ql_stream_t *stream, ql_app_error_t error_code, uint64_t final_size);
int ql_stream_rx_push(ql_conn_t *conn, ql_stream_t *stream, uint64_t offset, const uint8_t *data,
                      size_t len, bool fin);
static void ql__process_ack_frame(ql_conn_t *conn, ql_pn_space_t space, const ql_frame_ack_t *ack,
                                  uint64_t now_ms);
static void ql__ack_record_recv(ql_conn_t *conn, ql_pn_space_t space, ql_pkt_num_t pn,
                                bool ack_eliciting, uint64_t now_ms);
static int ql__send_ack(ql_conn_t *conn, ql_pn_space_t space, ql_enc_level_t level, uint64_t now_ms);
static void ql__set_loss_detection_timer(ql_conn_t *conn, uint64_t now_ms);
static void ql__detect_and_declare_losses(ql_conn_t *conn, ql_pn_space_t space, uint64_t now_ms);
static void ql__on_pto_timeout(ql_conn_t *conn, uint64_t now_ms);
static int ql__key_update_prepare(ql_conn_t *conn);
static void ql__key_update_promote(ql_conn_t *conn, uint64_t now_ms);
static void ql__on_possible_migration(ql_conn_t *conn, const struct sockaddr_storage *src_addr,
                                      socklen_t src_addrlen, uint64_t now_ms);
static void ql__cid_issue_new(ql_conn_t *conn, uint64_t now_ms);

static int ql__process_frames(ql_conn_t *conn, ql_enc_level_t level, const uint8_t *payload,
                              size_t payload_len, uint64_t now_ms,
                              const struct sockaddr_storage *src_addr, socklen_t src_addrlen,
                              bool *out_ack_eliciting) {
    size_t pos          = 0;
    bool ack_eliciting  = false;

    while (pos < payload_len) {
        ql_frame_t frame;
        int n = ql_frame_decode(payload + pos, payload_len - pos, &frame);
        if (n < 0) {
            return n;
        }
        pos += (size_t)n;

        switch (frame.type) {
            case QL_FRAME_PADDING:
                break;

            case QL_FRAME_PING:
                ack_eliciting = true;
                break;

            case QL_FRAME_ACK:
            case QL_FRAME_ACK_ECN:
                /* Not ack-eliciting itself (§13.2.1). */
                ql__process_ack_frame(conn, ql__level_to_pn_space(level), &frame.u.ack, now_ms);
                break;

            case QL_FRAME_CRYPTO: {
                ack_eliciting = true;
                int rc = ql_crypto_rx_push(conn, level, frame.u.crypto.offset, frame.u.crypto.data,
                                           (size_t)frame.u.crypto.length);
                if (rc < 0) {
                    return rc;
                }
                break;
            }

            case QL_FRAME_HANDSHAKE_DONE:
                ack_eliciting = true;
                if (conn->role == QL_ROLE_CLIENT) {
                    conn->handshake_confirmed = true; /* RFC 9001 4.1.2 */
                }
                break;

            case QL_FRAME_CONNECTION_CLOSE:
            case QL_FRAME_CONNECTION_CLOSE_APP:
                /* Full draining-state handling (echo suppression, drain
                 * timer, on_close callback) is chunk 7.2; record enough
                 * here that the tick loop stops sending. */
                conn->closing = true;
                conn->state   = QL_CONN_DRAINING;
                break;

            case QL_FRAME_STREAM:
            case QL_FRAME_STREAM_FIN:
            case QL_FRAME_STREAM_LEN:
            case QL_FRAME_STREAM_LEN_FIN:
            case QL_FRAME_STREAM_OFF:
            case QL_FRAME_STREAM_OFF_FIN:
            case QL_FRAME_STREAM_OFF_LEN:
            case QL_FRAME_STREAM_OFF_LEN_FIN: {
                ack_eliciting = true;
                ql_stream_t *s = ql_stream_find(conn, frame.u.stream.stream_id);
                if (!s) {
                    s = ql__stream_get_or_create(conn, frame.u.stream.stream_id);
                    if (!s) {
                        return QLITE_ERR_PROTO; /* bad stream id / limit violation */
                    }
                    if (conn->cfg.on_stream_open) {
                        conn->cfg.on_stream_open(conn, s, conn->cfg.user);
                    }
                }
                int rc = ql_stream_rx_push(conn, s, frame.u.stream.offset, frame.u.stream.data,
                                           (size_t)frame.u.stream.length, frame.u.stream.fin);
                if (rc < 0) {
                    return rc;
                }
                if (conn->cfg.on_data) {
                    conn->cfg.on_data(conn, s, conn->cfg.user);
                }
                break;
            }

            case QL_FRAME_RESET_STREAM: {
                ack_eliciting = true;
                ql_stream_t *s = ql_stream_find(conn, frame.u.reset_stream.stream_id);
                if (!s) {
                    s = ql__stream_get_or_create(conn, frame.u.reset_stream.stream_id);
                }
                if (s) {
                    ql__stream_apply_reset(s, frame.u.reset_stream.error_code,
                                          frame.u.reset_stream.final_size);
                    if (conn->cfg.on_data) {
                        conn->cfg.on_data(conn, s, conn->cfg.user);
                    }
                }
                break;
            }

            case QL_FRAME_STOP_SENDING: {
                ack_eliciting = true;
                ql_stream_t *s = ql_stream_find(conn, frame.u.stop_sending.stream_id);
                if (s && s->tx_state != QL_TX_STREAM_RESET_SENT &&
                    s->tx_state != QL_TX_STREAM_RESET_RCVD) {
                    /* Actually resetting our send side is triggered by the
                     * app calling qlite_stream_close(); just record the
                     * peer's requested error code and let on_data notify. */
                    s->reset_error_code = frame.u.stop_sending.error_code;
                    if (conn->cfg.on_data) {
                        conn->cfg.on_data(conn, s, conn->cfg.user);
                    }
                }
                break;
            }

            case QL_FRAME_MAX_DATA:
                ack_eliciting = true;
                if (frame.u.max_data.maximum_data > conn->fc.send_limit) {
                    conn->fc.send_limit = frame.u.max_data.maximum_data;
                    conn->fc.send_blocked = false;
                }
                break;

            case QL_FRAME_MAX_STREAM_DATA: {
                ack_eliciting = true;
                ql_stream_t *s = ql_stream_find(conn, frame.u.max_stream_data.stream_id);
                if (s && frame.u.max_stream_data.maximum_stream_data > s->fc.send_limit) {
                    s->fc.send_limit = frame.u.max_stream_data.maximum_stream_data;
                    s->fc.send_blocked = false;
                }
                break;
            }

            case QL_FRAME_MAX_STREAMS_BIDI:
                ack_eliciting = true;
                if (frame.u.max_streams.maximum_streams > conn->max_streams_bidi) {
                    conn->max_streams_bidi = frame.u.max_streams.maximum_streams;
                }
                break;

            case QL_FRAME_MAX_STREAMS_UNI:
                ack_eliciting = true;
                if (frame.u.max_streams.maximum_streams > conn->max_streams_uni) {
                    conn->max_streams_uni = frame.u.max_streams.maximum_streams;
                }
                break;

            case QL_FRAME_DATA_BLOCKED:
            case QL_FRAME_STREAM_DATA_BLOCKED:
            case QL_FRAME_STREAMS_BLOCKED_BIDI:
            case QL_FRAME_STREAMS_BLOCKED_UNI:
                /* Informational (§4.4/4.6/4.8): tells us the peer wanted to
                 * send more than its limit allowed. We don't proactively
                 * raise limits in response yet — periodic FC window updates
                 * (chunk 4.4.3) handle that independently. */
                ack_eliciting = true;
                break;

            case QL_FRAME_NEW_CONNECTION_ID: {
                ack_eliciting = true;
                const ql_frame_new_cid_t *f = &frame.u.new_cid;

                /* Retire anything below retire_prior_to first (§19.15) —
                 * including, per RFC, one we're about to add if its own
                 * sequence number happens to fall below the threshold. */
                for (int i = 0; i < conn->remote_cid_count; i++) {
                    if (!conn->remote_cids[i].is_retired &&
                        conn->remote_cids[i].sequence_num < f->retire_prior_to) {
                        conn->remote_cids[i].is_retired = true;
                        ql_frame_t rf;
                        memset(&rf, 0, sizeof(rf));
                        rf.type                     = QL_FRAME_RETIRE_CONNECTION_ID;
                        rf.u.retire_cid.sequence_num = conn->remote_cids[i].sequence_num;
                        uint8_t rb[16];
                        int rlen = ql_frame_encode(&rf, rb, sizeof(rb));
                        if (rlen >= 0) {
                            ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, rb, (size_t)rlen, true,
                                               QL_RETX_FLAG_RETIRE_CID, now_ms, NULL);
                        }
                    }
                }

                bool already_known = false;
                for (int i = 0; i < conn->remote_cid_count; i++) {
                    if (conn->remote_cids[i].sequence_num == f->sequence_num) {
                        already_known = true;
                        break;
                    }
                }
                if (!already_known && f->sequence_num >= f->retire_prior_to &&
                    conn->remote_cid_count < QL_MAX_CIDS) {
                    ql_cid_entry_t *e   = &conn->remote_cids[conn->remote_cid_count++];
                    e->cid              = f->cid;
                    e->sequence_num     = f->sequence_num;
                    e->retire_prior_to  = f->retire_prior_to;
                    e->reset_token      = f->stateless_reset_token;
                    e->is_active        = false;
                    e->is_retired       = false;
                }
                break;
            }

            case QL_FRAME_RETIRE_CONNECTION_ID: {
                ack_eliciting = true;
                uint64_t seq = frame.u.retire_cid.sequence_num;
                for (int i = 0; i < conn->local_cid_count; i++) {
                    if (conn->local_cids[i].sequence_num == seq) {
                        conn->local_cids[i].is_retired = true;
                        conn->local_cids[i].is_active  = false;
                        break;
                    }
                }
                break;
            }

            case QL_FRAME_PATH_CHALLENGE: {
                ack_eliciting = true;
                /* §8.2.2 — MUST echo the data back, on the path the
                 * challenge arrived on (which may not be the active path
                 * yet if this is itself part of a migration probe). */
                ql_frame_t rf;
                memset(&rf, 0, sizeof(rf));
                rf.type            = QL_FRAME_PATH_RESPONSE;
                rf.u.path_response.data = frame.u.path_challenge.data;
                uint8_t rb[16];
                int rlen = ql_frame_encode(&rf, rb, sizeof(rb));
                if (rlen >= 0 && src_addr) {
                    ql__send_level_pkt_to(conn, QL_ENC_LEVEL_APP, rb, (size_t)rlen, true,
                                          QL_RETX_FLAG_PATH_CHALLENGE, now_ms, src_addr, src_addrlen,
                                          NULL);
                }
                break;
            }

            case QL_FRAME_PATH_RESPONSE: {
                ack_eliciting = true;
                /* §8.2.3 — only meaningful if it matches a challenge we
                 * actually sent for the path currently being probed. */
                if (conn->probing_path.state == QL_PATH_PROBING &&
                    memcmp(frame.u.path_response.data.data, conn->probing_path.challenge_data.data,
                          QL_PATH_DATA_LEN) == 0) {
                    conn->probing_path.state = QL_PATH_VALIDATED;
                    ql_path_t validated       = conn->probing_path;
                    conn->active_path         = validated;
                    conn->migration_in_progress = false;
                    /* A fresh path starts unvalidated for amplification
                     * purposes on the SERVER side; only relevant pre-1RTT
                     * in practice, but reset the counters for hygiene. */
                    if (conn->cfg.on_migrate) {
                        conn->cfg.on_migrate(conn, &conn->active_path, conn->cfg.user);
                    }
                    memset(&conn->probing_path, 0, sizeof(conn->probing_path));
                }
                break;
            }

            default:
                /* Key-update frames have no wire representation of their
                 * own (handled via the short-header key_phase bit, chunk
                 * 6.4) — nothing else falls through here. Ack-eliciting
                 * per §13.2. */
                ack_eliciting = true;
                break;
        }
    }

    if (out_ack_eliciting) {
        *out_ack_eliciting = ack_eliciting;
    }
    return (int)pos;
}

/*
 * ql__send_level_pkt — encrypt `payload` as one packet at `level`, enqueue
 * the resulting datagram, and record sent-packet bookkeeping that later
 * phases (retransmission, congestion control) will build on.
 */
static int ql__send_level_pkt_to(ql_conn_t *conn, ql_enc_level_t level, const uint8_t *payload,
                                 size_t payload_len, bool ack_eliciting, uint32_t frame_flags,
                                 uint64_t now_ms, const struct sockaddr_storage *dest,
                                 socklen_t dest_len, int *out_idx) {
    ql_keys_t *wk = &conn->keys[level].write;
    if (!wk->is_set) {
        return QLITE_ERR_CRYPTO;
    }
    if (conn->send_queue.count >= QL_MAX_COALESCE_PKTS) {
        return QLITE_ERR_BUF;
    }

    /* 3.6.2 — anti-amplification gate: a server that hasn't validated the
     * client's address may not send more than 3x what it has received. */
    if (conn->role == QL_ROLE_SERVER && !conn->addr_valid.validated) {
        uint64_t budget = conn->addr_valid.bytes_received * QL_AMPLIFICATION_FACTOR;
        if (conn->addr_valid.bytes_sent + payload_len + QL_AEAD_TAG_LEN + 64 > budget) {
            return QLITE_ERR_WOULDBLOCK;
        }
    }

    ql_pn_space_t space  = ql__level_to_pn_space(level);
    ql_pkt_num_t pn      = conn->next_pn[space];

    ql_pkt_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    if (level == QL_ENC_LEVEL_APP) {
        hdr.is_long          = false;
        ql_short_hdr_t *sh   = &hdr.h.shdr;
        sh->first_byte       = QL_SHORT_HDR_FIXED_BIT | (conn->spin_bit ? QL_SHORT_HDR_SPIN_BIT : 0) |
                          (conn->key_update.current_phase ? QL_SHORT_HDR_KEY_PHASE : 0);
        sh->dst_cid = conn->remote_cid;
        sh->pkt_num = pn;
    } else {
        hdr.is_long        = true;
        ql_long_hdr_t *lh  = &hdr.h.lhdr;
        uint8_t type_bits;
        switch (level) {
            case QL_ENC_LEVEL_INITIAL:   lh->pkt_type = QL_PKT_INITIAL;   type_bits = 0; break;
            case QL_ENC_LEVEL_EARLY_DATA: lh->pkt_type = QL_PKT_0RTT;      type_bits = 1; break;
            case QL_ENC_LEVEL_HANDSHAKE: lh->pkt_type = QL_PKT_HANDSHAKE; type_bits = 2; break;
            default: return QLITE_ERR_ARGS;
        }
        lh->first_byte = (uint8_t)(QL_LONG_HDR_FORM | QL_LONG_HDR_FIXED_BIT |
                                   (type_bits << QL_LONG_HDR_TYPE_SHIFT));
        lh->version = QL_VERSION_1;
        lh->dst_cid = conn->remote_cid;
        lh->src_cid = conn->local_cid;
        lh->pkt_num = pn;
        if (lh->pkt_type == QL_PKT_INITIAL && conn->token.len > 0) {
            memcpy(lh->token, conn->token.data, conn->token.len);
            lh->token_len = conn->token.len;
        }
    }

    uint8_t out_buf[QL_PATH_MTU_ETHERNET + 64];
    int n = ql_pkt_encode(&hdr, wk, payload, payload_len, out_buf, sizeof(out_buf));
    if (n < 0) {
        return n;
    }

    ql_datagram_t *dg = &conn->send_queue.datagrams[conn->send_queue.tail];
    memcpy(dg->data, out_buf, (size_t)n);
    dg->len      = (size_t)n;
    dg->dest     = *dest;
    dg->dest_len = dest_len;
    conn->send_queue.tail = (conn->send_queue.tail + 1) % QL_MAX_COALESCE_PKTS;
    conn->send_queue.count++;

    conn->next_pn[space] = pn + 1;

    int idx                              = conn->sent_pkt_tail;
    conn->sent_pkts[idx].pkt_num         = pn;
    conn->sent_pkts[idx].pn_space        = space;
    conn->sent_pkts[idx].sent_at_ms      = now_ms;
    conn->sent_pkts[idx].in_flight_bytes = (size_t)n;
    conn->sent_pkts[idx].ack_eliciting   = ack_eliciting;
    conn->sent_pkts[idx].in_flight       = ack_eliciting;
    conn->sent_pkts[idx].is_lost         = false;
    conn->sent_pkts[idx].is_acked        = false;
    conn->sent_pkts[idx].frame_flags     = frame_flags;
    conn->sent_pkt_tail                  = (conn->sent_pkt_tail + 1) % QL_SENT_PKT_MAX;
    if (conn->sent_pkt_count < QL_SENT_PKT_MAX) {
        conn->sent_pkt_count++;
    }else{
        /* Ring is full: the slot we just overwrote (== old head) is now
         * the newest entry, so the true oldest entry moved forward one. */
        conn->sent_pkt_head = (conn->sent_pkt_head + 1) % QL_SENT_PKT_MAX;
    }

    conn->bytes_sent_total += (uint64_t)n;
    conn->pkts_sent++;
    conn->addr_valid.bytes_sent += (uint64_t)n;

    if (out_idx) {
        *out_idx = idx;
    }

    return n;
}

/* Thin wrapper: sends to the currently active path, as almost every caller
 * wants. ql__send_level_pkt_to exists for path validation / migration
 * probes (chunk 6.2/6.3), which must target a not-yet-active address. */
static int ql__send_level_pkt(ql_conn_t *conn, ql_enc_level_t level, const uint8_t *payload,
                              size_t payload_len, bool ack_eliciting, uint32_t frame_flags,
                              uint64_t now_ms, int *out_idx) {
    return ql__send_level_pkt_to(conn, level, payload, payload_len, ack_eliciting, frame_flags,
                                 now_ms, &conn->active_path.peer_addr, conn->active_path.peer_addrlen,
                                 out_idx);
}

/* -------------------------------------------------------------------------
 * ql_conn_tick — the glue loop (chunk 7.3). Each call:
 *   1. drains any inbound datagrams and dispatches their frames,
 *   2. pumps the TLS engine (get_data / install_keys, as before),
 *   3. flushes any newly-staged CRYPTO bytes out as packets,
 *   4. advances connection state and fires callbacks,
 *   5. flushes the outbound datagram queue to the socket.
 * Loss detection, ACK emission, and stream scheduling are later phases
 * and are not yet driven from here.
 * ------------------------------------------------------------------------- */
int ql_conn_tick(ql_conn_t *conn, uint64_t now_ms) {
    if (!conn) {
        return QLITE_ERR_ARGS;
    }

    /* ---- 1. Inbound datagrams (7.3.1 / 7.3.2) ---- */
    if (conn->fd >= 0) {
        uint8_t rx_buf[QL_PATH_MTU_ETHERNET + 64];
        uint8_t rx_payload[QL_PATH_MTU_ETHERNET + 64];

        for (;;) {
            struct sockaddr_storage rx_from;
            socklen_t rx_fromlen = sizeof(rx_from);

            int rn = ql_udp_recv(conn->fd, rx_buf, sizeof(rx_buf), &rx_from, &rx_fromlen);
            if (rn == QLITE_ERR_WOULDBLOCK) {
                break;
            }
            if (rn < 0) {
                return rn;
            }
            if (rn < 1) {
                continue;
            }

            conn->bytes_received_total += (uint64_t)rn;
            conn->pkts_received++;
            conn->addr_valid.bytes_received += (uint64_t)rn; /* 3.6.1 */

            uint8_t first  = rx_buf[0];
            bool is_long   = QL_PKT_IS_LONG(first);
            ql_enc_level_t level;

            if (is_long) {
                if (rn < 5) {
                    continue;
                }
                uint32_t ver = ((uint32_t)rx_buf[1] << 24) | ((uint32_t)rx_buf[2] << 16) |
                               ((uint32_t)rx_buf[3] << 8) | (uint32_t)rx_buf[4];
                if (ver == QL_VERSION_NEGOTIATION) {
                    /* Chunk 3.5.5 — parsed but not yet surfaced to the
                     * caller / used to abort the connection. */
                    ql_ver_neg_pkt_t vn;
                    ql_vn_decode(rx_buf, (size_t)rn, &vn);
                    continue;
                }
                uint8_t type_bits =
                    (uint8_t)((first & QL_LONG_HDR_TYPE_MASK) >> QL_LONG_HDR_TYPE_SHIFT);
                switch (type_bits) {
                    case 0: level = QL_ENC_LEVEL_INITIAL; break;
                    case 1: level = QL_ENC_LEVEL_EARLY_DATA; break;
                    case 2: level = QL_ENC_LEVEL_HANDSHAKE; break;
                    default:
                        /* Retry — chunks 2.4/3.5.1-3.5.3 not yet wired
                         * into the tick loop. */
                        continue;
                }
            } else {
                level = QL_ENC_LEVEL_APP;
            }

            ql_keys_t *rk = &conn->keys[level].read;
            if (!rk->is_set) {
                continue; /* can't decrypt this level (yet, or ever) */
            }

            ql_pkt_hdr_t hdr;
            memset(&hdr, 0, sizeof(hdr));
            if (!is_long) {
                /* ql_pkt_decode's short-header convention: caller supplies
                 * the expected DCID length before calling. */
                hdr.h.shdr.dst_cid.len = conn->local_cid.len;
            }

            int dn = ql_pkt_decode(rx_buf, (size_t)rn, rk, &hdr, rx_payload, sizeof(rx_payload));
            if (dn < 0 && level == QL_ENC_LEVEL_APP &&
                hdr.h.shdr.key_phase != conn->key_update.current_phase) {
                /* RFC 9001 §6.3/6.4 — a key_phase mismatch survived header
                 * protection removal (which uses a phase-invariant key), so
                 * this may genuinely be a peer-initiated update rather than
                 * corruption. Prepare the other generation if we haven't
                 * already, promote to it, and retry once. */
                if (ql__key_update_prepare(conn) == 0) {
                    ql__key_update_promote(conn, now_ms);
                    dn = ql_pkt_decode(rx_buf, (size_t)rn, &conn->keys[level].read, &hdr, rx_payload,
                                       sizeof(rx_payload));
                }
            }
            if (dn < 0) {
                continue; /* drop malformed/undecryptable datagram, §12.2 */
            }

            ql_pn_space_t space = ql__level_to_pn_space(level);
            ql_pkt_num_t pn     = is_long ? hdr.h.lhdr.pkt_num : hdr.h.shdr.pkt_num;
            if (conn->largest_recvd[space] == QL_PKT_NUM_NONE || pn > conn->largest_recvd[space]) {
                conn->largest_recvd[space] = pn;
            }

            if (level == QL_ENC_LEVEL_HANDSHAKE) {
                conn->addr_valid.validated = true; /* 3.6.3 */
            }

            if (level == QL_ENC_LEVEL_APP && conn->cfg.enable_migration) {
                bool same_addr = (rx_fromlen == conn->active_path.peer_addrlen) &&
                                 memcmp(&rx_from, &conn->active_path.peer_addr, rx_fromlen) == 0;
                if (!same_addr) {
                    /* AEAD auth already succeeded above, so this is either a
                     * genuine migration or an attacker who already holds
                     * our session keys (i.e. not a threat this check can
                     * add anything against) — safe to start validating it. */
                    ql__on_possible_migration(conn, &rx_from, rx_fromlen, now_ms);
                }
            }

            if (is_long && level == QL_ENC_LEVEL_INITIAL && conn->role == QL_ROLE_CLIENT &&
                hdr.h.lhdr.src_cid.len > 0) {
                /* Learn the server's chosen SCID (§7.2) so our next packet
                 * addresses it correctly. */
                conn->remote_cid = hdr.h.lhdr.src_cid;
            }

            bool ack_eliciting = false;
            int prc = ql__process_frames(conn, level, hdr.payload, hdr.payload_len, now_ms, &rx_from,
                                         rx_fromlen, &ack_eliciting);
            if (prc < 0) {
                continue; /* malformed frame payload; drop the datagram */
            }
            ql__ack_record_recv(conn, space, pn, ack_eliciting, now_ms);
        }
    }

    /* ---- 2. TLS progress: drain outbound bytes, install keys ---- */
    if (!conn->remote_tp_rcvd) {
        uint8_t tp_buf[1024];
        int tpn = ql_tls_get_peer_tp(&conn->tls, tp_buf, sizeof(tp_buf));
        if (tpn > 0) {
            ql_transport_params_t parsed;
            if (ql_tp_decode(tp_buf, (size_t)tpn, &parsed) >= 0) {
                conn->remote_tp        = parsed;
                conn->remote_tp_rcvd   = true;
                conn->max_streams_bidi = parsed.initial_max_streams_bidi;
                conn->max_streams_uni  = parsed.initial_max_streams_uni;
                conn->fc.send_limit    = parsed.initial_max_data;
            }
        }
    }

    for (int lvl = 0; lvl < QL_ENC_LEVEL_COUNT; lvl++) {
        ql_enc_level_t level = (ql_enc_level_t)lvl;
        ql_crypto_buf_t *cb  = &conn->crypto[level];

        for (;;) {
            size_t used  = cb->has_data ? (size_t)(cb->tx_offset % sizeof(cb->buf)) : 0;
            size_t avail = sizeof(cb->buf) - used;
            if (avail == 0) {
                break;
            }

            int n = ql_tls_get_data(&conn->tls, level, cb->buf + used, avail);
            if (n < 0) {
                return QLITE_ERR_CRYPTO;
            }
            if (n == 0) {
                break;
            }

            cb->tx_offset += (uint64_t)n;
            cb->has_data = true;

            if ((size_t)n < avail) {
                break;
            }
        }

        ql_key_pair_t *slot     = &conn->keys[level];
        bool already_installed = slot->read.is_set && slot->write.is_set;

        if (!already_installed) {
            ql_key_pair_t derived;
            memset(&derived, 0, sizeof(derived));

            int rc = ql_tls_install_keys(&conn->tls, level, &derived);
            if (rc == 0 && derived.read.is_set && derived.write.is_set) {
                conn->keys[level] = derived;
            }
        }
    }

    /* ---- 3. Outbound CRYPTO flush ---- */
    for (int lvl = 0; lvl < QL_ENC_LEVEL_COUNT; lvl++) {
        ql_enc_level_t level = (ql_enc_level_t)lvl;
        if (level == QL_ENC_LEVEL_EARLY_DATA) {
            continue; /* 0-RTT send path explicitly out of scope */
        }
        ql_crypto_buf_t *cb = &conn->crypto[level];
        if (!conn->keys[level].write.is_set) {
            continue;
        }
        if (cb->tx_offset <= cb->tx_sent_offset) {
            continue;
        }

        uint64_t send_off  = cb->tx_sent_offset;
        size_t avail        = (size_t)(cb->tx_offset - send_off);
        size_t start_pos    = (size_t)(send_off % sizeof(cb->buf));
        size_t chunk         = sizeof(cb->buf) - start_pos; /* don't wrap mid-memcpy */
        if (chunk > avail) {
            chunk = avail;
        }
        size_t max_frame = QL_PATH_MTU_ETHERNET - 96; /* headroom for hdr + frame overhead */
        if (chunk > max_frame) {
            chunk = max_frame;
        }
        if (chunk == 0) {
            continue;
        }

        ql_frame_t f;
        memset(&f, 0, sizeof(f));
        f.type            = QL_FRAME_CRYPTO;
        f.u.crypto.offset = send_off;
        f.u.crypto.length = chunk;
        f.u.crypto.data   = cb->buf + start_pos;

        uint8_t payload[QL_PATH_MTU_ETHERNET + 64];
        int flen = ql_frame_encode(&f, payload, sizeof(payload));
        if (flen < 0) {
            continue;
        }
        size_t payload_len = (size_t)flen;

        /* §14.1 — client's Initial datagrams must reach 1200 bytes. Pad
         * the frame payload itself, since one packet == one datagram here. */
        if (level == QL_ENC_LEVEL_INITIAL && conn->role == QL_ROLE_CLIENT) {
            size_t min_payload = (QL_MIN_INITIAL_DATAGRAM_SIZE > 64)
                                     ? (QL_MIN_INITIAL_DATAGRAM_SIZE - 64)
                                     : 0;
            if (payload_len < min_payload && min_payload <= sizeof(payload)) {
                memset(payload + payload_len, 0x00, min_payload - payload_len);
                payload_len = min_payload;
            }
        }

        int sent_idx = -1;
        int sn = ql__send_level_pkt(conn, level, payload, payload_len, true, QL_RETX_FLAG_CRYPTO,
                                    now_ms, &sent_idx);
        if (sn >= 0) {
            cb->tx_sent_offset = send_off + chunk;
            if (sent_idx >= 0) {
                conn->sent_pkts[sent_idx].crypto_level  = level;
                conn->sent_pkts[sent_idx].crypto_offset = send_off;
                conn->sent_pkts[sent_idx].crypto_len    = chunk;
            }
        }
        /* On failure (amplification-limited, queue full, keys not ready)
         * we simply retry next tick; tx_sent_offset is left untouched. */
    }

    /* ---- 3b. Outbound STREAM flush + flow-control window updates (4.2, 4.4.3, 4.4.4) ---- */
    if (conn->keys[QL_ENC_LEVEL_APP].write.is_set) {
        for (ql_stream_t *s = conn->stream_list; s; s = s->next) {
            uint64_t buffered = s->tx_head - s->tx_tail;
            /* qlite_stream_close(conn, s, 0) records the FIN point by
             * setting fc.final_size_known/fc.final_size at the current
             * tx_head; once tx_tail catches up to it, emit FIN. */
            bool wants_fin = (s->tx_state == QL_TX_STREAM_READY || s->tx_state == QL_TX_STREAM_SEND) &&
                             s->fc.final_size_known && s->tx_tail + buffered >= s->fc.final_size;

            if (buffered > 0 || wants_fin) {
                uint64_t stream_room =
                    (s->fc.send_limit > s->fc.send_offset) ? s->fc.send_limit - s->fc.send_offset : 0;
                uint64_t conn_room = (conn->fc.send_limit > conn->fc.send_offset)
                                         ? conn->fc.send_limit - conn->fc.send_offset
                                         : 0;
                uint64_t room       = stream_room < conn_room ? stream_room : conn_room;
                size_t send_len     = (size_t)(buffered < room ? buffered : room);
                bool blocked_by_fc  = send_len < buffered;

                size_t max_frame = QL_PATH_MTU_ETHERNET - 96;
                if (send_len > max_frame) {
                    send_len = max_frame;
                    blocked_by_fc = false; /* limited by packet size, not FC */
                }

                if (send_len > 0 || (wants_fin && buffered == 0)) {
                    uint8_t chunk_buf[QL_PATH_MTU_ETHERNET + 64];
                    for (size_t i = 0; i < send_len; i++) {
                        chunk_buf[i] = s->tx_buf[(size_t)((s->tx_tail + i) % QL_STREAM_BUF_SIZE)];
                    }

                    bool fin_here = wants_fin && (s->tx_tail + send_len >= s->fc.final_size);

                    ql_frame_t f;
                    memset(&f, 0, sizeof(f));
                    f.type                = QL_FRAME_STREAM;
                    f.u.stream.stream_id  = s->id;
                    f.u.stream.offset     = s->tx_tail;
                    f.u.stream.has_offset = (s->tx_tail != 0);
                    f.u.stream.length     = send_len;
                    f.u.stream.has_length = true;
                    f.u.stream.data       = chunk_buf;
                    f.u.stream.fin        = fin_here;

                    uint8_t frame_buf[QL_PATH_MTU_ETHERNET + 64];
                    int flen = ql_frame_encode(&f, frame_buf, sizeof(frame_buf));
                    if (flen >= 0) {
                        int sent_idx = -1;
                        int ssn = ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, frame_buf,
                                                     (size_t)flen, true, QL_RETX_FLAG_STREAM, now_ms, &sent_idx);
                        if (ssn >= 0) {
                            if (sent_idx >= 0) {
                                conn->sent_pkts[sent_idx].stream_id     = s->id;
                                conn->sent_pkts[sent_idx].stream_offset = s->tx_tail;
                                conn->sent_pkts[sent_idx].stream_len    = send_len;
                                conn->sent_pkts[sent_idx].stream_fin    = fin_here;
                            }

                            /* fc.send_offset is a high-water mark (highest
                             * offset ever transmitted), not a cumulative
                             * counter — retransmissions re-declare bytes
                             * already inside that mark and must not spend
                             * flow-control budget a second time. */
                            uint64_t frame_end_off = s->tx_tail + send_len;
                            s->tx_tail = frame_end_off;
                            if (frame_end_off > s->fc.send_offset) {
                                uint64_t new_bytes = frame_end_off - s->fc.send_offset;
                                conn->fc.send_offset += new_bytes;
                                s->fc.send_offset = frame_end_off;
                            }
                            if (s->tx_state == QL_TX_STREAM_READY) {
                                s->tx_state = QL_TX_STREAM_SEND;
                            }
                            if (fin_here) {
                                s->tx_state = QL_TX_STREAM_DATA_SENT;
                            }
                        }
                    }
                }

                if (blocked_by_fc) {
                    bool stream_is_bottleneck = stream_room < conn_room;
                    if (stream_is_bottleneck && (!s->fc.send_blocked || s->fc.blocked_at != s->fc.send_limit)) {
                        ql_frame_t bf;
                        memset(&bf, 0, sizeof(bf));
                        bf.type                             = QL_FRAME_STREAM_DATA_BLOCKED;
                        bf.u.stream_data_blocked.stream_id   = s->id;
                        bf.u.stream_data_blocked.stream_data_limit = s->fc.send_limit;
                        uint8_t bb[32];
                        int blen = ql_frame_encode(&bf, bb, sizeof(bb));
                        if (blen >= 0 && ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, bb, (size_t)blen,
                                                            true, QL_RETX_FLAG_STREAM, now_ms, NULL) >= 0) {
                            s->fc.send_blocked = true;
                            s->fc.blocked_at   = s->fc.send_limit;
                        }
                    } else if (!stream_is_bottleneck &&
                              (!conn->fc.send_blocked || conn->fc.blocked_at != conn->fc.send_limit)) {
                        ql_frame_t bf;
                        memset(&bf, 0, sizeof(bf));
                        bf.type                    = QL_FRAME_DATA_BLOCKED;
                        bf.u.data_blocked.data_limit = conn->fc.send_limit;
                        uint8_t bb[16];
                        int blen = ql_frame_encode(&bf, bb, sizeof(bb));
                        if (blen >= 0 && ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, bb, (size_t)blen,
                                                            true, QL_RETX_FLAG_STREAM, now_ms, NULL) >= 0) {
                            conn->fc.send_blocked = true;
                            conn->fc.blocked_at   = conn->fc.send_limit;
                        }
                    }
                }
            }

            /* Receive-side per-stream window update: extend once the app
             * has consumed roughly half of the currently-advertised limit. */
            if (s->fc.recv_limit > (uint64_t)(QL_STREAM_BUF_SIZE / 2) &&
                s->fc.recv_consumed >= s->fc.recv_limit - QL_STREAM_BUF_SIZE / 2 &&
                s->rx_state != QL_RX_STREAM_RESET_RCVD && s->rx_state != QL_RX_STREAM_RESET_READ) {
                uint64_t new_limit = s->fc.recv_consumed + QL_STREAM_BUF_SIZE;
                if (new_limit > s->fc.recv_limit) {
                    ql_frame_t mf;
                    memset(&mf, 0, sizeof(mf));
                    mf.type                                = QL_FRAME_MAX_STREAM_DATA;
                    mf.u.max_stream_data.stream_id          = s->id;
                    mf.u.max_stream_data.maximum_stream_data = new_limit;
                    uint8_t mb[24];
                    int mlen = ql_frame_encode(&mf, mb, sizeof(mb));
                    if (mlen >= 0 && ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, mb, (size_t)mlen,
                                                        true, QL_RETX_FLAG_MAX_STREAM_DATA,
                                                        now_ms, NULL) >= 0) {
                        s->fc.recv_limit = new_limit;
                    }
                }
            }
        }

        /* Connection-level receive-side window update. */
        if (conn->fc.recv_limit > (uint64_t)(QL_CONN_FC_WINDOW_DEFAULT / 2) &&
            conn->fc.recv_consumed >= conn->fc.recv_limit - QL_CONN_FC_WINDOW_DEFAULT / 2) {
            uint64_t new_limit = conn->fc.recv_consumed + QL_CONN_FC_WINDOW_DEFAULT;
            if (new_limit > conn->fc.recv_limit) {
                ql_frame_t mf;
                memset(&mf, 0, sizeof(mf));
                mf.type                 = QL_FRAME_MAX_DATA;
                mf.u.max_data.maximum_data = new_limit;
                uint8_t mb[16];
                int mlen = ql_frame_encode(&mf, mb, sizeof(mb));
                if (mlen >= 0 && ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, mb, (size_t)mlen, true,
                                                    QL_RETX_FLAG_MAX_DATA, now_ms, NULL) >= 0) {
                    conn->fc.recv_limit = new_limit;
                }
            }
        }
    }

    /* ---- 3c. CID housekeeping (chunk 6.1) ---- */
    if (conn->keys[QL_ENC_LEVEL_APP].write.is_set) {
        ql__cid_issue_new(conn, now_ms);
    }

    /* ---- 4. Handshake completion / state transitions ---- */
    if (ql_tls_handshake_done(&conn->tls)) {
        conn->handshake_complete = true;
    }

    if (conn->role == QL_ROLE_SERVER && conn->handshake_complete && !conn->handshake_confirmed &&
        conn->keys[QL_ENC_LEVEL_APP].write.is_set) {
        ql_frame_t f;
        memset(&f, 0, sizeof(f));
        f.type = QL_FRAME_HANDSHAKE_DONE;
        uint8_t fb[8];
        int flen = ql_frame_encode(&f, fb, sizeof(fb));
        if (flen >= 0) {
            int sn = ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, fb, (size_t)flen, true,
                                        QL_RETX_FLAG_HANDSHAKE_DONE, now_ms, NULL);
            if (sn >= 0) {
                conn->handshake_confirmed = true; /* RFC 9001 4.1.2 */
            }
        }
    }

    /* RFC 9001 4.9.1 — Initial keys are no longer needed once Handshake
     * keys are installed. */
    if (conn->keys[QL_ENC_LEVEL_HANDSHAKE].read.is_set &&
        conn->keys[QL_ENC_LEVEL_HANDSHAKE].write.is_set && conn->keys[QL_ENC_LEVEL_INITIAL].read.is_set) {
        memset(&conn->keys[QL_ENC_LEVEL_INITIAL], 0, sizeof(conn->keys[QL_ENC_LEVEL_INITIAL]));
    }

    bool confirmed = (conn->role == QL_ROLE_SERVER)
                          ? conn->handshake_confirmed
                          : (conn->handshake_complete && conn->handshake_confirmed);

    if (confirmed && conn->state != QL_CONN_CONNECTED) {
        conn->state = QL_CONN_CONNECTED;
        /* RFC 9001 4.9.2 — Handshake keys are discarded once the
         * handshake is confirmed. */
        memset(&conn->keys[QL_ENC_LEVEL_HANDSHAKE], 0, sizeof(conn->keys[QL_ENC_LEVEL_HANDSHAKE]));
        if (conn->cfg.on_connected) {
            conn->cfg.on_connected(conn, conn->cfg.user);
        }
    } else if (conn->state == QL_CONN_INITIAL && conn->keys[QL_ENC_LEVEL_HANDSHAKE].write.is_set) {
        conn->state = QL_CONN_HANDSHAKE;
    }

    /* ---- 4b. Outbound ACK flush (chunk 5.1.2) ---- */
    for (int i = 0; i < QL_PN_SPACE_COUNT; i++) {
        ql_pn_space_t space = (ql_pn_space_t)i;
        ql_ack_state_t *a   = &conn->ack[space];
        if (!a->needs_ack || now_ms < a->ack_send_deadline_ms) {
            continue;
        }
        ql_enc_level_t level = (space == QL_PN_SPACE_INITIAL)   ? QL_ENC_LEVEL_INITIAL
                              : (space == QL_PN_SPACE_HANDSHAKE) ? QL_ENC_LEVEL_HANDSHAKE
                                                                  : QL_ENC_LEVEL_APP;
        ql__send_ack(conn, space, level, now_ms);
    }

    /* ---- 4c. PTO timer (chunk 5.3) ---- */
    ql__set_loss_detection_timer(conn, now_ms);
    if (conn->cc.pto_deadline_ms != 0 && now_ms >= conn->cc.pto_deadline_ms) {
        /* Distinguish "a loss-time deadline fired" from "a genuine PTO":
         * ql__set_loss_detection_timer prioritizes loss_time, and
         * ql__detect_and_declare_losses recomputes it — calling that first
         * resolves anything that was actually a loss rather than a probe. */
        for (int i = 0; i < QL_PN_SPACE_COUNT; i++) {
            ql__detect_and_declare_losses(conn, (ql_pn_space_t)i, now_ms);
        }
        ql__set_loss_detection_timer(conn, now_ms);
        if (conn->cc.pto_deadline_ms != 0 && now_ms >= conn->cc.pto_deadline_ms) {
            ql__on_pto_timeout(conn, now_ms);
            ql__set_loss_detection_timer(conn, now_ms);
        }
    }

    /* ---- 5. Flush outbound queue to the socket ---- */
    if (conn->fd >= 0) {
        while (conn->send_queue.count > 0) {
            ql_datagram_t *dg = &conn->send_queue.datagrams[conn->send_queue.head];
            int sn = ql_udp_send(conn->fd, (struct sockaddr *)&dg->dest, dg->dest_len, dg->data,
                                 dg->len);
            if (sn == QLITE_ERR_WOULDBLOCK) {
                break; /* leave the rest queued for next tick */
            }
            conn->send_queue.head  = (conn->send_queue.head + 1) % QL_MAX_COALESCE_PKTS;
            conn->send_queue.count--;
        }
    }

    return QLITE_OK;
}

/* -------------------------------------------------------------------------
 * qlite_connect — client-side connection bootstrap (chunk 3.4.1).
 *
 * Opens the UDP socket, picks a random Initial DCID (used to both derive
 * Initial keys and address the first packet, per RFC 9001 5.2), wires up
 * the TLS engine, and moves the connection to QL_CONN_INITIAL. The actual
 * ClientHello is produced and sent by the next ql_conn_tick() call.
 * IPv4 only for now; ssl_ctx is an `SSL_CTX *` already configured by the
 * caller with certs/ALPN/etc — qlite doesn't own certificate policy.
 * ------------------------------------------------------------------------- */
int qlite_connect(ql_conn_t *conn, const char *peer_addr, uint16_t peer_port, void *ssl_ctx) {
    if (!conn || !peer_addr || !ssl_ctx) {
        return QLITE_ERR_ARGS;
    }
    if (conn->role != QL_ROLE_CLIENT) {
        return QLITE_ERR_ARGS;
    }
    if (conn->state != QL_CONN_IDLE) {
        return QLITE_ERR_CLOSED;
    }

    int fd = ql_udp_socket(NULL, 0);
    if (fd < 0) {
        return fd;
    }
    conn->fd = fd;

    struct sockaddr_in *sin = (struct sockaddr_in *)&conn->active_path.peer_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port   = htons(peer_port);
    if (inet_pton(AF_INET, peer_addr, &sin->sin_addr) != 1) {
        return QLITE_ERR_ARGS;
    }
    conn->active_path.peer_addrlen = sizeof(*sin);
    conn->active_path.mtu          = QL_PATH_MTU_DEFAULT;
    conn->active_path.state        = QL_PATH_VALIDATED; /* our own outbound path, assumed usable */

    /* RFC 9001 5.2 — client picks a random (>= 8 byte recommended) DCID
     * for its first Initial; both sides derive Initial keys from it. */
    ql_cid_generate(&conn->remote_cid, QL_CID_MAX_LEN);
    if (conn->remote_cid.len == 0) {
        return QLITE_ERR_INTERNAL;
    }

    if (ql_tls_init(&conn->tls, ssl_ctx, QL_ROLE_CLIENT, conn->remote_cid.data,
                    conn->remote_cid.len) != 0) {
        return QLITE_ERR_CRYPTO;
    }

    conn->state = QL_CONN_INITIAL;
    return QLITE_OK;
}

/*
 * ql_new / ql_del — the project's single allocation choke point (chunk
 * 4.1.3), so a future arena/pool allocator only has to change these two
 * functions.
 */
static void *ql_new(size_t size) {
    return calloc(1, size);
}

// static void ql_del(void *ptr) {
//     free(ptr);
// }

static bool ql__stream_type_is_bidi(ql_stream_type_t type) {
    return type == QL_STREAM_TYPE_CLIENT_BIDI || type == QL_STREAM_TYPE_SERVER_BIDI;
}

static bool ql__stream_type_is_local(const ql_conn_t *conn, ql_stream_type_t type) {
    if (conn->role == QL_ROLE_CLIENT) {
        return type == QL_STREAM_TYPE_CLIENT_BIDI || type == QL_STREAM_TYPE_CLIENT_UNI;
    }
    return type == QL_STREAM_TYPE_SERVER_BIDI || type == QL_STREAM_TYPE_SERVER_UNI;
}

/*
 * ql_fc_stream_init — assign this stream's initial flow-control limits from
 * the negotiated transport parameters (RFC 9000 §4.1, §18.2). Send limits
 * come from what the *peer* told us it will accept (remote_tp); receive
 * limits come from what *we* advertised (local_tp).
 */
static void ql_fc_stream_init(ql_conn_t *conn, ql_stream_t *stream) {
    bool local  = ql__stream_type_is_local(conn, stream->type);
    bool bidi   = ql__stream_type_is_bidi(stream->type);

    if (!bidi) {
        /* Uni streams only carry data in the initiator's send direction. */
        if (local) {
            stream->fc.send_limit = conn->remote_tp.initial_max_stream_data_uni;
            stream->fc.recv_limit = 0; /* we never receive on our own uni stream */
        } else {
            stream->fc.send_limit = 0; /* we never send on a peer's uni stream */
            stream->fc.recv_limit = conn->local_tp.initial_max_stream_data_uni;
        }
        return;
    }

    if (local) {
        stream->fc.send_limit = conn->remote_tp.initial_max_stream_data_bidi_remote;
        stream->fc.recv_limit = conn->local_tp.initial_max_stream_data_bidi_local;
    } else {
        stream->fc.send_limit = conn->remote_tp.initial_max_stream_data_bidi_local;
        stream->fc.recv_limit = conn->local_tp.initial_max_stream_data_bidi_remote;
    }
}

/*
 * ql_stream_init — chunk 4.1.1: zero the stream, assign id/type, and wire
 * up its flow-control limits. Does not link it into conn->stream_list —
 * callers (qlite_stream_open / ql__stream_get_or_create) do that once they
 * know where the stream is coming from.
 */
static void ql_stream_init(ql_stream_t *stream, ql_stream_id_t id, ql_conn_t *conn) {
    memset(stream, 0, sizeof(*stream));
    stream->id       = id;
    stream->type     = (ql_stream_type_t)(id & 0x03);
    stream->tx_state = QL_TX_STREAM_READY;
    stream->rx_state = QL_RX_STREAM_RECV;
    ql_fc_stream_init(conn, stream);
}

/* ql_stream_find — chunk 4.1.2: linear search of the intrusive list. */
ql_stream_t *ql_stream_find(ql_conn_t *conn, ql_stream_id_t id) {
    if (!conn) {
        return NULL;
    }
    for (ql_stream_t *s = conn->stream_list; s; s = s->next) {
        if (s->id == id) {
            return s;
        }
    }
    return NULL;
}

static void ql__stream_link(ql_conn_t *conn, ql_stream_t *stream) {
    stream->next        = conn->stream_list;
    conn->stream_list    = stream;
}

/*
 * qlite_stream_open — chunk 4.1.3: locally-initiated stream creation.
 * Enforces the peer's advertised MAX_STREAMS limit.
 */
int qlite_stream_open(ql_conn_t *conn, bool bidi, ql_stream_t **out) {
    if (!conn || !out) {
        return QLITE_ERR_ARGS;
    }

    ql_stream_type_t type;
    if (conn->role == QL_ROLE_CLIENT) {
        type = bidi ? QL_STREAM_TYPE_CLIENT_BIDI : QL_STREAM_TYPE_CLIENT_UNI;
    } else {
        type = bidi ? QL_STREAM_TYPE_SERVER_BIDI : QL_STREAM_TYPE_SERVER_UNI;
    }

    uint64_t seq         = conn->next_stream_id[type] >> 2; /* how many of this type opened so far */
    uint64_t limit       = bidi ? conn->max_streams_bidi : conn->max_streams_uni;
    if (seq >= limit) {
        return QLITE_ERR_STREAM; /* peer's MAX_STREAMS limit reached — caller should back off */
    }

    ql_stream_t *stream = (ql_stream_t *)ql_new(sizeof(ql_stream_t));
    if (!stream) {
        return QLITE_ERR_NOMEM;
    }

    ql_stream_id_t id = conn->next_stream_id[type];
    ql_stream_init(stream, id, conn);
    conn->next_stream_id[type] = id + 4;

    ql__stream_link(conn, stream);
    *out = stream;
    return QLITE_OK;
}

/*
 * ql__stream_get_or_create — chunk 4.1.4: called when a frame references a
 * stream ID we haven't seen yet. Only valid for peer-initiated streams
 * within our advertised MAX_STREAMS limit; anything else is a protocol
 * violation the caller should turn into a connection close.
 */
static ql_stream_t *ql__stream_get_or_create(ql_conn_t *conn, ql_stream_id_t id) {
    ql_stream_type_t type = (ql_stream_type_t)(id & 0x03);
    if (ql__stream_type_is_local(conn, type)) {
        /* An endpoint referencing an ID in its own numbering space that it
         * hasn't opened yet is a protocol violation (STREAM_STATE_ERROR). */
        return NULL;
    }

    uint64_t seq   = id >> 2;
    bool bidi      = ql__stream_type_is_bidi(type);
    uint64_t limit = bidi ? conn->local_tp.initial_max_streams_bidi
                          : conn->local_tp.initial_max_streams_uni;
    if (seq >= limit) {
        return NULL; /* STREAM_LIMIT_ERROR */
    }

    ql_stream_t *stream = (ql_stream_t *)ql_new(sizeof(ql_stream_t));
    if (!stream) {
        return NULL;
    }
    ql_stream_init(stream, id, conn);
    ql__stream_link(conn, stream);

    /* Keep our own bookkeeping of "next id we'd hand out" in sync so a
     * later qlite_stream_open() of the same type can't collide — not
     * required for peer-initiated types, but harmless to skip; peer and
     * local numbering spaces never overlap (chunk 2.1). */
    return stream;
}

/*
 * qlite_stream_close — chunk 4.1.5. error_code == 0 requests a graceful
 * FIN once buffered data drains; error_code != 0 sends RESET_STREAM
 * immediately and abandons anything still buffered.
 */
int qlite_stream_close(ql_conn_t *conn, ql_stream_t *stream, ql_app_error_t error_code) {
    if (!conn || !stream) {
        return QLITE_ERR_ARGS;
    }
    if (stream->tx_state != QL_TX_STREAM_READY && stream->tx_state != QL_TX_STREAM_SEND) {
        return QLITE_ERR_STREAM; /* already finished/reset */
    }

    if (error_code == 0) {
        /* Mark the FIN point at the current write cursor; ql_conn_tick's
         * STREAM flush (chunk 4.2) sends it once tx_tail catches up. */
        stream->fc.final_size       = stream->tx_head;
        stream->fc.final_size_known = true;
        return QLITE_OK;
    }

    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                    = QL_FRAME_RESET_STREAM;
    f.u.reset_stream.stream_id  = stream->id;
    f.u.reset_stream.error_code = error_code;
    f.u.reset_stream.final_size = stream->tx_tail; /* only what we actually sent counts */

    uint8_t buf[32];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));
    if (flen < 0) {
        return flen;
    }

    int sent_idx = -1;
    int sn = ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, buf, (size_t)flen, true,
                                QL_RETX_FLAG_RESET_STREAM, ql_now_ms(), &sent_idx);
    if (sn < 0) {
        return sn;
    }
    if(sent_idx >= 0){
        conn->sent_pkts[sent_idx].stream_id = stream->id;
    }

    stream->reset_error_code = error_code;
    stream->tx_state         = QL_TX_STREAM_RESET_SENT;
    return QLITE_OK;
}

/*
 * qlite_send — chunk 4.2.1: buffer application data for a stream. Actual
 * STREAM frames go out from ql_conn_tick's flush pass (chunk 4.2.2-4.2.4).
 * Returns the number of bytes buffered, which may be less than `len` if
 * the send-side ring buffer is full (apply backpressure and retry later).
 */
int qlite_send(ql_conn_t *conn, ql_stream_t *stream, const uint8_t *data, size_t len) {
    if (!conn || !stream || (!data && len > 0)) {
        return QLITE_ERR_ARGS;
    }
    if (stream->tx_state != QL_TX_STREAM_READY && stream->tx_state != QL_TX_STREAM_SEND) {
        return QLITE_ERR_STREAM; /* stream already FIN'd or reset */
    }

    uint64_t used = stream->tx_head - stream->tx_tail;
    uint64_t free_space = (QL_STREAM_BUF_SIZE > used) ? QL_STREAM_BUF_SIZE - used : 0;
    size_t n = (size_t)((uint64_t)len < free_space ? len : free_space);
    if (n == 0) {
        return (len == 0) ? 0 : QLITE_ERR_AGAIN;
    }

    for (size_t i = 0; i < n; i++) {
        stream->tx_buf[(size_t)((stream->tx_head + i) % QL_STREAM_BUF_SIZE)] = data[i];
    }
    stream->tx_head += n;
    return (int)n;
}

/*
 * ql__stream_apply_reset — chunk 4.3.6: peer RESET_STREAM. Discards any
 * unread buffered bytes; the app learns of the reset via qlite_recv().
 */
static void ql__stream_apply_reset(ql_stream_t *stream, ql_app_error_t error_code, uint64_t final_size) {
    if (stream->rx_state == QL_RX_STREAM_RESET_RCVD || stream->rx_state == QL_RX_STREAM_RESET_READ) {
        return; /* already reset */
    }
    stream->rx_state         = QL_RX_STREAM_RESET_RCVD;
    stream->reset_error_code = error_code;
    stream->fc.final_size    = final_size;
    stream->fc.final_size_known = true;
    stream->rx_tail = stream->rx_head; /* drop anything unread and not yet consumed */
}


/*
 * ql_stream_rx_push — chunk 4.3: reassemble inbound STREAM frame data.
 * Out-of-order bytes are staged in the ring buffer with a bitmap (mirrors
 * ql_crypto_rx_push's approach); the buffer wraps, so the bitmap is
 * cleared as each byte is folded into the contiguous run so the same slot
 * can be reused by a later offset.
 */
int ql_stream_rx_push(ql_conn_t *conn, ql_stream_t *stream, uint64_t offset, const uint8_t *data,
                      size_t len, bool fin) {
    (void)conn;
    if (!stream || (!data && len > 0)) {
        return QLITE_ERR_ARGS;
    }
    if (stream->rx_state == QL_RX_STREAM_RESET_RCVD || stream->rx_state == QL_RX_STREAM_RESET_READ) {
        return QLITE_OK; /* stream already reset; silently discard (§3.2) */
    }

    uint64_t end = offset + (uint64_t)len;

    /* §4.5 — final size, once known, is immutable and bounds all data. */
    if (stream->fc.final_size_known) {
        if (end > stream->fc.final_size || (fin && end != stream->fc.final_size)) {
            return QLITE_ERR_PROTO;
        }
    } else if (fin) {
        stream->fc.final_size       = end;
        stream->fc.final_size_known = true;
    }

    if (len > 0) {
        if (end > stream->fc.recv_limit) {
            return QLITE_ERR_FC;
        }

        uint64_t start = offset;
        const uint8_t *d = data;
        size_t n         = len;
        if (start < stream->rx_tail) {
            if (end <= stream->rx_tail) {
                n = 0; /* fully duplicate retransmission */
            } else {
                uint64_t skip = stream->rx_tail - start;
                d     += skip;
                n     -= (size_t)skip;
                start  = stream->rx_tail;
            }
        }

        if (n > 0) {
            if (start + n - stream->rx_head > QL_STREAM_BUF_SIZE) {
                return QLITE_ERR_BUF; /* peer sent beyond what FC should allow */
            }
            if (end > stream->rx_highest_offset) {
                stream->rx_highest_offset = end;
            }
            for (size_t i = 0; i < n; i++) {
                size_t pos = (size_t)((start + i) % QL_STREAM_BUF_SIZE);
                stream->rx_buf[pos] = d[i];
                stream->rx_received[pos / 8] |= (uint8_t)(1u << (pos % 8));
            }
            while (stream->rx_tail < stream->rx_highest_offset) {
                size_t pos = (size_t)(stream->rx_tail % QL_STREAM_BUF_SIZE);
                if (!(stream->rx_received[pos / 8] & (uint8_t)(1u << (pos % 8)))) {
                    break;
                }
                stream->rx_received[pos / 8] &= (uint8_t) ~(1u << (pos % 8));
                stream->rx_tail++;
            }
        }
    }

    if (stream->fc.final_size_known && stream->rx_tail >= stream->fc.final_size &&
        stream->rx_state == QL_RX_STREAM_RECV) {
        stream->rx_state = QL_RX_STREAM_SIZE_KNOWN;
    }
    if (stream->fc.final_size_known && stream->rx_tail >= stream->fc.final_size &&
        stream->rx_head == stream->rx_tail) {
        stream->rx_state = QL_RX_STREAM_DATA_RCVD;
    }

    return QLITE_OK;
}

/*
 * qlite_recv — chunk 4.3.5: copy out whatever contiguous bytes are ready.
 * Returns >=0 bytes read (0 meaning EOF/FIN with nothing left), or
 * QLITE_ERR_AGAIN if nothing is available yet, or QLITE_ERR_CLOSED if the
 * stream was reset (stream->reset_error_code holds the peer's code).
 */
int qlite_recv(ql_conn_t *conn, ql_stream_t *stream, uint8_t *out, size_t max_len) {
    (void)conn;
    if (!stream || (!out && max_len > 0)) {
        return QLITE_ERR_ARGS;
    }

    uint64_t avail = stream->rx_tail - stream->rx_head;
    if (avail == 0) {
        if (stream->rx_state == QL_RX_STREAM_RESET_RCVD) {
            stream->rx_state = QL_RX_STREAM_RESET_READ;
            return QLITE_ERR_CLOSED;
        }
        if (stream->fc.final_size_known && stream->rx_head >= stream->fc.final_size) {
            stream->rx_state = QL_RX_STREAM_DATA_READ;
            return 0; /* EOF */
        }
        return QLITE_ERR_AGAIN;
    }

    size_t n = (size_t)((avail < (uint64_t)max_len) ? avail : (uint64_t)max_len);
    for (size_t i = 0; i < n; i++) {
        out[i] = stream->rx_buf[(size_t)((stream->rx_head + i) % QL_STREAM_BUF_SIZE)];
    }
    stream->rx_head += n;
    stream->fc.recv_consumed += n;
    if (conn) {
        conn->fc.recv_consumed += n;
    }

    if (stream->rx_head == stream->rx_tail && stream->fc.final_size_known &&
        stream->rx_head >= stream->fc.final_size) {
        stream->rx_state = QL_RX_STREAM_DATA_READ;
    }

    return (int)n;
}

/*
 * ql__ack_record_recv — chunk 5.1.1: fold a just-decoded packet number into
 * this space's ACK state (a sorted, merged list of contiguous ranges,
 * highest first) and decide whether/when we owe the peer an ACK.
 */
static void ql__ack_record_recv(ql_conn_t *conn, ql_pn_space_t space, ql_pkt_num_t pn,
                                bool ack_eliciting, uint64_t now_ms) {
    ql_ack_state_t *a = &conn->ack[space];

    if (a->range_count == 0) {
        a->ranges[0].largest = pn;
        a->ranges[0].count   = 1;
        a->range_count       = 1;
    } else {
        bool handled = false;
        for (int i = 0; i < a->range_count && !handled; i++) {
            ql_pkt_num_t lo = a->ranges[i].largest - a->ranges[i].count + 1;

            if (pn >= lo && pn <= a->ranges[i].largest) {
                handled = true; /* duplicate, already covered */
            } else if (pn == a->ranges[i].largest + 1) {
                a->ranges[i].largest = pn;
                a->ranges[i].count++;
                if (i > 0) {
                    ql_pkt_num_t above_lo = a->ranges[i - 1].largest - a->ranges[i - 1].count + 1;
                    if (a->ranges[i].largest + 1 == above_lo) {
                        a->ranges[i - 1].count += a->ranges[i].count;
                        for (int j = i; j < a->range_count - 1; j++) {
                            a->ranges[j] = a->ranges[j + 1];
                        }
                        a->range_count--;
                    }
                }
                handled = true;
            } else if (pn + 1 == lo) {
                a->ranges[i].count++;
                if (i + 1 < a->range_count) {
                    ql_pkt_num_t new_lo = a->ranges[i].largest - a->ranges[i].count + 1;
                    if (new_lo == a->ranges[i + 1].largest + 1) {
                        a->ranges[i].count += a->ranges[i + 1].count;
                        for (int j = i + 1; j < a->range_count - 1; j++) {
                            a->ranges[j] = a->ranges[j + 1];
                        }
                        a->range_count--;
                    }
                }
                handled = true;
            } else if (pn > a->ranges[i].largest) {
                /* Belongs strictly between ranges[i-1] and ranges[i] (or at
                 * the very front) — insert a fresh singleton range here. */
                int n = a->range_count < QL_ACK_RANGE_MAX ? a->range_count : QL_ACK_RANGE_MAX - 1;
                for (int j = n; j > i; j--) {
                    a->ranges[j] = a->ranges[j - 1];
                }
                a->ranges[i].largest = pn;
                a->ranges[i].count   = 1;
                if (a->range_count < QL_ACK_RANGE_MAX) {
                    a->range_count++;
                }
                handled = true;
            }
        }
        if (!handled && a->range_count < QL_ACK_RANGE_MAX) {
            /* Lower than everything currently tracked. */
            a->ranges[a->range_count].largest = pn;
            a->ranges[a->range_count].count   = 1;
            a->range_count++;
        }
        /* else: peer is acknowledging something older than our tracked
         * history window — RFC 9002 explicitly allows bounding this. */
    }

    a->largest_recvd = a->ranges[0].largest;

    if (ack_eliciting) {
        a->ack_eliciting_recvd++;
        if (!a->needs_ack) {
            a->needs_ack            = true;
            uint64_t delay          = (space == QL_PN_SPACE_APP) ? QL_ACK_TIMEOUT_MS : 0;
            a->ack_send_deadline_ms = now_ms + delay;
        }
        if (space != QL_PN_SPACE_APP || a->ack_eliciting_recvd >= QL_ACK_DELAY_THRESHOLD) {
            a->ack_send_deadline_ms = now_ms; /* send with the next tick */
        }
    }
}

/*
 * ql__send_ack — chunk 5.1.2: build an ACK frame straight out of the
 * per-space ack state and send it (never retransmitted on loss — ACK
 * frames aren't ack-eliciting and carry no frame_flags).
 */
static int ql__send_ack(ql_conn_t *conn, ql_pn_space_t space, ql_enc_level_t level, uint64_t now_ms) {
    ql_ack_state_t *a = &conn->ack[space];
    if (a->range_count == 0 || !conn->keys[level].write.is_set) {
        return QLITE_ERR_AGAIN;
    }

    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                 = QL_FRAME_ACK; /* we don't track incoming ECN marks yet */
    f.u.ack.largest_acked   = a->ranges[0].largest;
    f.u.ack.ack_delay       = 0; /* TODO: real ack-delay accounting */
    f.u.ack.first_ack_range = a->ranges[0].count - 1;

    int extra = a->range_count - 1;
    if (extra > QL_ACK_RANGE_MAX) {
        extra = QL_ACK_RANGE_MAX;
    }
    f.u.ack.range_count = (uint64_t)extra;
    for (int i = 0; i < extra; i++) {
        f.u.ack.ranges[i] = a->ranges[i + 1];
    }

    uint8_t buf[QL_PATH_MTU_ETHERNET];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));
    if (flen < 0) {
        return flen;
    }

    int sn = ql__send_level_pkt(conn, level, buf, (size_t)flen, false, 0, now_ms, NULL);
    if (sn < 0) {
        return sn;
    }

    a->needs_ack            = false;
    a->ack_eliciting_recvd  = 0;
    a->ack_send_deadline_ms = 0;
    a->largest_acked_sent   = a->ranges[0].largest;
    return sn;
}

/*
 * ql__on_pkt_acked — chunk 5.1.3/5.4: an ACK confirmed this packet.
 * Release its congestion-window budget, grow the window (NewReno,
 * RFC 9002 7.3), and advance the "confirmed delivered" cursors that let
 * CRYPTO/STREAM data eventually stop being retransmit candidates.
 */
static void ql__on_pkt_acked(ql_conn_t *conn, ql_sent_pkt_t *sp) {
    if (sp->in_flight) {
        conn->cc.bytes_in_flight = (conn->cc.bytes_in_flight >= sp->in_flight_bytes)
                                       ? conn->cc.bytes_in_flight - sp->in_flight_bytes
                                       : 0;
        sp->in_flight = false;
    }

    if (conn->cc.state == QL_CC_RECOVERY) {
        if (sp->pkt_num > conn->cc.recovery_start_pn) {
            conn->cc.state = QL_CC_CONGESTION_AVD;
        }
    } else if (conn->cc.state == QL_CC_SLOW_START) {
        conn->cc.cwnd += sp->in_flight_bytes;
        if (conn->cc.cwnd >= conn->cc.ssthresh) {
            conn->cc.state = QL_CC_CONGESTION_AVD;
        }
    } else if (conn->cc.cwnd > 0) {
        /* Congestion avoidance: increase by (acked_bytes * MSS) / cwnd. */
        conn->cc.cwnd += (sp->in_flight_bytes * QL_PATH_MTU_DEFAULT) / conn->cc.cwnd;
    }

    if (sp->frame_flags & QL_RETX_FLAG_CRYPTO) {
        uint64_t acked_end = sp->crypto_offset + sp->crypto_len;
        if (acked_end > conn->crypto[sp->crypto_level].tx_acked_offset) {
            conn->crypto[sp->crypto_level].tx_acked_offset = acked_end;
        }
    }
    if (sp->frame_flags & (QL_RETX_FLAG_STREAM | QL_RETX_FLAG_RESET_STREAM)) {
        ql_stream_t *s = ql_stream_find(conn, sp->stream_id);
        if (s) {
            if (sp->frame_flags & QL_RETX_FLAG_STREAM) {
                uint64_t acked_end = sp->stream_offset + sp->stream_len;
                if (acked_end > s->tx_acked_offset) {
                    s->tx_acked_offset = acked_end;
                }
                if (sp->stream_fin && s->tx_state == QL_TX_STREAM_DATA_SENT) {
                    s->tx_state = QL_TX_STREAM_DATA_RCVD;
                }
            }
            if ((sp->frame_flags & QL_RETX_FLAG_RESET_STREAM) &&
                s->tx_state == QL_TX_STREAM_RESET_SENT) {
                s->tx_state = QL_TX_STREAM_RESET_RCVD;
            }
        }
    }
    if (sp->frame_flags & QL_RETX_FLAG_HANDSHAKE_DONE) {
        /* Nothing further to do — already marked confirmed when sent. */
    }
}

/*
 * ql__on_pkt_lost — chunk 5.2.3/5.4: declare a packet lost. Cuts the
 * congestion window once per recovery episode (RFC 9002 7.3.2) and
 * rewinds whatever retransmission cursor is responsible for its data so
 * the normal tick-loop flush passes naturally resend it.
 */
static void ql__on_pkt_lost(ql_conn_t *conn, ql_sent_pkt_t *sp) {
    if (sp->in_flight) {
        conn->cc.bytes_in_flight = (conn->cc.bytes_in_flight >= sp->in_flight_bytes)
                                       ? conn->cc.bytes_in_flight - sp->in_flight_bytes
                                       : 0;
        sp->in_flight = false;
    }
    sp->is_lost = true;

    if (conn->cc.state != QL_CC_RECOVERY || sp->pkt_num > conn->cc.recovery_start_pn) {
        conn->cc.recovery_start_pn =
            (conn->next_pn[sp->pn_space] > 0) ? conn->next_pn[sp->pn_space] - 1 : 0;
        conn->cc.ssthresh = conn->cc.cwnd / 2;
        if (conn->cc.ssthresh < 2 * QL_PATH_MTU_DEFAULT) {
            conn->cc.ssthresh = 2 * QL_PATH_MTU_DEFAULT;
        }
        conn->cc.cwnd  = conn->cc.ssthresh;
        conn->cc.state = QL_CC_RECOVERY;
    }

    if (sp->frame_flags & QL_RETX_FLAG_CRYPTO) {
        if (sp->crypto_offset < conn->crypto[sp->crypto_level].tx_sent_offset) {
            conn->crypto[sp->crypto_level].tx_sent_offset = sp->crypto_offset;
        }
    }
    if (sp->frame_flags & QL_RETX_FLAG_STREAM) {
        ql_stream_t *s = ql_stream_find(conn, sp->stream_id);
        if (s && sp->stream_offset < s->tx_tail) {
            s->tx_tail = sp->stream_offset;
        }
    }
    if (sp->frame_flags & QL_RETX_FLAG_HANDSHAKE_DONE) {
        conn->handshake_confirmed = false; /* the tick loop will resend it */
    }
    /* RESET_STREAM loss: a lite simplification — we don't auto-resend it.
     * A real stack would re-arm and retransmit; here the app can notice
     * via qlite_stream_close's return and the stream simply stays in
     * QL_TX_STREAM_RESET_SENT a little longer than ideal. */
}

/*
 * ql__rtt_sample — RFC 9002 §5.3, taken once per ACK that newly
 * acknowledges the largest packet number in that ACK.
 */
static void ql__rtt_sample(ql_conn_t *conn, uint64_t sent_at_ms, uint64_t ack_delay_units,
                           uint64_t now_ms) {
    if (sent_at_ms == 0 || now_ms < sent_at_ms) {
        return;
    }
    uint64_t latest_rtt_us  = (now_ms - sent_at_ms) * 1000;
    conn->cc.latest_rtt_us  = latest_rtt_us;

    if (conn->cc.min_rtt_us == UINT64_MAX || latest_rtt_us < conn->cc.min_rtt_us) {
        conn->cc.min_rtt_us = latest_rtt_us;
    }

    uint64_t ack_delay_exp =
        conn->remote_tp_rcvd ? conn->remote_tp.ack_delay_exponent : QL_DEFAULT_ACK_DELAY_EXP;
    uint64_t ack_delay_us = ack_delay_units << ack_delay_exp;
    uint64_t max_ack_delay_us =
        (conn->remote_tp_rcvd && conn->handshake_confirmed)
            ? (uint64_t)conn->remote_tp.max_ack_delay_ms * 1000
            : UINT64_MAX;
    if (ack_delay_us > max_ack_delay_us) {
        ack_delay_us = max_ack_delay_us;
    }

    uint64_t adjusted_rtt_us = latest_rtt_us;
    if (latest_rtt_us > conn->cc.min_rtt_us + ack_delay_us) {
        adjusted_rtt_us = latest_rtt_us - ack_delay_us;
    }

    if (!conn->cc.rtt_sample_taken) {
        conn->cc.smoothed_rtt_us        = adjusted_rtt_us;
        conn->cc.rtt_var_us             = adjusted_rtt_us / 2;
        conn->cc.rtt_sample_taken       = true;
        conn->cc.first_rtt_sample_at_ms = now_ms;
    } else {
        uint64_t diff = (conn->cc.smoothed_rtt_us > adjusted_rtt_us)
                            ? conn->cc.smoothed_rtt_us - adjusted_rtt_us
                            : adjusted_rtt_us - conn->cc.smoothed_rtt_us;
        conn->cc.rtt_var_us      = (3 * conn->cc.rtt_var_us + diff) / 4;
        conn->cc.smoothed_rtt_us = (7 * conn->cc.smoothed_rtt_us + adjusted_rtt_us) / 8;
    }
}

/*
 * ql__process_ack_frame — chunk 5.1.3: apply a received ACK frame to our
 * sent-packet history, sample RTT off the newly-acked largest packet, and
 * re-run loss detection (an ACK is exactly the event that can reveal a
 * packet threshold loss).
 */
static void ql__process_ack_frame(ql_conn_t *conn, ql_pn_space_t space, const ql_frame_ack_t *ack,
                                  uint64_t now_ms) {
    bool newly_acked_largest    = false;
    uint64_t largest_acked_sent_at = 0;

    ql_pkt_num_t hi = ack->largest_acked;
    ql_pkt_num_t lo = hi - ack->first_ack_range;

    for (int pass = -1; pass < (int)ack->range_count; pass++) {
        if (pass >= 0) {
            hi = ack->ranges[pass].largest; /* already absolute — see decode */
            lo = hi - ack->ranges[pass].count + 1;
        }
        for (int i = 0; i < conn->sent_pkt_count; i++) {
            int idx        = (conn->sent_pkt_head + i) % QL_SENT_PKT_MAX;
            ql_sent_pkt_t *sp = &conn->sent_pkts[idx];
            if (sp->pn_space != space || sp->is_acked) {
                continue;
            }
            if (sp->pkt_num < lo || sp->pkt_num > hi) {
                continue;
            }
            sp->is_acked = true;
            if (sp->pkt_num == ack->largest_acked && sp->ack_eliciting) {
                newly_acked_largest      = true;
                largest_acked_sent_at    = sp->sent_at_ms;
            }
            ql__on_pkt_acked(conn, sp);
        }
    }

    if (newly_acked_largest) {
        ql__rtt_sample(conn, largest_acked_sent_at, ack->ack_delay, now_ms);
    }

    /* A fresh ACK can retroactively push older unacked packets past the
     * packet-count threshold, so re-run loss detection now. */
    ql__detect_and_declare_losses(conn, space, now_ms);
    ql__set_loss_detection_timer(conn, now_ms);
}

/*
 * ql__detect_and_declare_losses — RFC 9002 §6.1: packet- and time-threshold
 * loss detection for one packet-number space, run after any ACK is
 * processed and again whenever the loss-detection timer fires.
 */
static void ql__detect_and_declare_losses(ql_conn_t *conn, ql_pn_space_t space, uint64_t now_ms) {
    ql_pkt_num_t largest_acked = QL_PKT_NUM_NONE;
    for (int i = 0; i < conn->sent_pkt_count; i++) {
        int idx           = (conn->sent_pkt_head + i) % QL_SENT_PKT_MAX;
        ql_sent_pkt_t *sp = &conn->sent_pkts[idx];
        if (sp->pn_space == space && sp->is_acked &&
            (largest_acked == QL_PKT_NUM_NONE || sp->pkt_num > largest_acked)) {
            largest_acked = sp->pkt_num;
        }
    }
    if (largest_acked == QL_PKT_NUM_NONE) {
        conn->cc.loss_time[space] = 0;
        return;
    }

    uint64_t rtt_us =
        conn->cc.rtt_sample_taken
            ? (conn->cc.smoothed_rtt_us > conn->cc.latest_rtt_us ? conn->cc.smoothed_rtt_us
                                                                 : conn->cc.latest_rtt_us)
            : QL_INITIAL_RTT_US;
    uint64_t loss_delay_us = (rtt_us * QL_LOSS_TIME_THRESHOLD_NUM) / QL_LOSS_TIME_THRESHOLD_DEN;
    uint64_t min_delay_us  = (uint64_t)QL_TIMER_GRANULARITY_MS * 1000;
    if (loss_delay_us < min_delay_us) {
        loss_delay_us = min_delay_us;
    }
    uint64_t loss_delay_ms = loss_delay_us / 1000;

    conn->cc.loss_time[space] = 0;

    for (int i = 0; i < conn->sent_pkt_count; i++) {
        int idx           = (conn->sent_pkt_head + i) % QL_SENT_PKT_MAX;
        ql_sent_pkt_t *sp = &conn->sent_pkts[idx];
        if (sp->pn_space != space || sp->is_acked || sp->is_lost || !sp->in_flight) {
            continue;
        }
        if (sp->pkt_num > largest_acked) {
            continue; /* can't judge packets sent after the largest acked one */
        }

        bool pkt_thresh  = (largest_acked - sp->pkt_num) >= QL_LOSS_PACKET_THRESHOLD;
        bool time_thresh = now_ms >= sp->sent_at_ms + loss_delay_ms;

        if (pkt_thresh || time_thresh) {
            ql__on_pkt_lost(conn, sp);
        } else {
            uint64_t sp_loss_time_ms = sp->sent_at_ms + loss_delay_ms;
            if (conn->cc.loss_time[space] == 0 || sp_loss_time_ms < conn->cc.loss_time[space]) {
                conn->cc.loss_time[space] = sp_loss_time_ms;
            }
        }
    }
}

/*
 * ql__set_loss_detection_timer — RFC 9002 §6.2.1: arm on the earliest
 * per-space loss_time if one is pending, otherwise on a PTO computed from
 * the current RTT estimate, doubling with each consecutive PTO.
 */
static void ql__set_loss_detection_timer(ql_conn_t *conn, uint64_t now_ms) {
    uint64_t earliest_loss = 0;
    for (int i = 0; i < QL_PN_SPACE_COUNT; i++) {
        if (conn->cc.loss_time[i] != 0 &&
            (earliest_loss == 0 || conn->cc.loss_time[i] < earliest_loss)) {
            earliest_loss = conn->cc.loss_time[i];
        }
    }
    if (earliest_loss != 0) {
        conn->cc.pto_deadline_ms = earliest_loss;
        return;
    }

    if (conn->cc.bytes_in_flight == 0 && conn->handshake_confirmed) {
        conn->cc.pto_deadline_ms = 0; /* nothing outstanding to probe for */
        return;
    }

    uint64_t rtt_us    = conn->cc.rtt_sample_taken ? conn->cc.smoothed_rtt_us : QL_INITIAL_RTT_US;
    uint64_t rttvar4_us = conn->cc.rtt_sample_taken ? 4 * conn->cc.rtt_var_us : 0;
    if (rttvar4_us < 1000) {
        rttvar4_us = 1000; /* kGranularity floor, in microseconds */
    }
    uint64_t max_ack_delay_us =
        conn->remote_tp_rcvd ? (uint64_t)conn->remote_tp.max_ack_delay_ms * 1000 : 0;

    uint64_t pto_us = (rtt_us + rttvar4_us + max_ack_delay_us);
    /* Exponential backoff (§6.2.1); guard the shift against overflow for a
     * connection that's been probing for a very long time. */
    int shift = conn->cc.pto_count < 32 ? conn->cc.pto_count : 32;
    pto_us <<= shift;

    conn->cc.pto_deadline_ms = now_ms + pto_us / 1000;
}

/*
 * ql__on_pto_timeout — RFC 9002 §6.2.4. A full probe implementation sends
 * up to two in-flight-eligible packets; this lite version sends one PING
 * per space that still has data outstanding, which is enough to elicit a
 * fresh ACK and get the loss-detection/retransmission machinery moving
 * again after a stall.
 */
static void ql__on_pto_timeout(ql_conn_t *conn, uint64_t now_ms) {
    conn->cc.pto_count++;

    for (int i = 0; i < QL_PN_SPACE_COUNT; i++) {
        bool has_in_flight = false;
        for (int j = 0; j < conn->sent_pkt_count; j++) {
            int idx = (conn->sent_pkt_head + j) % QL_SENT_PKT_MAX;
            if (conn->sent_pkts[idx].pn_space == i && conn->sent_pkts[idx].in_flight) {
                has_in_flight = true;
                break;
            }
        }
        if (!has_in_flight) {
            continue;
        }

        ql_enc_level_t level = (i == QL_PN_SPACE_INITIAL)   ? QL_ENC_LEVEL_INITIAL
                              : (i == QL_PN_SPACE_HANDSHAKE) ? QL_ENC_LEVEL_HANDSHAKE
                                                              : QL_ENC_LEVEL_APP;
        if (!conn->keys[level].write.is_set) {
            continue;
        }

        ql_frame_t f;
        memset(&f, 0, sizeof(f));
        f.type = QL_FRAME_PING;
        uint8_t buf[4];
        int flen = ql_frame_encode(&f, buf, sizeof(buf));
        if (flen >= 0) {
            ql__send_level_pkt(conn, level, buf, (size_t)flen, true, QL_RETX_FLAG_PING, now_ms, NULL);
        }
    }
}

/*
 * ql__cid_issue_new — chunk 6.1: top up how many local CIDs we've handed
 * the peer, up to both QL_MAX_CIDS and whatever active_cid_limit the peer
 * advertised. Called opportunistically from the tick loop.
 */
static void ql__cid_issue_new(ql_conn_t *conn, uint64_t now_ms) {
    (void)now_ms;
    if (!conn->keys[QL_ENC_LEVEL_APP].write.is_set) {
        return;
    }

    uint64_t peer_limit = conn->remote_tp_rcvd ? conn->remote_tp.active_cid_limit
                                               : QL_DEFAULT_ACTIVE_CID_LIMIT;
    int limit = (int)((peer_limit < QL_MAX_CIDS) ? peer_limit : QL_MAX_CIDS);

    int active = 0;
    for (int i = 0; i < conn->local_cid_count; i++) {
        if (!conn->local_cids[i].is_retired) {
            active++;
        }
    }

    while (active < limit && conn->local_cid_count < QL_MAX_CIDS) {
        ql_cid_entry_t *e = &conn->local_cids[conn->local_cid_count];
        ql_cid_generate(&e->cid, QL_CID_MAX_LEN);
        if (e->cid.len == 0) {
            break;
        }
        e->sequence_num    = conn->next_cid_seq++;
        e->retire_prior_to = 0;
        e->is_active       = true;
        e->is_retired      = false;
        ql__fill_random(e->reset_token.data, sizeof(e->reset_token.data));

        ql_frame_t f;
        memset(&f, 0, sizeof(f));
        f.type                        = QL_FRAME_NEW_CONNECTION_ID;
        f.u.new_cid.sequence_num       = e->sequence_num;
        f.u.new_cid.retire_prior_to    = 0;
        f.u.new_cid.cid                = e->cid;
        f.u.new_cid.stateless_reset_token = e->reset_token;

        uint8_t buf[64];
        int flen = ql_frame_encode(&f, buf, sizeof(buf));
        if (flen < 0) {
            break;
        }
        if (ql__send_level_pkt(conn, QL_ENC_LEVEL_APP, buf, (size_t)flen, true,
                               QL_RETX_FLAG_NEW_CID, ql_now_ms(), NULL) < 0) {
            break; /* try again next tick */
        }

        conn->local_cid_count++;
        active++;
    }
}

/*
 * ql__on_possible_migration — chunk 6.3: a validly-decrypted 1-RTT packet
 * arrived from an address that isn't the active path. Start (or continue)
 * validating it; we don't switch active_path until PATH_RESPONSE confirms
 * it (handled in ql__process_frames' QL_FRAME_PATH_RESPONSE case).
 */
static void ql__on_possible_migration(ql_conn_t *conn, const struct sockaddr_storage *src_addr,
                                      socklen_t src_addrlen, uint64_t now_ms) {
    if (conn->probing_path.state == QL_PATH_PROBING &&
        conn->probing_path.peer_addrlen == src_addrlen &&
        memcmp(&conn->probing_path.peer_addr, src_addr, src_addrlen) == 0) {
        return; /* already probing this exact address */
    }

    memset(&conn->probing_path, 0, sizeof(conn->probing_path));
    conn->probing_path.peer_addr    = *src_addr;
    conn->probing_path.peer_addrlen = src_addrlen;
    conn->probing_path.local_addr   = conn->active_path.local_addr;
    conn->probing_path.local_addrlen = conn->active_path.local_addrlen;
    conn->probing_path.mtu          = QL_PATH_MTU_DEFAULT; /* re-discover conservatively */
    conn->probing_path.state        = QL_PATH_PROBING;
    conn->probing_path.challenge_sent_at_ms = now_ms;
    ql__fill_random(conn->probing_path.challenge_data.data, QL_PATH_DATA_LEN);

    conn->migration_in_progress = true;

    ql_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type                  = QL_FRAME_PATH_CHALLENGE;
    f.u.path_challenge.data = conn->probing_path.challenge_data;
    uint8_t buf[16];
    int flen = ql_frame_encode(&f, buf, sizeof(buf));
    if (flen >= 0) {
        ql__send_level_pkt_to(conn, QL_ENC_LEVEL_APP, buf, (size_t)flen, true,
                              QL_RETX_FLAG_PATH_CHALLENGE, now_ms, src_addr, src_addrlen, NULL);
    }
}

/*
 * ql__key_update_prepare / ql__key_update_promote — chunk 6.4, RFC 9001 §6.
 * See the discussion above ql_conn_tick's receive loop for why this needs
 * two steps: preparing derives the next generation's key/iv (the HP key
 * never changes across updates, §6.4) without disturbing anything in use;
 * promoting swaps it in — either because we chose to (qlite_key_update)
 * or because the peer's key_phase bit told us they already did.
 */
static int ql__key_update_prepare(ql_conn_t *conn) {
    if (conn->key_update.next.read.is_set && conn->key_update.next.write.is_set) {
        return QLITE_OK; /* already prepared for the upcoming generation */
    }
    if (!conn->keys[QL_ENC_LEVEL_APP].read.is_set || !conn->keys[QL_ENC_LEVEL_APP].write.is_set) {
        return QLITE_ERR_CLOSED;
    }

    ql_tls_backend_t *be = (ql_tls_backend_t *)conn->tls.tls_ctx;
    size_t rlen = be->pending[QL_ENC_LEVEL_APP].read_secret_len;
    size_t wlen = be->pending[QL_ENC_LEVEL_APP].write_secret_len;
    if (rlen == 0 || wlen == 0) {
        return QLITE_ERR_INTERNAL; /* secrets not retained — shouldn't happen post-handshake */
    }

    const EVP_MD *rmd = (rlen == 48) ? EVP_sha384() : EVP_sha256();
    const EVP_MD *wmd = (wlen == 48) ? EVP_sha384() : EVP_sha256();

    if (hkdf_expand_label(rmd, be->pending[QL_ENC_LEVEL_APP].read_secret, rlen, "quic ku",
                          conn->key_update.next_read_secret, rlen) != 0) {
        return QLITE_ERR_CRYPTO;
    }
    if (hkdf_expand_label(wmd, be->pending[QL_ENC_LEVEL_APP].write_secret, wlen, "quic ku",
                          conn->key_update.next_write_secret, wlen) != 0) {
        return QLITE_ERR_CRYPTO;
    }
    conn->key_update.next_read_secret_len  = rlen;
    conn->key_update.next_write_secret_len = wlen;

    const SSL_CIPHER *cipher = SSL_get_current_cipher(be->ssl);
    if (derive_ql_keys(cipher, conn->key_update.next_read_secret, rlen,
                       &conn->key_update.next.read) != 0) {
        return QLITE_ERR_CRYPTO;
    }
    if (derive_ql_keys(cipher, conn->key_update.next_write_secret, wlen,
                       &conn->key_update.next.write) != 0) {
        return QLITE_ERR_CRYPTO;
    }

    /* RFC 9001 §6.4 — the header-protection key never changes. */
    memcpy(conn->key_update.next.read.hp, conn->keys[QL_ENC_LEVEL_APP].read.hp, QL_HP_KEY_MAX_LEN);
    conn->key_update.next.read.hp_len = conn->keys[QL_ENC_LEVEL_APP].read.hp_len;
    memcpy(conn->key_update.next.write.hp, conn->keys[QL_ENC_LEVEL_APP].write.hp, QL_HP_KEY_MAX_LEN);
    conn->key_update.next.write.hp_len = conn->keys[QL_ENC_LEVEL_APP].write.hp_len;

    return QLITE_OK;
}

static void ql__key_update_promote(ql_conn_t *conn, uint64_t now_ms) {
    (void)now_ms;
    ql_key_pair_t old_active     = conn->keys[QL_ENC_LEVEL_APP];
    conn->keys[QL_ENC_LEVEL_APP] = conn->key_update.next;
    /* The just-retired generation is kept in `next` as a grace-period
     * fallback for decrypting any late/reordered old-phase packets — a
     * lite simplification: we don't bound how long this is retained. */
    conn->key_update.next          = old_active;
    conn->key_update.current_phase = !conn->key_update.current_phase;
    conn->key_update.update_sent_pn = conn->next_pn[QL_PN_SPACE_APP];

    ql_tls_backend_t *be = (ql_tls_backend_t *)conn->tls.tls_ctx;
    memcpy(be->pending[QL_ENC_LEVEL_APP].read_secret, conn->key_update.next_read_secret,
          conn->key_update.next_read_secret_len);
    be->pending[QL_ENC_LEVEL_APP].read_secret_len = conn->key_update.next_read_secret_len;
    memcpy(be->pending[QL_ENC_LEVEL_APP].write_secret, conn->key_update.next_write_secret,
          conn->key_update.next_write_secret_len);
    be->pending[QL_ENC_LEVEL_APP].write_secret_len = conn->key_update.next_write_secret_len;

    /* Clear the staging secrets so ql__key_update_prepare derives fresh
     * next time rather than mistaking this generation's leftovers for an
     * already-prepared upcoming one. */
    memset(conn->key_update.next_read_secret, 0, sizeof(conn->key_update.next_read_secret));
    memset(conn->key_update.next_write_secret, 0, sizeof(conn->key_update.next_write_secret));
    conn->key_update.next_read_secret_len  = 0;
    conn->key_update.next_write_secret_len = 0;
}

/*
 * qlite_key_update — chunk 6.4 public entry point. RFC 9001 §6.1 forbids
 * initiating another update until the packet sent in the previous new
 * phase has been acknowledged; we check that lazily here rather than
 * tracking it as a standing timer.
 */
int qlite_key_update(ql_conn_t *conn) {
    if (!conn) {
        return QLITE_ERR_ARGS;
    }
    if (!conn->handshake_confirmed) {
        return QLITE_ERR_CLOSED;
    }

    if (conn->key_update.update_pending) {
        bool confirmed = false;
        for (int i = 0; i < conn->sent_pkt_count; i++) {
            int idx = (conn->sent_pkt_head + i) % QL_SENT_PKT_MAX;
            if (conn->sent_pkts[idx].pn_space == QL_PN_SPACE_APP &&
                conn->sent_pkts[idx].pkt_num == conn->key_update.update_sent_pn) {
                confirmed = conn->sent_pkts[idx].is_acked;
                break;
            }
        }
        if (!confirmed) {
            return QLITE_ERR_AGAIN;
        }
        conn->key_update.update_pending = false;
    }

    int rc = ql__key_update_prepare(conn);
    if (rc < 0) {
        return rc;
    }

    ql__key_update_promote(conn, ql_now_ms());
    conn->key_update.update_pending = true;
    return QLITE_OK;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
#endif /* QLITE_H */
