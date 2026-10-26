/**
 * @file: defines.h
 * @brief: just a file for me keep all the defines in places and easy to get to 
 * 
 * DATE: 2026-10-26
 */

#define QL_VARINT_MAX UINT64_C(4611686018427387903) /* 2^62 − 1  16 */
#define QL_VARINT_1B_MAX UINT64_C(63)
#define QL_VARINT_2B_MAX UINT64_C(16383)
#define QL_VARINT_4B_MAX UINT64_C(1073741823)

/* Minimum encoded sizes for varints — useful for buffer-size assertions */
#define QL_VARINT_1B_SIZE 1
#define QL_VARINT_2B_SIZE 2
#define QL_VARINT_4B_SIZE 4
#define QL_VARINT_8B_SIZE 8

/*
 * Sentinel "no packet number yet received" value.
 * Must not collide with any valid packet number (0 .. 2^62-1).
 */
#define QL_PKT_NUM_NONE UINT64_MAX

/* Connection ID 5.1 — opaque, 1–20 bytes; len=0 means zero-length CID */
#define QL_CID_MAX_LEN 20
/* Stateless Reset Token 10.3.2 — exactly 16 bytes */
#define QL_RESET_TOKEN_LEN 16
/* Path validation data 19.17–19.18 — exactly 8 bytes */
#define QL_PATH_DATA_LEN 8

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
#define QL_LOSS_PACKET_THRESHOLD 3   /* kPacketThreshold */
#define QL_LOSS_TIME_THRESHOLD_NUM 9 /* kTimeThreshold = 9/8 */
#define QL_LOSS_TIME_THRESHOLD_DEN 8
#define QL_TIMER_GRANULARITY_MS 1 /* kGranularity */
#define QL_INITIAL_RTT_US 500000  /* kInitialRtt = 500ms, used before any sample */

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
#define QL_CONN_FC_WINDOW_DEFAULT \
    (QL_STREAM_BUF_SIZE * 4) /* connection-level recv window step (4.4.3) */

/* Server limits */
#define QL_SERVER_MAX_CONNS 1024
#define QL_MAX_CIDS 8      /* connection IDs we issue/track 5.1 */
#define QL_MAX_VERSIONS 16 /* Version Negotiation list */

/* 21.3 — Anti-amplification limit: 3x received bytes before addr validation */
#define QL_AMPLIFICATION_FACTOR 3

#define QL_TOKEN_MAX_LEN 256

/* 19.8 — STREAM frame bit-flags (within 0x08..0x0F) */
#define QL_STREAM_FLAG_FIN 0x01u
#define QL_STREAM_FLAG_LEN 0x02u
#define QL_STREAM_FLAG_OFF 0x04u

/* 18.2 — Transport parameter defaults */
#define QL_DEFAULT_ACK_DELAY_EXP 3 /* 2^3 = 8 µs units */
#define QL_DEFAULT_MAX_ACK_DELAY_MS 25
#define QL_DEFAULT_ACTIVE_CID_LIMIT 2

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

/*
 * ql_listener_t — a server's shared UDP socket plus a registry of the
 * connections it has demuxed onto it (chunk 7.1). One socket serves every
 * connection; ql_conn_t.fd for a server-side connection just aliases this
 * fd for sending — inbound demux happens here, not in ql_conn_tick.
 */
#define QL_LISTENER_MAX_CONNS 256
#define QL_LISTENER_ACCEPT_QUEUE 64

/*
 * Scratch buffer big enough to hold an unprotected header (first byte +
 * version + two CIDs + token + length field + max 4-byte pkt-num):
 * 1 + 4 + (1+20) + (1+20) + 2 + QL_TOKEN_MAX_LEN + 2 + 4 = 311, rounded up.
 */
#define QL_PKT_HDR_SCRATCH_MAX 320