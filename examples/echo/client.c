/**
 * @file: client.c
 */
#include "../../include/qlite.h"

typedef struct {
    const char *message;
    ql_stream_t *stream;
    bool done;
} app_t;

static SSL_CTX *make_ssl_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    /* Demo only: don't verify the self-signed server cert. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    static const unsigned char alpn[] = {4, 'e', 'c', 'h', 'o'};
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));
    return ctx;
}

/* Handshake confirmed: peer's transport params are known, so streams
 * opened now get correct flow-control limits. */
static void on_connected(ql_conn_t *conn, void *user) {
    app_t *app = (app_t *)user;
    printf("[client] connected, opening stream\n");

    if (qlite_stream_open(conn, true, &app->stream) != QLITE_OK) {
        fprintf(stderr, "[client] stream open failed\n");
        app->done = true;
        return;
    }
    int n = qlite_send(conn, app->stream, (const uint8_t *)app->message, strlen(app->message));
    printf("[client] queued %d bytes on stream %llu\n", n, (unsigned long long)app->stream->id);
    qlite_stream_close(conn, app->stream, 0); /* graceful FIN after the data drains */
}

static void on_data(ql_conn_t *conn, ql_stream_t *s, void *user) {
    app_t *app = (app_t *)user;
    uint8_t buf[2048];
    for (;;) {
        int n = qlite_recv(conn, s, buf, sizeof(buf));
        if (n == QLITE_ERR_AGAIN) {
            break;
        }
        if (n == 0) { /* server FIN'd: we've got the full echo */
            printf("[client] echo complete, closing connection\n");
            app->done = true;
            qlite_close(conn, true, 0, "done");
            break;
        }
        if (n < 0) {
            app->done = true;
            break;
        }
        printf("[client] echo: %.*s\n", n, (const char *)buf);
    }
}

static void on_close(ql_conn_t *conn, ql_transport_error_t err, void *user) {
    (void)conn;
    printf("[client] connection closed (err=0x%x)\n", (unsigned)err);
    ((app_t *)user)->done = true;
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t port    = (argc > 2) ? (uint16_t)atoi(argv[2]) : 4433;
    app_t app        = {.message = (argc > 3) ? argv[3] : "hello over QUIC"};

    SSL_CTX *ctx = make_ssl_ctx();
    if (!ctx) return 1;

    ql_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_params.max_idle_timeout_ms                  = 30000;
    cfg.local_params.initial_max_data                     = 1 << 20;
    cfg.local_params.initial_max_stream_data_bidi_local   = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_stream_data_bidi_remote  = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_stream_data_uni          = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_streams_bidi             = 100;
    cfg.local_params.initial_max_streams_uni              = 10;
    cfg.on_connected = on_connected;
    cfg.on_data      = on_data;
    cfg.on_close     = on_close;
    cfg.user         = &app;

    /* ql_conn_t is large (sent-packet ring etc.) — keep it off the stack. */
    ql_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return 1;

    int rc = ql_conn_init(conn, QL_ROLE_CLIENT, &cfg);
    if (rc != QLITE_OK) {
        fprintf(stderr, "ql_conn_init failed: %d\n", rc);
        return 1;
    }
    rc = qlite_connect(conn, host, port, ctx);
    if (rc != QLITE_OK) {
        fprintf(stderr, "qlite_connect failed: %d\n", rc);
        return 1;
    }
    printf("[client] connecting to %s:%u\n", host, port);

    uint64_t start = ql_now_ms();
    while (ql_now_ms() - start < 10000) {
        rc = ql_conn_tick(conn, ql_now_ms());
        if (rc == QLITE_ERR_CLOSED) {
            break; /* drain finished */
        }
        if (rc < 0) {
            fprintf(stderr, "[client] tick error: %d\n", rc);
            break;
        }
        nanosleep(&(struct timespec){0, 1000000L}, NULL);
    }

    if (!app.done) {
        fprintf(stderr, "[client] timed out\n");
    }

    ql_conn_free(conn);
    free(conn);
    SSL_CTX_free(ctx);
    return app.done ? 0 : 1;
}