/**
 * @file: server.c
 */
#include "../../include/qlite.h"

#include <signal.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char ours[] = {4, 'e', 'c', 'h', 'o'};
    if (SSL_select_next_proto((unsigned char **)out, outlen, ours, sizeof(ours), in, inlen) ==
        OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *make_ssl_ctx(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* ---- callbacks (shared by every accepted connection) ---- */

static void on_connected(ql_conn_t *conn, void *user) {
    (void)conn; (void)user;
    printf("[server] handshake confirmed\n");
}

static void on_stream_open(ql_conn_t *conn, ql_stream_t *s, void *user) {
    (void)conn; (void)user;
    printf("[server] stream %llu opened by peer\n", (unsigned long long)s->id);
}

/* Echo everything back; when the peer FINs, FIN our side too. */
static void on_data(ql_conn_t *conn, ql_stream_t *s, void *user) {
    (void)user;
    uint8_t buf[2048];
    for (;;) {
        int n = qlite_recv(conn, s, buf, sizeof(buf));
        if (n == QLITE_ERR_AGAIN) {
            break;
        }
        if (n == QLITE_ERR_CLOSED) {
            printf("[server] stream %llu reset by peer\n", (unsigned long long)s->id);
            break;
        }
        if (n == 0) { /* EOF */
            printf("[server] stream %llu: peer finished, closing our side\n",
                   (unsigned long long)s->id);
            qlite_stream_close(conn, s, 0);
            break;
        }
        if (n < 0) {
            break;
        }
        printf("[server] stream %llu: got %d bytes: %.*s\n", (unsigned long long)s->id, n, n,
               (const char *)buf);
        qlite_send(conn, s, buf, (size_t)n);
    }
}

static void on_close(ql_conn_t *conn, ql_transport_error_t err, void *user) {
    (void)conn; (void)user;
    printf("[server] connection closed (err=0x%x)\n", (unsigned)err);
}

int main(int argc, char **argv) {
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : 4433;

    signal(SIGINT, on_sigint);

    SSL_CTX *ctx = make_ssl_ctx("cert.pem", "key.pem");
    if (!ctx) {
        fprintf(stderr, "failed to set up TLS (need cert.pem / key.pem, see Makefile)\n");
        return 1;
    }

    ql_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_params.max_idle_timeout_ms                  = 30000;
    cfg.local_params.initial_max_data                     = 1 << 20;
    /* Keep per-stream windows <= QL_STREAM_BUF_SIZE (the ring buffer size). */
    cfg.local_params.initial_max_stream_data_bidi_local   = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_stream_data_bidi_remote  = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_stream_data_uni          = QL_STREAM_BUF_SIZE;
    cfg.local_params.initial_max_streams_bidi             = 100;
    cfg.local_params.initial_max_streams_uni              = 10;
    cfg.on_connected   = on_connected;
    cfg.on_stream_open = on_stream_open;
    cfg.on_data        = on_data;
    cfg.on_close       = on_close;

    ql_listener_t *l = calloc(1, sizeof(*l));
    if (!l) return 1;
    int rc = qlite_listen(l, NULL, port, &cfg, ctx);
    if (rc != QLITE_OK) {
        fprintf(stderr, "qlite_listen failed: %d\n", rc);
        return 1;
    }
    printf("[server] listening on UDP port %u\n", port);

    while (!g_stop) {
        qlite_listener_tick(l, ql_now_ms());

        /* Drain the accept queue; the listener keeps ticking these conns. */
        ql_conn_t *c;
        while ((c = qlite_accept(l)) != NULL) {
            printf("[server] accepted a connection\n");
        }
        nanosleep(&(struct timespec){0, 1000000L}, NULL);
    }

    printf("\n[server] shutting down\n");
    for (int i = 0; i < l->conn_count; i++) {
        if (l->conns[i]) {
            qlite_close(l->conns[i], true, 0, "server shutdown");
            ql_conn_tick(l->conns[i], ql_now_ms());
        }
    }
    close(l->fd);
    SSL_CTX_free(ctx);
    return 0;
}