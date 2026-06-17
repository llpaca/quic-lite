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
#include <string.h>
#include <errno.h>
#include <time.h>

/* POSIX — needed in implementation but declared here so all TUs agree */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>



#if defined(__cplusplus)
} /* extern "C" */
#endif
#endif /* QLITE_H */