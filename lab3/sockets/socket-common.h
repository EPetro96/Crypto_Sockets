/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5
#define BFR_SIZE 256
#define KEY_SIZE 16
#define BLOCK_SIZE 16

#define HELLO_THERE "Hello there!"

#endif /* _SOCKET_COMMON_H */

