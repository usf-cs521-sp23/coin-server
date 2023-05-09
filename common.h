#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>

#include "task.h"

#ifndef VERSION
#define VERSION 1.0
#endif

#define DEBUG_ON 1

struct __attribute__((__packed__)) msg_header {
    uint64_t msg_len;
    uint16_t msg_type;
};

struct __attribute__((__packed__)) msg_request_task {
    struct msg_header header;
    char username[20];
};

struct __attribute__((__packed__)) msg_task {
        struct msg_header header;
        uint64_t sequence_num;
        char block[MAX_BLOCK_LEN];
        uint32_t difficulty;
};

struct __attribute__((__packed__)) msg_solution {
        struct msg_header header;
        char username[20];
        char block[MAX_BLOCK_LEN];
        uint32_t difficulty;
        uint64_t nonce;
};

struct __attribute__((__packed__)) msg_verification {
        struct msg_header header;
        bool ok;
        char error_description[128];
};

struct __attribute__((__packed__)) msg_heartbeat {
        struct msg_header header;
        char username[20];
        uint64_t sequence_num;
};

union __attribute__((__packed__)) msg_wrapper {
        struct msg_header header;
        struct msg_request_task request_task;
        struct msg_task task;
        struct msg_solution solution;
        struct msg_verification verification;
        struct msg_heartbeat heartbeat;
};

enum MSG_TYPES {
        MSG_REQUEST_TASK,
        MSG_TASK,
        MSG_SOLUTION,
        MSG_VERIFICATION,
        MSG_HEARTBEAT,
};

size_t msg_size(enum MSG_TYPES type);

/**
 * Function: read_len
 * Purpose:  reads from an input stream, retrying until a specific number of
 *           bytes has been read. This ensures complete message delivery.
 *
 * Args:
 *  * fd     - the file descriptor to read from
 *  * buf    - pointer to buffer to store data
 *  * length - size of the incoming message. If less than 'length' bytes are
 *             received, we'll keep retrying the read() operation.
 */
int read_len(int fd, void *buf, size_t length);

int write_len(const int fd, const void *buf, size_t length);

union msg_wrapper create_msg(enum MSG_TYPES type);

int read_msg(int fd, union msg_wrapper *msg);

int write_msg(int fd, const union msg_wrapper *msg);

#endif
