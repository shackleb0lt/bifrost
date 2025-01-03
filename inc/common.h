/**
 * MIT License
 * Copyright (c) 2024 Aniruddha Kawade
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <inttypes.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define get_opcode(buf)     ntohs(((uint16_t *)buf)[0])
#define get_blocknum(buf)   ntohs(((uint16_t *)buf)[1])

#define set_opcode(buf, x)   ((uint16_t *)buf)[0] = htons((uint16_t)(x))
#define set_blocknum(buf, x) ((uint16_t *)buf)[1] = htons((uint16_t)(x))

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)

#define MIN_BLK_SIZE 8
#define DEF_BLK_SIZE 512
#define MAX_BLK_SIZE 65464

#define PATH_LEN        500
#define TFTP_PORT_NO    69
#define DATA_HDR_LEN    4
#define ARGS_HDR_LEN    2

#define TFTP_TIMEOUT_MS            200
#define TFTP_MAXTIMEOUT_MS        3000
#define TFTP_NUM_RETRIES            12

#define BLKSIZE_OP      "blksize"
#define BLKSIZE_OPLEN   7
#define TSIZE_OP        "tsize"
#define TSIZE_OPLEN     5
#define WINDOW_OP       "windowsize"
#define WINDOW_OPLEN    10

typedef enum
{
    CODE_UNDEF = 0,
    CODE_RRQ = 1,
    CODE_WRQ = 2,
    CODE_DATA = 3,
    CODE_ACK = 4,
    CODE_ERROR = 5,
    CODE_OACK = 6
} TFTP_OPCODE;

typedef enum
{
    EUNDEF = 0,
    ENOTFOUND = 1,
    EACCESS = 2,
    ENOSPACE = 3,
    EBADOP = 4,
    EBADID = 5,
    EEXISTS = 6,
    ENOUSER = 7,
    EBADOPT = 8,
} TFTP_ERRCODE;

typedef enum
{
    MODE_OCTET = 0,
    MODE_NETASCII = 1,
    MODE_MAIL = 2,
} TFTP_MODE;

typedef enum 
{
    PROG_START = 0,
    PROG_UPDATE = 1,
    PROG_FINISH = 2,
    PROG_ERROR = 3,
} TFTP_PROGRESS;


int register_sighandler(void (*handler_func)(int));

bool is_valid_blocksize(char *size, size_t *block_size);

size_t tftp_mode_to_str(TFTP_MODE mode, char **mode_str);

const char *tftp_err_to_str(TFTP_ERRCODE err_code);

char *get_option_val(const char *opt, char *oack_str, ssize_t len);

#endif