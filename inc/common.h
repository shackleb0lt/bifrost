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
#include <netinet/ip_icmp.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)
typedef struct in_addr *ipv4addr;

#define MIN_BLK_SIZE 8
#define DEF_BLK_SIZE 512
#define MAX_BLK_SIZE 65464

#define PATH_LEN 500
#define TFTP_PORT_NO 69

#define TFTP_TIMEOUT_MS            200
#define TFTP_MAXTIMEOUT_MS        3000
#define TFTP_NUM_RETRIES            12

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

typedef struct
{
    char local_name[PATH_MAX];
    char remote_name[PATH_LEN];

    size_t local_len;
    size_t remote_len;

    char *mode_str;
    size_t mode_len;

    int local_fd;
    off_t file_size;

    struct sockaddr_in server;
    size_t block_size;
    TFTP_OPCODE action;
    TFTP_MODE mode;
} tftp_session;

typedef struct
{
    uint16_t opcode;
    union common
    {
        char args[0];
        uint16_t block;
    } __attribute__((__packed__)) un;
    char data[0];
} __attribute__((__packed__)) tftp_pkt;


int register_sighandler(void (*handler_func)(int));
bool is_valid_blocksize(char *size, size_t *block_size);
size_t tftp_mode_to_str(TFTP_MODE mode, char **mode_str);
const char *tftp_err_to_str(TFTP_ERRCODE err_code);

#endif