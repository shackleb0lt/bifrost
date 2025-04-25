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

#ifndef CLIENT_TFTP_H
#define CLIENT_TFTP_H

#include "common.h"

#define PROG_BAR_LEN    64
#define UPDATE_DIFF     1024 * 128
#define OPTION_LEN      32

typedef enum
{
    ERROR_STATE = 0,
    SEND_REQ,
    RRQ_SENT,
    WRQ_SENT,
    SEND_OACK,
    RECV_ACK,
    RECV_DATA,
    SEND_ACK,
    SEND_DATA,
    WAIT_PKT,
} TFTP_CLIENT_STATE;

typedef struct 
{
    char tx_buf[PKT_BUFFER_SIZE];
    char rx_buf[PKT_BUFFER_SIZE];

    char local_name[PATH_MAX];
    char remote_name[PATH_LEN];

    size_t local_len;
    size_t remote_len;

    socklen_t addr_len;
    struct sockaddr_storage addr;

    size_t BUF_SIZE;
    size_t tx_len;
    size_t rx_len;

    size_t blk_size;
    size_t win_size;

    int conn_sock;
    int file_desc;

    off_t file_size;
    off_t curr_size;

    bool is_oack;
    bool is_tsize_off;

    TFTP_OPCODE type;
    TFTP_CLIENT_STATE state;
} tftp_request;

#endif