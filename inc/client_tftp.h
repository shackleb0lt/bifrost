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
#define UPDATE_DIFF     1024*128

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
    off_t curr_size;

    struct sockaddr_in server;
    struct sockaddr *addr;

    size_t block_size;
    TFTP_OPCODE action;
    TFTP_MODE mode;
} tftp_session;

#endif