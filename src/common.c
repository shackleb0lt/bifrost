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

#include "common.h"

const char *err_strs[] =
{
    "Unknown error",
    "File not found",
    "Access violation",
    "Disk full or allocation exceeded",
    "Illegal TFTP operation",
    "Unknown transfer ID",
    "File already exists",
    "No such user",
    "Bad option/s received"
};

const char *opcode_strs[] =
{
    "CODE_UNDEF",
    "CODE_RRQ",
    "CODE_WRQ",
    "CODE_DATA",
    "CODE_ACK",
    "CODE_ERROR",
    "CODE_OACK",    
};

/**
 * Returns a string literal corresponding to the error code
 * Note:- Function never returns NULL
 */
const char *tftp_err_to_str(TFTP_ERRCODE err_code)
{
    if (err_code > EBADOPT)
        err_code = EUNDEF;
    return err_strs[err_code];
}

/**
 * Returns a string literal corresponding to the op code
 * In case of unknown code, it is converted to string and returned
 */
const char *tftp_opcode_to_str(TFTP_OPCODE opcode)
{
    static _Thread_local char conv[32] = {0};

    if (opcode <= CODE_OACK)
        return opcode_strs[opcode];

    snprintf(conv, 32, "%d", opcode);
    return (const char *)conv;
}

/**
 * Copies string corresponding to the mode into the buffer.
 * Returns length of copied string
 * By default or in case of error, "octet" is stored in the buffer.
 */
size_t tftp_mode_to_str(TFTP_MODE mode, char mode_str[])
{
    char *str = NULL;
    if (mode == MODE_MAIL)
        str = "mail";
    else if (mode == MODE_NETASCII)
        str = "netascii";
    else
        str = "octet";

    strcpy(mode_str, str);
    return strlen(str);
}

/**
 * Parse the blocksize string and convert it to a number
 * Check if it falls within acceptable limit of 8 to 65464 bytes
 * Stores the parsed number in location pointed by block_size parameter
 * @return true if valid, false otherwise
 */
bool is_valid_blocksize(const char *size_str, size_t *block_size)
{
    size_t total = 0;
    size_t index = 0;

    if (size_str == NULL || *size_str == '\0')
        return false;

    for (index = 0; size_str[index] != '\0'; index++)
    {
        if (size_str[index] < '0' || size_str[index] > '9')
            return false;

        total *= 10;
        total += (uint8_t)(size_str[index] - '0');

        if (total > MAX_BLK_SIZE)
            return false;
    }

    if (total < MIN_BLK_SIZE)
        return false;

    *block_size = total;
    return true;
}

/**
 * Parse the window size string and convert it to a number
 * Check if its value is in accordance with RFC 7440
 * Stores the parsed number in location pointed by win_size parameter
 * @return true if valid, false otherwise
 */
bool is_valid_windowsize(const char *size_str, size_t *win_size)
{
    size_t total = 0;
    size_t index = 0;

    if (size_str == NULL || *size_str == '\0')
        return false;

    for (index = 0; size_str[index] != '\0'; index++)
    {
        if (size_str[index] < '0' || size_str[index] > '9')
            return false;

        total *= 10;
        total += (uint8_t)(size_str[index] - '0');

        if (total > MAX_WIN_SIZE)
            return false;
    }

    if (total == 0)
        return false;

    *win_size = total;
    return true;
}

/**
 * Parse the port num string and convert it to a number
 * Stores the parsed number in location pointed by port num parameter
 * @return true if valid, false otherwise
 */
bool is_valid_portnum(const char *size_str, uint16_t *port_num)
{
    size_t total = 0;
    size_t index = 0;

    if (size_str == NULL || *size_str == '\0')
        return false;

    for (index = 0; size_str[index] != '\0'; index++)
    {
        if (size_str[index] < '0' || size_str[index] > '9')
            return false;

        total *= 10;
        total += (uint8_t)(size_str[index] - '0');

        if (total > MAX_PORT_NUM)
            return false;
    }

    *port_num = (uint16_t)total;
    return true;
}

/**
 * Parse the file size string and convert it to a number
 * Stores the parsed number in location pointed by port num parameter
 * Maximum file size supported right now is MAX_BLOCK_SIZE * MAX_BLOCK_NUM
 * If rollover is implemented we can transmit larger files even with smaller blk size
 * @return true if valid, false otherwise
 */
bool is_valid_filesize(const char *size_str, off_t *file_size)
{
    off_t total = 0;
    size_t index = 0;

    if (size_str == NULL || *size_str == '\0')
        return false;

    for (index = 0; size_str[index] != '\0'; index++)
    {
        if (size_str[index] < '0' || size_str[index] > '9')
            return false;

        total *= 10;
        total += (uint8_t)(size_str[index] - '0');

        if (total > MAX_FILE_SIZE)
            return false;
    }

    *file_size = total;
    return true;
}

/**
 * Scans the string received in OACK by client or in Request by server
 * If an option with name opt is present return it's value as str
 *
 * Returns NULL if such an option was not found
 */
char *get_option_val(const char *opt, char oack_str[], size_t len)
{
    size_t i = 0;
    bool is_found = false;

    while (i < len)
    {
        if (oack_str[i] == '\0')
        {
            if (is_found)
                return oack_str;

            if (strcasecmp(oack_str, opt) == 0)
                is_found = true;

            i++;
            oack_str += i;
            len -= i;
            i = 0;
        }
        else
            i++;
    }
    return NULL;
}

/**
 * Add TFTP options to a buffer of size buf_len
 * Use passed parameters for filling the buffer
 *
 * @return 0 on success, -1 if buffer is insufficient
 */
size_t insert_options(char buf[], size_t blk_size, off_t file_size, size_t win_size)
{
    size_t op_len = 0;
    size_t curr_len = 0;
    char option[64] = {0};
    char *curr_ptr = buf;

    if (blk_size != DEF_BLK_SIZE)
    {
        op_len = (size_t)snprintf(option, 64, "%lu", blk_size);
        curr_len += BLKSIZE_OPLEN + op_len + 2;

        strcpy(curr_ptr, BLKSIZE_OP);
        curr_ptr += BLKSIZE_OPLEN + 1;
        strcpy(curr_ptr, option);
        curr_ptr += op_len + 1;
    }

    if (file_size != -1)
    {
        op_len = (size_t)snprintf(option, 64, "%lu", file_size);
        curr_len += TSIZE_OPLEN + op_len + 2;

        strcpy(curr_ptr, TSIZE_OP);
        curr_ptr += TSIZE_OPLEN + 1;
        strcpy(curr_ptr, option);
        curr_ptr += op_len + 1;
    }

    if (win_size != DEF_WIN_SIZE)
    {
        op_len = (size_t)snprintf(option, 64, "%lu", win_size);
        curr_len += WINSIZE_OPLEN + op_len + 2;

        strcpy(curr_ptr, WINSIZE_OP);
        curr_ptr += WINSIZE_OPLEN + 1;
        strcpy(curr_ptr, option);
        curr_ptr += op_len + 1;
    }

    return curr_len;
}

/**
 * Extract TFTP options from buffer of length buf_len
 * Validate the options and store in the pointers
 * @return 0 if extracted parameters are valid, -1 on failure
 */
int extract_options(char buf[], size_t buf_len, size_t *blk_size, off_t *t_size, size_t *win_size)
{
    char *val = NULL;

    if (blk_size)
    {
        val = get_option_val(BLKSIZE_OP, buf, buf_len);
        if (val && is_valid_blocksize(val, blk_size) == false)
        {
            LOG_ERROR("%s: Received invalid block size %s", __func__, val);
            return -1;
        }
    }

    if (t_size)
    {
        val = get_option_val(TSIZE_OP, buf, buf_len);
        if (val && is_valid_filesize(val, t_size) == false)
        {
            LOG_ERROR("%s: Received invalid file size %s", __func__, val);
            return -1;
        }
    }

    if (win_size)
    {
        val = get_option_val(WINSIZE_OP, buf, buf_len);
        if (val && is_valid_windowsize(val, win_size) == false)
        {
            LOG_ERROR("%s: Received invalid window size %s", __func__, val);
            return -1;
        }
    }

    return 0;
}

/**
 * Function to register signal handler during initialisation
 * allows to catch interrupt signals and gracefully exit
 */
int register_sighandler(void (*handler_func)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler_func;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        LOG_ERROR("sigaction: SIGTERM: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        LOG_ERROR("sigaction: SIGINT: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1)
    {
        LOG_ERROR("sigaction: SIGHUP: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1)
    {
        LOG_ERROR("sigaction: SIGHUP: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * Prints a tftp request buffer in presentable format
 */
void print_tftp_request(char *buf, size_t len)
{
    TFTP_OPCODE code = get_opcode(buf);
    LOG_RAW("[INFO ] %s ", tftp_opcode_to_str(code));

    buf += ARGS_HDR_LEN;
    len -= ARGS_HDR_LEN;

    while (len)
    {
        size_t curr_len = strnlen(buf, DEF_BLK_SIZE);
        LOG_RAW("%s ", buf);

        if (curr_len >= len)
            break;

        len -= curr_len + 1;
        buf += curr_len + 1;
    }

    LOG_RAW("\n");
}

/**
 * Parses the received packet to extract error code
 * and error message if any sent by the server.
 */
void handle_error_packet(char rx_buf[], ssize_t b_recv)
{
    TFTP_ERRCODE err_code = get_blocknum(rx_buf);
    rx_buf += DATA_HDR_LEN;
    b_recv -= DATA_HDR_LEN;

    if (b_recv == 0)
        rx_buf = (char *)tftp_err_to_str(err_code);
    else
        rx_buf[b_recv] = '\0';
#ifdef DEBUG
    LOG_ERROR("(%d): %s", err_code, rx_buf);
#else
    LOG_ERROR("%s", rx_buf);
#endif
}

/**
 * 
 */
size_t tftp_rollover_blocknumber(size_t block_number, size_t prev_block_number)
{
    unsigned short b = (unsigned short)block_number;
    unsigned short pb = (unsigned short)prev_block_number;
    long result = b | (prev_block_number & ~0xFFFF);
    if (b < 0x4000 && pb > 0xC000)
    result += 0x10000;
    else if (b > 0xC000 && pb < 0x4000 && (prev_block_number & ~0xFFFF))
    result -= 0x10000;
    return result;
}

/**
 * Securely reads data upto 'buf_size' bytes atan offset calulated
 * from absolute blocksize, into 'buf'. Using the file descriptor fd.
 * Returns the length of data actually read or -1 in case or error
 */
ssize_t file_read(int fd, void *buf, size_t buf_size, size_t abs_blk_num)
{
    char *ptr = buf;
    ssize_t total_read = 0, bytes_read = 0;
    off_t offset = ((off_t) abs_blk_num - 1) * (off_t) buf_size;

    while (buf_size > 0)
    {
        bytes_read = pread(fd, ptr, buf_size, offset);
        if (bytes_read < 0)
        {
            if (errno == EINTR)
                continue;
            
            LOG_ERROR("pread: %s", strerror(errno));
            return -1;
        }

        if (bytes_read == 0)
            break;
        
        ptr += bytes_read;
        offset += bytes_read;
        buf_size -= (size_t) bytes_read;
        total_read += bytes_read;
    }

    return total_read;
}

/**
 * Securely write data upto 'count' bytes to a file descriptor from 'buf'
 * Returns the length of data actually written or -1 in case or error
 */
ssize_t file_write(int fd, const void *buf, size_t count)
{
    ssize_t total_written = 0;
    const char *ptr = buf;

    while (count > 0)
    {
        ssize_t written = write(fd, ptr, count);

        if (written < 0)
        {
            if (errno == EINTR)
                continue;

            LOG_ERROR("write: %s", strerror(errno));
            return -1;
        }

        if (written == 0)
            break;

        ptr += written;
        count -= (size_t)written;
        total_written += written;
    }

    return total_written;
}

/**
 * 
 */
ssize_t safe_recv(int fd, void *buf, size_t buf_size, int timeout)
{
    struct pollfd pfd = {0};
    int poll_ret = 0;
	ssize_t bytes_recv = 0;

	while (1)
    {
        pfd.fd = fd;
        pfd.events = POLLIN;
        poll_ret = poll(&pfd, 1, timeout);
        if (poll_ret == 0)
            return 0;
        else if (poll_ret > 0)
            break;
        else if (poll_ret < 0 && errno != EINTR)
        {
            LOG_ERROR("%s poll: %s", __func__, strerror(errno));
            return -1;
        }
	}

    bytes_recv = recv(fd, buf, buf_size, 0);
    if (bytes_recv < 0)
    {
        LOG_ERROR("%s recv: %s", __func__, strerror(errno));
        return -1;
    }
    else if (bytes_recv < DATA_HDR_LEN)
    {
        LOG_ERROR("%s: Received packet is too small (%ld bytes)", __func__, bytes_recv);
        return -1;
    }

	return bytes_recv;
}

/**
 * Converts error code to a string, or uses
 * err_str contents to create an error packet
 * This packet is sent to the server/client
 * indicating an error occurred and stop transfer
 */
void send_error_packet(int conn_sock, char *err_str, TFTP_ERRCODE err_code)
{
    size_t len = 0;
    char buf[DATA_HDR_LEN + DEF_BLK_SIZE] = {0};

    set_opcode(buf, CODE_ERROR);
    set_blocknum(buf, err_code);
    len += DATA_HDR_LEN;
    if (err_str == NULL)
        len += (size_t)snprintf(buf + DATA_HDR_LEN, DEF_BLK_SIZE, "%s", tftp_err_to_str(err_code));
    else
        len += (size_t)snprintf(buf + DATA_HDR_LEN, DEF_BLK_SIZE, "%s", err_str);

    send(conn_sock, buf, len, 0);
}