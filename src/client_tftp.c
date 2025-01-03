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

#include "client_tftp.h"

bool is_prog_bar = true;
char *g_exe_name = NULL;
tftp_session g_sess_args;

/**
 * Prints the usage of the tftp client binary
 */
void print_usage(char *err_str)
{
    if (err_str != NULL && *err_str != '\0')
        printf("Error: %s\n", err_str);

    printf("\nUsage:\n");
    printf("  %s [OPTION]... HOST [PORT]\n\n", g_exe_name);
    printf("Options:\n");
    printf("  %-18s Get/Download file\n",   "-g");
    printf("  %-18s Put/Upload file\n",     "-p");
    printf("  %-18s Local file path\n",     "-l FILE");
    printf("  %-18s Remote file path\n",    "-r FILE");
    printf("  %-18s Transfer block size 8 - 65464\n", "-b SIZE");
    printf("  %-18s show usage and exit\n", "-h");
    printf("Note: Option -p or -g is mandatory, and they are mutually exclusive\n");
    printf("    : Option -l and -r are both mandatory\n");
    printf("    : Default block size is 512 bytes\n");
}

/**
 * Parses the local and file names for validity
 * Autocompletes the destination path if it's a directory
 * by using the filename of source path.
 * Also opens the local file and stores the descriptor in args
 * @return true if valid filenames, false otherwise
 */
int parse_parameters()
{
    size_t len = 0;
    struct stat st = {0};
    char *filename = NULL;

    g_sess_args.local_fd = -1;

    if (g_sess_args.action == CODE_WRQ)
    {
        if (g_sess_args.local_name[g_sess_args.local_len - 1] == '/')
        {
            fprintf(stderr, "%s: local file path is directory\n", g_sess_args.local_name);
            return -1;
        }

        if (access(g_sess_args.local_name, F_OK | R_OK) != 0)
        {
            fprintf(stderr, "%s: %s\n", g_sess_args.local_name, strerror(errno));
            return -1;
        }

        if (g_sess_args.remote_name[g_sess_args.remote_len - 1] == '/')
        {
            filename = strrchr(g_sess_args.local_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN);
            }
            else
            {
                filename = g_sess_args.local_name;
                len = g_sess_args.local_len;
            }

            if ((g_sess_args.remote_len + len) >= PATH_LEN)
            {
                fprintf(stderr, "Destination file name %s%s is too long", g_sess_args.remote_name, filename);
                return -1;
            }
            strncat(g_sess_args.remote_name, filename, len);
            g_sess_args.remote_len += len; 
        }

        if (stat(g_sess_args.local_name, &st) == -1)
        {
            fprintf(stderr, "Could not stat file %s\n", g_sess_args.local_name);
            return -1;
        }

        g_sess_args.file_size = st.st_size;
        g_sess_args.local_fd = open(g_sess_args.local_name, O_RDONLY);
    }
    else if (g_sess_args.action == CODE_RRQ)
    {
        if (g_sess_args.remote_name[g_sess_args.remote_len - 1] == '/')
        {
            fprintf(stderr, "%s: Remote file path is directory\n", g_sess_args.remote_name);
            return -1;
        }

        if (g_sess_args.local_name[g_sess_args.local_len - 1] == '/')
        {
            filename = strrchr(g_sess_args.remote_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN - 1);
            }
            else
            {
                filename = g_sess_args.remote_name;
                len = g_sess_args.remote_len;
            }

            if ((g_sess_args.local_len + len) >= PATH_MAX)
            {
                fprintf(stderr, "Local file name %s%s will be too long\n", g_sess_args.local_name, filename);
                return -1;
            }
            strncat(g_sess_args.local_name, filename, len);
            g_sess_args.local_len += len;
        }
        g_sess_args.local_fd = open(g_sess_args.local_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    }

    if (g_sess_args.local_fd < 0)
    {
        fprintf(stderr, "Unable to open local file %s: %s\n", g_sess_args.local_name, strerror(errno));
        return -1;
    }

    g_sess_args.mode_len = tftp_mode_to_str(g_sess_args.mode, &(g_sess_args.mode_str));

    if ((4 + g_sess_args.remote_len + g_sess_args.mode_len) > DEF_BLK_SIZE)
    {
        fprintf(stderr, "Remote file name is too long");
        close(g_sess_args.local_fd);
        return -1;
    }

    return 0;
}

/**
 * Function that catches signal and terminates the program gracefully
 */
void handle_signal(int sig)
{
    struct sigaction sa;
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
    exit(128 + sig);
}

/**
 * Convert hostname or ipv4 address from string to
 * network form and stores in dest_addr pointer.
 * @returns A static string which hold presentation form
 */
char *get_dest_addr(const char *input, char *port_no, struct sockaddr_in *dest_addr)
{
    int ret = 0;
    unsigned long port = TFTP_PORT_NO;
    struct addrinfo hint;
    struct addrinfo *res;
    static char ipstr[INET_ADDRSTRLEN] = {0};

    if(port_no)
    {
        port = strtoul(port_no, NULL, 10);
        if (port == 0 || errno)
            return NULL;
        else if(port > 65535)
            return NULL;
    }
    
    dest_addr->sin_port = htons((in_port_t) port);

    dest_addr->sin_family = AF_INET;

    // Check if string is of the form "X.X.X.X"
    ret = inet_pton(AF_INET, input, &(dest_addr->sin_addr));
    if (ret == 1)
    {
        strncpy(ipstr, input, INET_ADDRSTRLEN - 1);
        return ipstr;
    }

    // If a hostname was provided then lookup it's ip address
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = 0;

    ret = getaddrinfo(input, NULL, &hint, &res);
    if (ret != 0 || res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return NULL;
    }
    dest_addr->sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    inet_ntop(AF_INET, &(dest_addr->sin_addr), ipstr, INET_ADDRSTRLEN);
    return ipstr;
}

/**
 * Function that prints a progress bar to display 
 * the transfer rate to the user.
 */
void update_prog_bar(TFTP_PROGRESS ptype)
{
    static size_t p_size = 0;
    static size_t p_per = 0;
    static bool is_init = false;
    static char p_bar[PROG_BAR_LEN + 1] = {0};

    size_t c_per = 0;
    size_t       index = 0;
    if (!is_init && ptype == PROG_START)
    {
        is_init = true;
        p_per = 0;
        memset(p_bar, ' ', PROG_BAR_LEN);
        printf("\r[%s] %lu%% (%lu) bytes", p_bar, c_per, g_sess_args.curr_size);
        fflush(stdout);
    }

    if (!is_init)
        return;
    
    if(ptype == PROG_FINISH)
    {
        c_per = (100 * g_sess_args.curr_size) / g_sess_args.file_size;
        memset(p_bar, '=', PROG_BAR_LEN);
        printf("\r[%s] %lu%% (%lu) bytes\n", p_bar, c_per, g_sess_args.curr_size);
        fflush(stdout);
    }
    else if(ptype == PROG_ERROR)
    {
        printf("\n");
        fflush(stdout);
    }
    else if(ptype == PROG_UPDATE)
    {
        c_per = (100 * g_sess_args.curr_size) / g_sess_args.file_size;
        index = PROG_BAR_LEN * c_per / 100;

        memset(p_bar, '=', index);
        if(c_per > p_per || (size_t) g_sess_args.curr_size > (p_size + UPDATE_DIFF))
        {
            printf("\r[%s] %lu%% (%lu) bytes", p_bar, c_per, g_sess_args.curr_size);
            fflush(stdout);
            p_per = c_per;
            p_size = g_sess_args.curr_size;
        }
    }
}

/**
 * Parses the received packet to extract error code
 * and error message if any sent by the server.
 * Prints the same to the stderr
 */
void display_error_packet(char *rx_buf)
{
    char *err_msg = rx_buf + DATA_HDR_LEN;
    TFTP_ERRCODE err_code = get_blocknum(rx_buf);
    size_t len = strnlen(err_msg, g_sess_args.block_size - 1);

    err_msg[len] = '\0';

    if(len == 0)
        fprintf(stderr, "server error: %s\n", tftp_err_to_str(err_code));
    else
        fprintf(stderr, "server error: %s\n", err_msg);
}

/**
 * Allocates buffer memory for tx and rx packets
 * Releases previous dynamic memory before allocating new one
 * 
 * Returns 0 on failure, else buffer size on success
 */
size_t allocate_packet_buf(char **buf1, char **buf2)
{
    char *tx_buf = *buf1;
    char *rx_buf = *buf2;
    size_t SIZE = g_sess_args.block_size + DATA_HDR_LEN;

    if (tx_buf)
        free(tx_buf);
    if (rx_buf)
        free(rx_buf);

    tx_buf = (char *)malloc(SIZE);
    if (!tx_buf)
    {
        (*buf1) = NULL;
        (*buf2) = NULL;
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        return 0;
    }

    rx_buf = (char *)malloc(SIZE);
    if (!rx_buf)
    {
        (*buf1) = NULL;
        (*buf2) = NULL;
        free(tx_buf);
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        return 0;
    }

    memset(tx_buf, 0, SIZE);
    memset(rx_buf, 0, SIZE);

    (*buf1) = tx_buf;
    (*buf2) = rx_buf;
    return SIZE;
}

/**
 * Parse the received string in OACK packet
 * for the options acknowledged by the server
 * 
 * Returns -1 on error, 0 otherwise
 */
int recieve_oack_packet(char *args, ssize_t len)
{
    char *val = NULL;

    val = get_option_val("tsize", args, len);
    if (val && g_sess_args.action == CODE_RRQ)
        g_sess_args.file_size = (off_t)strtoull(val, NULL, 10);
    
    if (g_sess_args.block_size == DEF_BLK_SIZE)
        return 0;

    val = get_option_val("blksize", args, len);
    if (val == NULL)
    {
        g_sess_args.block_size = DEF_BLK_SIZE;
        return 0;
    }

    if(!is_valid_blocksize(val, &(g_sess_args.block_size)))
    {
        fprintf(stderr, "Illegal blocksize %s\n", val);
        return -1;
    }

    return 0;
}

/**
 * Function that sets up the socket for future communication
 * Also performs some security check to be sure packet
 * originated from intended source.
 * 
 * Returns the size of the data read in first packet, -1 on error.
 */
ssize_t receive_first_packet(int conn_fd, char *rx_buf, size_t BUF_SIZE)
{
    int ret = 0;
    ssize_t bytes_read = 0;
    socklen_t s_len = SOCKADDR_SIZE;
    struct in_addr saved_addr = {0};

    saved_addr.s_addr = g_sess_args.server.sin_addr.s_addr;
    bytes_read = recvfrom(conn_fd, rx_buf, BUF_SIZE, 0, g_sess_args.addr, &s_len);
    if (bytes_read > 0)
    {
        if (saved_addr.s_addr != g_sess_args.server.sin_addr.s_addr)
        {
            fprintf(stderr, "Received response from unknown IP address\n");
            return -1;
        }

        ret = connect(conn_fd, g_sess_args.addr, SOCKADDR_SIZE);
        if (ret != 0)
        {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            return -1;
        }
    }
    return bytes_read;
}

/**
 * Fill the buffer with TFTP request data to server
 * following the  RFC 1350 specifications 
 * Returns the packet length which can be supplied
 * to sendto function along with the buffer 
 */
size_t construct_first_packet(char *tx_buf)
{
    int op_len = 0;
    size_t tx_len = 0;
    char op_buf[16] = {0};
    char *curr_ptr = tx_buf + ARGS_HDR_LEN;

    set_opcode(tx_buf, g_sess_args.action);

    strncpy(curr_ptr, g_sess_args.remote_name, g_sess_args.remote_len);
    curr_ptr += g_sess_args.remote_len + 1;

    strncpy(curr_ptr, g_sess_args.mode_str, g_sess_args.mode_len);
    curr_ptr += g_sess_args.mode_len + 1;

    tx_len = (size_t)(curr_ptr - tx_buf);

    if (g_sess_args.block_size != DEF_BLK_SIZE)
    {
        op_len = snprintf(op_buf, 16, "%lu", g_sess_args.block_size);
        tx_len += (size_t)op_len + BLKSIZE_OPLEN + 2;

        if (tx_len > DEF_BLK_SIZE)
        {
            fprintf(stderr, "Remote path too long\n");
            return (size_t)-1;
        }

        strncpy(curr_ptr, BLKSIZE_OP, BLKSIZE_OPLEN + 1);
        curr_ptr += BLKSIZE_OPLEN + 1;

        strncpy(curr_ptr, op_buf, (size_t) op_len);
        curr_ptr += op_len + 1;
    }

    op_len = snprintf(op_buf, 16, "%lu", g_sess_args.file_size);
    tx_len += (size_t)op_len + TSIZE_OPLEN + 2;

    if (tx_len > DEF_BLK_SIZE)
    {
        fprintf(stderr, "Remote path too long\n");
        return (size_t)-1;
    }

    strncpy(curr_ptr, TSIZE_OP, TSIZE_OPLEN + 1);
    curr_ptr += TSIZE_OPLEN + 1;

    strncpy(curr_ptr, op_buf, (size_t) op_len);
    curr_ptr += op_len + 1;

    tx_len = (size_t)(curr_ptr - tx_buf);
    return tx_len;
}

/**
 * Construct the next block for TFTP transfer
 * Can be an ACK  packet in case of download
 * Can be a DATA packet in case of upload
 * 
 * Returns the packet length which can be supplied
 * to sendto function along with the buffer 
 */
size_t construct_next_packet(char *tx_buf, size_t prev_block)
{
    size_t tx_len = 0;
    ssize_t bytes_read = 0;
    char *curr_ptr = tx_buf + DATA_HDR_LEN;

    tx_len = DATA_HDR_LEN;
    if(g_sess_args.action == CODE_RRQ)
    {
        set_opcode(tx_buf, CODE_ACK);
        set_blocknum(tx_buf, prev_block);
        return tx_len;
    }

    set_opcode(tx_buf, CODE_DATA);
    set_blocknum(tx_buf, prev_block + 1);

    bytes_read = read(g_sess_args.local_fd, curr_ptr, g_sess_args.block_size);
    if (bytes_read < 0)
        return (size_t) -1;

    tx_len += (size_t) bytes_read;
    return tx_len;
}

/**
 * Construct a packet mentioning the error code and message
 * to be sent to the server, causing termination from server side
 * 
 * Returns size of the packet to be sent
 */
size_t construct_error_packet(char *tx_buf, TFTP_ERRCODE err_code, char *err_msg, bool is_op)
{
    int tx_len = DATA_HDR_LEN;
    char *curr_ptr = tx_buf + DATA_HDR_LEN;
    set_opcode(tx_buf, CODE_ERROR);
    set_blocknum(tx_buf, err_code);

    if (err_msg)
        tx_len += snprintf(curr_ptr, g_sess_args.block_size - 1, "%s: %s", err_msg, strerror(errno));
    else
        tx_len += snprintf(curr_ptr, g_sess_args.block_size - 1, "%s", tftp_err_to_str(err_code));

    if(is_op)
        fprintf(stderr, "%s\n", curr_ptr);
    return (size_t)tx_len;
}

void perform_download()
{
    int ret = 0;
    int conn_fd = -1;
    struct pollfd pfd = {0};

    bool is_first_pkt = true;
    bool is_finished = false;
    bool is_oack_exp = true;

    size_t e_block_num = 1;
    size_t r_block_num = 1;
    ssize_t bytes_sent = 0;
    ssize_t bytes_read = 0;

    size_t tx_len = 0;
    TFTP_OPCODE r_opcode = CODE_UNDEF;

    int retries = TFTP_NUM_RETRIES;
    int wait_time = TFTP_TIMEOUT_MS;

    char *tx_buf = NULL;
    char *rx_buf = NULL;

    size_t BUF_SIZE = allocate_packet_buf(&tx_buf, &rx_buf);
    if (!BUF_SIZE)
        return;

    conn_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn_fd < 0)
    {
        fprintf(stderr, "socket %s\n", strerror(errno));
        free(tx_buf);
        free(rx_buf);
        return;
    }

    tx_len = construct_first_packet(tx_buf);
    if (tx_len == (size_t)-1)
        goto exit_transfer;

    goto send_again;

send_packet:
    tx_len = construct_next_packet(tx_buf, r_block_num);

    retries = TFTP_NUM_RETRIES;
    wait_time = TFTP_TIMEOUT_MS;

send_again:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, g_sess_args.addr, SOCKADDR_SIZE);
    if (bytes_sent != (ssize_t)tx_len)
    {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        goto exit_transfer;
    }

    if (is_finished)
    {
        update_prog_bar(PROG_FINISH);
        goto exit_transfer;
    }

recv_again:
    pfd.fd = conn_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, wait_time);
    if (ret == 0)
    {
        retries--;
        if (retries == 0)
        {
            fprintf(stderr, "TFTP timeout\n");
            goto exit_transfer;
        }
        wait_time += (wait_time >> 1);
        if (wait_time > TFTP_MAXTIMEOUT_MS)
            wait_time = TFTP_MAXTIMEOUT_MS;
        goto send_again;
    }
    else if (ret < 0)
    {
        tx_len = construct_error_packet(tx_buf, EUNDEF, "epoll", true);
        goto send_err_packet;
    }

    if (is_first_pkt)
    {
        is_first_pkt = false;
        bytes_read = receive_first_packet(conn_fd, rx_buf, BUF_SIZE);
        if (bytes_read <= 0)
            goto exit_transfer;
    }
    else
    {
        bytes_read = recv(conn_fd, rx_buf, BUF_SIZE, 0);
        if (bytes_read <= 0)
        {
            tx_len = construct_error_packet(tx_buf, EUNDEF, "recv", true);
            goto send_err_packet;
        }
    }

    r_opcode = get_opcode(rx_buf);

    if (is_oack_exp)
    {
        is_oack_exp = false;
        if (r_opcode == CODE_OACK)
        {
            ret = recieve_oack_packet(rx_buf + ARGS_HDR_LEN, bytes_read - ARGS_HDR_LEN);
            if (ret == -1)
            {
                tx_len = construct_error_packet(tx_buf, EBADOPT, NULL, false);
                goto send_err_packet;
            }
        }
        else 
            g_sess_args.block_size = DEF_BLK_SIZE;

        if (g_sess_args.block_size != (BUF_SIZE - DATA_HDR_LEN))
        {
            BUF_SIZE = allocate_packet_buf(&tx_buf, &rx_buf);
            if(!BUF_SIZE)
                goto exit_transfer;
        }

        if(g_sess_args.file_size)
            update_prog_bar(PROG_START);

        if (r_opcode == CODE_OACK)
        {
            // To send ACK 0 for the OACK
            r_block_num = 0;
            goto send_packet;
        }
    }
    
    if (r_opcode == CODE_DATA)
    {
        r_block_num = get_blocknum(rx_buf);
        if (r_block_num == e_block_num)
        {
            char *data = rx_buf + DATA_HDR_LEN;
            bytes_sent = write(g_sess_args.local_fd, data, (size_t)(bytes_read - DATA_HDR_LEN));
            if (bytes_sent != (bytes_read - DATA_HDR_LEN))
            {
                tx_len = construct_error_packet(tx_buf, ENOSPACE, "write", true);
                goto send_err_packet;
            }

            g_sess_args.curr_size += bytes_sent;
            update_prog_bar(PROG_UPDATE);

            if ((size_t)(bytes_read - 4) < g_sess_args.block_size)
                is_finished = true;

            e_block_num++;
            goto send_packet;
        }
    }
    else if (r_opcode == CODE_ERROR)
    {
        display_error_packet(rx_buf);
        goto exit_transfer;
    }

    goto recv_again;

send_err_packet:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, g_sess_args.addr, SOCKADDR_SIZE);

exit_transfer:
    close(conn_fd);
    close(g_sess_args.local_fd);
    free(tx_buf);
    free(rx_buf);

    if (!is_finished)
        remove(g_sess_args.local_name);
}

void perform_upload()
{
    int ret = 0;
    int conn_fd = -1;
    struct pollfd pfd = {0};

    bool is_first_pkt = true;
    bool is_finished = false;
    bool is_oack_exp = true;

    size_t e_block_num = 0;
    size_t r_block_num = 0;
    ssize_t bytes_sent = 0;
    ssize_t bytes_read = 0;

    size_t tx_len = 0;
    TFTP_OPCODE r_opcode = CODE_UNDEF;

    int retries = TFTP_NUM_RETRIES;
    int wait_time = TFTP_TIMEOUT_MS;

    char *tx_buf = NULL;
    char *rx_buf = NULL;

    size_t BUF_SIZE = allocate_packet_buf(&tx_buf, &rx_buf);
    if (!BUF_SIZE)
        return;

    conn_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn_fd < 0)
    {
        fprintf(stderr, "socket %s\n", strerror(errno));
        free(tx_buf);
        free(rx_buf);
        return;
    }

    tx_len = construct_first_packet(tx_buf);
    if (tx_len == (size_t)-1)
        goto exit_transfer;

    goto send_again;

send_packet:
    tx_len = construct_next_packet(tx_buf, r_block_num);
    if (tx_len == (size_t)-1)
    {
        tx_len = construct_error_packet(tx_buf, EUNDEF, "read", true);
        goto send_err_packet;
    }
    else if (!is_first_pkt && tx_len < BUF_SIZE)
    {
        is_finished = true;
    }

    retries = TFTP_NUM_RETRIES;
    wait_time = TFTP_TIMEOUT_MS;

send_again:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, g_sess_args.addr, SOCKADDR_SIZE);
    if (bytes_sent != (ssize_t)tx_len)
    {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        goto exit_transfer;
    }

recv_again:
    pfd.fd = conn_fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, wait_time);
    if (ret == 0)
    {
        retries--;
        if (retries == 0)
        {
            fprintf(stderr, "TFTP timeout\n");
            goto exit_transfer;
        }
        wait_time += (wait_time >> 1);
        if (wait_time > TFTP_MAXTIMEOUT_MS)
            wait_time = TFTP_MAXTIMEOUT_MS;
        goto send_again;
    }
    else if (ret < 0)
    {
        tx_len = construct_error_packet(tx_buf, EUNDEF, "epoll", true);
        goto send_err_packet;
    }

    if (is_first_pkt)
    {
        is_first_pkt = false;
        bytes_read = receive_first_packet(conn_fd, rx_buf, BUF_SIZE);
        if (bytes_read <= 0)
            goto exit_transfer;
    }
    else
    {
        bytes_read = recv(conn_fd, rx_buf, BUF_SIZE, 0);
        if (bytes_read <= 0)
        {
            tx_len = construct_error_packet(tx_buf, EUNDEF, "recv", true);
            goto send_err_packet;
        }
    }

    r_opcode = get_opcode(rx_buf);

    if (is_oack_exp)
    {
        is_oack_exp = false;
        if (r_opcode == CODE_OACK)
        {
            ret = recieve_oack_packet(rx_buf + ARGS_HDR_LEN, bytes_read - ARGS_HDR_LEN);
            if (ret == -1)
            {
                tx_len = construct_error_packet(tx_buf, EBADOPT, NULL, false);
                goto send_err_packet;
            }
        }
        else
            g_sess_args.block_size = DEF_BLK_SIZE;

        if (g_sess_args.block_size != (BUF_SIZE - DATA_HDR_LEN))
        {
            BUF_SIZE = allocate_packet_buf(&tx_buf, &rx_buf);
            if(!BUF_SIZE)
                goto exit_transfer;
        }

        if (r_opcode == CODE_OACK)
        {
            // Expect ACK 1 instead of ACK 0
            // After Option negotiation
            update_prog_bar(PROG_START);
            e_block_num = 1;
            goto send_packet;
        }

    }
    
    if (r_opcode == CODE_ACK)
    {
        r_block_num = get_blocknum(rx_buf);
        if(e_block_num == 0)
            update_prog_bar(PROG_START);

        if (r_block_num == e_block_num)
        {
            g_sess_args.curr_size += (bytes_sent - DATA_HDR_LEN);
            if (is_finished)
            {
                update_prog_bar(PROG_FINISH);
                goto exit_transfer;
            }
            update_prog_bar(PROG_UPDATE);
            e_block_num++;
            goto send_packet;
        }
    }
    else if (r_opcode == CODE_ERROR)
    {
        display_error_packet(rx_buf);
        goto exit_transfer;
    }

    goto recv_again;

send_err_packet:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, g_sess_args.addr, SOCKADDR_SIZE);

exit_transfer:
    close(conn_fd);
    close(g_sess_args.local_fd);
    free(tx_buf);
    free(rx_buf);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    char *hostname = NULL;

    g_exe_name = argv[0];

    ret = register_sighandler(handle_signal);
    if (ret != 0)
        return EXIT_FAILURE;

    memset(&g_sess_args, 0, sizeof(tftp_session));

    g_sess_args.local_fd = -1;
    g_sess_args.addr = (struct sockaddr *)&g_sess_args.server;
    g_sess_args.block_size = DEF_BLK_SIZE;
    g_sess_args.mode = MODE_OCTET;

    while ((ret = getopt(argc, argv, "l:r:b:gph")) != -1)
    {
        switch (ret)
        {
            case 'b':
            {
                if(!is_valid_blocksize(optarg, &(g_sess_args.block_size)))
                {
                    printf("Invalid Block Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'g':
            {
                if(g_sess_args.action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                g_sess_args.action = CODE_RRQ;
                break;
            }
            case 'p':
            {
                if(g_sess_args.action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                g_sess_args.action = CODE_WRQ;
                break;
            }
            case 'l':
            {
                if(optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Local path not provided");
                    return EXIT_FAILURE;
                }
                g_sess_args.local_len = strnlen(optarg, PATH_MAX);
                if(g_sess_args.local_len >= PATH_MAX)
                {
                    print_usage("Local path should be shorter than "TOSTRING(PATH_MAX));
                    return EXIT_FAILURE;
                }
                strncpy(g_sess_args.local_name, optarg, g_sess_args.local_len);
                break;
            }
            case 'r':
            {
                if(optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Remote path not provided");
                    return EXIT_FAILURE;
                }
                g_sess_args.remote_len = strnlen(optarg, PATH_LEN);
                if(g_sess_args.remote_len >= PATH_LEN)
                {
                    print_usage("Remote path is too long");
                    return EXIT_FAILURE;
                }
                strncpy(g_sess_args.remote_name, optarg, g_sess_args.remote_len);
                break;
            }
            case 'h':
            {
                print_usage("");
                return EXIT_SUCCESS;
            }
            case '?':
            default:
            {
                print_usage("");
                return EXIT_FAILURE;
            }
        }
    }

    if (g_sess_args.action == CODE_UNDEF)
    {
        print_usage("Either -g or -p option is required");
        return EXIT_FAILURE;
    }

    if (g_sess_args.local_len == 0)
    {
        print_usage("Need to specify local path");
        return EXIT_FAILURE;
    }

    if (g_sess_args.remote_len == 0)
    {
        print_usage("Need to specify remote path");
        return EXIT_FAILURE;
    }

    if (argv[optind] == NULL)
    {
        print_usage("Missing destination argument");
        return EXIT_FAILURE;
    }

    hostname = get_dest_addr(argv[optind], argv[optind + 1], &(g_sess_args.server));
    if (hostname == NULL)
    {
        if(argv[optind + 1])
            fprintf(stderr, "Destination IP %s port %s could not be resolved\n", argv[optind], argv[optind + 1]);
        else
            fprintf(stderr, "Destination IP %s could not be resolved\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (parse_parameters())
    {
        return EXIT_FAILURE;
    }

    if(g_sess_args.action == CODE_RRQ)
        perform_download();
    else if(g_sess_args.action == CODE_WRQ)
        perform_upload();

    fflush(stderr);
    fflush(stdout);

    return 0;
}