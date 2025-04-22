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

/**
 * Prints the usage of the tftp client binary
 */
void print_usage(char *err_str)
{
    if (err_str != NULL && *err_str != '\0')
        printf("Error: %s\n", err_str);

    printf("\nUsage:\n");
    printf("  %s [OPTION] ... HOST [PORT]\n\n", g_exe_name);
    printf("Options:\n");
    printf("  %-18s Get/Download file\n",   "-g");
    printf("  %-18s Put/Upload file\n",     "-p");
    printf("  %-18s Local file path\n",     "-l FILE");
    printf("  %-18s Remote file path\n",    "-r FILE");
    printf("  %-18s Transfer block size 8 - 65464\n", "-b SIZE");
    printf("  %-18s Transfer window size 1 - 65536\n", "-w COUNT");
    printf("  %-18s Do not give transfer size\n", "-t");
    printf("  %-18s Do not display progress bar\n", "-q");
    printf("  %-18s show usage and exit\n", "-h");
    printf("Note: Option -p or -g is mandatory, and are mutually exclusive\n");
    printf("    : Option -l and -r are both mandatory\n");
    printf("    : Default block size is 512 bytes\n");
    printf("    : Default window size is 1 (RFC 7440)\n");
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
 * 
void *progress_bar(void * arg)
{
    tftp_context *ctx = (tftp_context *)arg;

    char p_bar[PROG_BAR_LEN + 1] = {0};    
    off_t p_size = 0;
    off_t p_per = 0;
    off_t c_per = 0;
    off_t index = 0;

    memset(p_bar, ' ', PROG_BAR_LEN);
    while (ctx->prog == PROG_START)
    {
        c_per = (100 * ctx->curr_size) / ctx->file_size;
        index = PROG_BAR_LEN * c_per / 100;
        
        if (c_per > p_per || ctx->curr_size > p_size + UPDATE_DIFF)
        {
            memset(p_bar, '=', (size_t) index);
            printf("\r[%s] %ld%% (%ld) bytes", p_bar, c_per, ctx->curr_size);
            fflush(stdout);
            p_per = c_per;
            p_size = ctx->curr_size;
        }
        usleep(1000);
    }

    if (ctx->prog == PROG_FINISH)
    {
        c_per = (100 * ctx->curr_size) / ctx->file_size;
        index = PROG_BAR_LEN * c_per / 100;        
        memset(p_bar, '=', (size_t) index);
        printf("\r[%s] %ld%% (%ld) bytes", p_bar, c_per, ctx->curr_size);
        fflush(stdout);
    }

    printf("\n");
    fflush(stdout);
    return NULL;
}
 */

/**
 * Parses the local and file names for validity
 * Autocompletes the destination path if it's a directory
 * by using the filename of source path.
 * Also opens the local file and saves the descriptor
 */
int parse_parameters(tftp_request *req)
{
    size_t len = 0;
    struct stat st = {0};
    char *filename = NULL;

    if (req->type == CODE_WRQ)
    {
        if (req->local_name[req->local_len - 1] == '/')
        {
            LOG_ERROR("%s: Local file path is directory", req->local_name);
            return -1;
        }

        if (access(req->local_name, F_OK | R_OK) != 0)
        {
            LOG_ERROR("access %s: %s", req->local_name, strerror(errno));
            return -1;
        }

        if (req->remote_name[req->remote_len - 1] == '/')
        {
            filename = strrchr(req->local_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN);
            }
            else
            {
                filename = req->local_name;
                len = req->local_len;
            }

            if ((req->remote_len + len) >= PATH_LEN)
            {
                LOG_ERROR("Remote file path cannot be longer than the limit" TOSTRING(PATH_LEN));
                return -1;
            }
            strncat(req->remote_name, filename, len);
            req->remote_len += len;
        }

        if (stat(req->local_name, &st) == -1)
        {
            LOG_ERROR("stat %s: %s", req->local_name, strerror(errno));
            return -1;
        }

        req->file_size = st.st_size;
        req->file_desc = open(req->local_name, O_RDONLY);
    }
    else if (req->type == CODE_RRQ)
    {
        if (req->remote_name[req->remote_len - 1] == '/')
        {
            LOG_ERROR("%s: Remote file path is directory", req->remote_name);
            return -1;
        }

        if (req->local_name[req->local_len - 1] == '/')
        {
            filename = strrchr(req->remote_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN - 1);
            }
            else
            {
                filename = req->remote_name;
                len = req->remote_len;
            }

            if ((req->local_len + len) >= PATH_MAX)
            {
                    LOG_ERROR("Local file path cannot be longer than " TOSTRING(PATH_LEN));
                return -1;
            }
            strncat(req->local_name, filename, len);
            req->local_len += len;
        }
        req->file_desc = open(req->local_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    }

    if (req->is_tsize_off)
        req->file_size = -1;

    if (req->file_desc < 0)
    {
        LOG_ERROR("Unable to open local file %s: %s", req->local_name, strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Convert hostname or ip address from string to
 * network form and stores in dest_addr pointer.
 */
int parse_ip_address(tftp_request *req, const char *ip_addr, char *port_no)
{
    uint16_t port = TFTP_PORT_NO;
    s_addr4 *ipv4 = (s_addr4 *)&(req->addr);
    s_addr6 *ipv6 = (s_addr6 *)&(req->addr);

    if (port_no && is_valid_portnum(port_no, &port) == false)
    {
        LOG_ERROR("Invalid port number received %s", port_no);
        return -1;
    }

    if (inet_pton(AF_INET, ip_addr, &(ipv4->sin_addr)) == 1)
    {
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        req->addr_len = sizeof(s_addr4);
    }
    else if (inet_pton(AF_INET6, ip_addr, &(ipv6->sin6_addr)) == 1)
    {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        req->addr_len = sizeof(s_addr6);
    }
    else
    {
        LOG_ERROR("Invalid IP address provided %s", ip_addr);
        return -1;
    }

    return 0;
}

/**
 * Parses the OACK packet sent by the server
 * Extracts the file size in case of download
 * Validates block size and window size acknowledgement
 */
int parse_oack_string(tftp_request *req)
{
    int ret = 0;
    size_t *blk_size = NULL;
    size_t *win_size = NULL;
    off_t *file_size = NULL;

#ifdef DEBUG
    print_tftp_request(req->rx_buf, req->rx_len);
#endif
    if (req->blk_size != DEF_BLK_SIZE)
        blk_size = &(req->blk_size);

    if (req->win_size != DEF_WIN_SIZE)
        win_size = &(req->win_size);

    if (req->file_size == 0 && req->type == CODE_RRQ)
        file_size = &(req->file_size);

    ret = extract_options(req->rx_buf + ARGS_HDR_LEN, req->rx_len - ARGS_HDR_LEN, blk_size, file_size, win_size);
    if (ret)
    {
        send_error_packet(req->conn_sock, NULL, EBADOPT);
        return -1;
    }

    if (req->type == CODE_RRQ)
    {
        req->state = SEND_ACK;
    }
    else if (req->type == CODE_WRQ)
    {
        req->state = SEND_DATA;
    }

    return 0;
}

/**
 * 
 */
int init_tftp_request(tftp_request *req)
{
    size_t option_len = 0;
    char *curr_ptr = req->tx_buf + ARGS_HDR_LEN;

    set_opcode(req->tx_buf, req->type);
    req->tx_len = ARGS_HDR_LEN;

    strncpy(curr_ptr, req->remote_name, req->remote_len);
    req->tx_len += req->remote_len + 1;
    curr_ptr += req->remote_len + 1;

    strncpy(curr_ptr, "octet", 6);
    req->tx_len += 6;
    curr_ptr += 6;

    option_len = insert_options(curr_ptr, req->blk_size, req->file_size, req->win_size);
    req->tx_len += option_len;
    if (req->tx_len > REQUEST_SIZE)
    {
        LOG_ERROR("Request size longer than " STRINGIFY(REQUEST_SIZE) ", reduce file path len");
        return -1;
    }

    if (option_len > 0)
        req->is_oack = true;

#ifdef DEBUG
    print_tftp_request(req->tx_buf, req->tx_len);
#endif

    req->conn_sock = socket(req->addr.ss_family, SOCK_DGRAM, 0);
    if (req->conn_sock < 0)
    {
        close(req->file_desc);
        LOG_ERROR("%s socket %s", __func__, strerror(errno));
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
int tftp_connect(tftp_request *req)
{
    int ret = 0;
    int attempts = 0;
    struct pollfd pfd = {0};
    
    ssize_t bytes_sent = 0;
    ssize_t bytes_recv = 0;
    TFTP_OPCODE code = CODE_UNDEF;

    req->state = SEND_REQ;

    while (1)
    {
        bytes_sent = sendto(req->conn_sock, req->tx_buf, req->tx_len, 0,
                            (s_addr *)&(req->addr), req->addr_len);
        
        if (bytes_sent != (ssize_t)req->tx_len)
        {
            LOG_ERROR("%s sendto: %s", __func__, strerror(errno));
            return -1;
        }

wait_again:
        pfd.fd = req->conn_sock;
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, TFTP_TIMEOUT_MS);

        if (ret == 0)
        {
            if (attempts == TFTP_NUM_RETRIES)
            {
                LOG_ERROR("tftp timeout");
                return -1;
            }
            attempts++;
        }
        else if (ret < 0)
        {
            if (errno == EINTR)
                goto wait_again;

            LOG_ERROR("%s poll: %s", __func__, strerror(errno));
            return -1;
        }
        else
        {
            break;
        }

    }
                
    bytes_recv = recvfrom(req->conn_sock, req->rx_buf, req->BUF_SIZE, 0, (s_addr *)&(req->addr), &req->addr_len);
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

    code = get_opcode(req->rx_buf);
    if (code == CODE_ERROR)
    {
        handle_error_packet(req->rx_buf, bytes_recv);
        return -1;
    }
    else if ((req->is_oack && code == CODE_OACK) ||
             (req->type == CODE_RRQ && code == CODE_DATA && get_blocknum(req->rx_buf) == 1) ||
             (req->type == CODE_WRQ && code == CODE_ACK && get_blocknum(req->rx_buf) == 0))
    {
        req->rx_len = (size_t)bytes_recv;
    }
    else
    {
#ifdef DEBUG
        LOG_ERROR("Recieved unexpected opcode %d block num %d", code, get_blocknum(req->rx_buf));
#else
        LOG_ERROR("Recived unexpected data");
#endif
        set_opcode(req->tx_buf, CODE_ERROR);
        set_blocknum(req->tx_buf, EBADOP);
        req->tx_len = DATA_HDR_LEN;
        bytes_sent = sendto(req->conn_sock, req->tx_buf, req->tx_len, 0, (s_addr *)&(req->addr), req->addr_len);
        return -1;
    }

    ret = connect(req->conn_sock, (s_addr *)&(req->addr), req->addr_len);
    if (ret != 0)
    {
        LOG_ERROR("%s connect: %s", __func__, strerror(errno));
        return -1;
    }

    if (code == CODE_DATA)
    {
        req->rx_len = (size_t) bytes_recv - DATA_HDR_LEN;
        req->state = RECV_DATA;
        return 0;
    }
    else if (code == CODE_ACK)
    {
        req->state = SEND_DATA;
        return 0;
    }

    return parse_oack_string(req);
}

int tftp_recv_file(tftp_request *req)
{
    TFTP_CLIENT_STATE prev_state = RRQ_SENT;
    size_t w_block_num = 0;
    size_t l_block_num = 0;
    size_t r_block_num = 0;

    ssize_t bytes_writ = 0;
    ssize_t bytes_recv = 0;
    ssize_t bytes_sent = 0;

    TFTP_OPCODE r_opcode = CODE_UNDEF;

    int attempts = 0;
    int timeout = TFTP_TIMEOUT_MS;

    while(1)
    {
        switch(req->state)
        {
            case SEND_ACK:
            {
                set_opcode(req->tx_buf, CODE_ACK);
                set_blocknum(req->tx_buf, l_block_num);
                req->tx_len = DATA_HDR_LEN;

                bytes_sent = send(req->conn_sock, req->tx_buf, req->tx_len, 0);
                if (bytes_sent < 0)
                {
                    LOG_ERROR("%s send DATA %s", __func__, strerror(errno));
                    return -1;
                }

                if (prev_state != RRQ_SENT && req->rx_len < req->blk_size)
                    return 0;

                w_block_num = 0;
                prev_state = SEND_ACK;
                req->state = WAIT_PKT;
                break;
            }
            case WAIT_PKT:
            {
                bytes_recv = safe_recv(req->conn_sock, req->rx_buf, req->BUF_SIZE, timeout);
                if (bytes_recv == 0)
                {
                    if (attempts == TFTP_NUM_RETRIES)
                    {
                        LOG_ERROR("tftp timeout");
                        return -1;
                    }
                    attempts++;
                    req->state = prev_state;
                    break;
                }
                else if (bytes_recv < 0)
                {
                    send_error_packet(req->conn_sock, "recv error", EUNDEF);
                    return -1;
                }
                
                r_opcode = get_opcode(req->rx_buf);
                r_block_num = tftp_rollover_blocknumber(get_blocknum(req->rx_buf), l_block_num);
                if (r_opcode != CODE_DATA)
                {
                    attempts++;
                    break;
                }
                else if (r_block_num != l_block_num + 1)
                {
                    break;
                }

                req->rx_len = (size_t) bytes_recv - DATA_HDR_LEN;
                req->state = RECV_DATA;
                break;                
            }
            case RECV_DATA:
            {
                bytes_writ = file_write(req->file_desc, req->rx_buf + DATA_HDR_LEN, req->rx_len);
                if (bytes_writ != (ssize_t)req->rx_len)
                {
                    send_error_packet(req->conn_sock, "Error writing to file", EUNDEF);
                    return -1;
                }
                l_block_num++;
                w_block_num++;

                if (w_block_num == req->win_size || req->rx_len < req->blk_size)
                    req->state = SEND_ACK;
                else
                    req->state = WAIT_PKT;
                break;
            }
            default:
            {
                return -1;
            }
        }
    }
    return 0;
}

int tftp_send_file(tftp_request *req)
{
    size_t w_block_num = 0;
    size_t e_block_num = 1;
    size_t l_block_num = 0;
    size_t r_block_num = 0;

    ssize_t bytes_read = 0;
    ssize_t bytes_recv = 0;
    ssize_t bytes_sent = 0;

    TFTP_OPCODE r_opcode = CODE_UNDEF;

    int attempts = 0;
    int timeout = TFTP_TIMEOUT_MS;

    while(1)
    {
        switch(req->state)
        {
            case SEND_DATA:
            {
                set_opcode(req->tx_buf, CODE_DATA);
                set_blocknum(req->tx_buf, e_block_num);
                bytes_read = file_read(req->file_desc, req->tx_buf + DATA_HDR_LEN, req->blk_size, e_block_num);
                if (bytes_read < 0)
                {
                    send_error_packet(req->conn_sock, "file read error", EUNDEF);
                    return -1;
                }
                req->tx_len = DATA_HDR_LEN + (size_t)bytes_read;

                bytes_sent = send(req->conn_sock, req->tx_buf, req->tx_len, 0);
                if (bytes_sent < 0)
                {
                    LOG_ERROR("%s send DATA %s", __func__, strerror(errno));
                    return -1;
                }

                w_block_num++;
                e_block_num++;
                if (w_block_num == req->win_size || req->tx_len < req->BUF_SIZE)
                {
                    req->state = WAIT_PKT;
                }
                break;
            }
            case WAIT_PKT:
            {
                bytes_recv = safe_recv(req->conn_sock, req->rx_buf, req->BUF_SIZE, timeout);

                // If timeout occured resend all packets in window
                if (bytes_recv == 0)
                {
                    if (attempts == TFTP_NUM_RETRIES)
                    {
                        LOG_ERROR("tftp timeout");
                        return -1;
                    }
                    attempts++;
                    w_block_num = 0;
                    e_block_num -= req->win_size;
                    req->state = SEND_DATA;
                    break;
                }
                else if (bytes_recv < 0)
                {
                    send_error_packet(req->conn_sock, "recv error", EUNDEF);
                    return -1;
                }
                
                r_opcode = get_opcode(req->rx_buf);
                r_block_num = tftp_rollover_blocknumber(get_blocknum(req->rx_buf), l_block_num);
                if (r_opcode != CODE_ACK)
                {
                    // If non ack packet is received, discard
                    // And  wait for another packet
                    attempts++;
                    break;
                }

                // Consider block num roll over
                if (r_block_num <= l_block_num)
                {
                    // If recieved ack is an older ack discard
                    // If data packets were lost and we recieved last ack
                    // Wait for timeout to prevent SAS and resend all packets
                    break;
                }
                else if (r_block_num >= e_block_num)
                {
                    break;
                }
                req->state = RECV_ACK;
                break;                
            }
            case RECV_ACK:
            {
                if (req->tx_len < req->BUF_SIZE)
                    return 0;

                l_block_num = r_block_num;
                w_block_num = 0;
                attempts = 0;
                req->state = SEND_DATA;
                break;
            }
            default:
            {
                return -1;
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    tftp_request req;

#ifdef TIMER_ON
    double elapsed = 0;
    struct timespec start = {0};
    struct timespec end = {0};
#endif

    g_exe_name = argv[0];
    memset(&req, 0, sizeof(tftp_request));

    req.conn_sock = -1;
    req.file_desc = -1;
    req.blk_size = DEF_BLK_SIZE;
    req.win_size = DEF_WIN_SIZE;

    ret = register_sighandler(handle_signal);
    if (ret != 0)
        return EXIT_FAILURE;

    while ((ret = getopt(argc, argv, "l:r:b:w:gptqh")) != -1)
    {
        switch (ret)
        {
            case 'b':
            {
                if (!is_valid_blocksize(optarg, &req.blk_size))
                {
                    printf("Invalid Block Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'w':
            {
                if (!is_valid_windowsize(optarg, &req.win_size))
                {
                    printf("Invalid Window Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'g':
            {
                if (req.type != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                req.type = CODE_RRQ;
                break;
            }
            case 'p':
            {
                if (req.type != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                req.type = CODE_WRQ;
                break;
            }
            case 'l':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Local path not provided");
                    return EXIT_FAILURE;
                }
                req.local_len = strnlen(optarg, PATH_MAX);
                if (req.local_len >= PATH_MAX)
                {
                    print_usage("Local path should be shorter than " TOSTRING(PATH_MAX));
                    return EXIT_FAILURE;
                }
                strncpy(req.local_name, optarg, req.local_len);
                break;
            }
            case 'r':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Remote path not provided");
                    return EXIT_FAILURE;
                }
                req.remote_len = strnlen(optarg, PATH_LEN);
                if (req.remote_len >= PATH_LEN)
                {
                    print_usage("Remote path should be shorter than " TOSTRING(PATH_LEN));
                    return EXIT_FAILURE;
                }
                strncpy(req.remote_name, optarg, req.remote_len);
                break;
            }
            case 't':
            {
                req.is_tsize_off = true;
                break;
            }
            case 'q':
            {
                is_prog_bar = false;
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

    if (req.type == CODE_UNDEF)
    {
        print_usage("Either -g or -p option is required");
        return EXIT_FAILURE;
    }

    if (req.local_len == 0)
    {
        print_usage("Need to specify local path");
        return EXIT_FAILURE;
    }

    if (req.remote_len == 0)
    {
        print_usage("Need to specify remote path");
        return EXIT_FAILURE;
    }

    if (argv[optind] == NULL)
    {
        print_usage("Missing destination argument");
        return EXIT_FAILURE;
    }

    req.BUF_SIZE = req.blk_size + DATA_HDR_LEN;

    ret = parse_ip_address(&req, argv[optind], argv[optind + 1]);
    if (ret)
    {
        return EXIT_FAILURE;
    }

    ret = parse_parameters(&req);
    if (ret)
    {
        return EXIT_FAILURE;
    }

    ret = init_tftp_request(&req);
    if (ret)
    {
        close(req.file_desc);
    }

#ifdef TIMER_ON
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    ret = tftp_connect(&req);
    if (ret)
    {
        close(req.file_desc);
        close(req.conn_sock);
        return EXIT_FAILURE;
    }

    if (req.type == CODE_RRQ)
    {
        ret = tftp_recv_file(&req);
    }
    else if (req.type == CODE_WRQ)
    {
        ret = tftp_send_file(&req);
    }

#ifdef TIMER_ON
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (double)(end.tv_sec - start.tv_sec) * 1000.0 +
              (double)(end.tv_nsec - start.tv_nsec) / 1e6;
    LOG_INFO("Elapsed time: %.3f ms", elapsed);
#endif

    close(req.conn_sock);
    close(req.file_desc);

    fflush(stderr);
    fflush(stdout);
    return 0;
}