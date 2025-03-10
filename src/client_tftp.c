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
tftp_client g_sess_args;

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
    printf("  %-18s Do not display progress bar\n", "-q");
    printf("  %-18s show usage and exit\n", "-h");
    printf("Note: Option -p or -g is mandatory, and they are mutually exclusive\n");
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
 */
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

/**
 * Parses the local and file names for validity
 * Autocompletes the destination path if it's a directory
 * by using the filename of source path.
 * Also opens the local file and saves the descriptor
 */
int parse_parameters()
{
    size_t len = 0;
    struct stat st = {0};
    char *filename = NULL;
    tftp_context *ctx = &(g_sess_args.tftp_ctx);

    if (ctx->action == CODE_WRQ)
    {
        if (g_sess_args.local_name[g_sess_args.local_len - 1] == '/')
        {
            LOG_ERROR("%s: local file path is directory", g_sess_args.local_name);
            return -1;
        }

        if (access(g_sess_args.local_name, F_OK | R_OK) != 0)
        {
            LOG_ERROR("access %s: %s", g_sess_args.local_name, strerror(errno));
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
                LOG_ERROR("Destination file name %s%s is too long", g_sess_args.remote_name, filename);
                return -1;
            }
            strncat(g_sess_args.remote_name, filename, len);
            g_sess_args.remote_len += len;
        }

        if (stat(g_sess_args.local_name, &st) == -1)
        {
            LOG_ERROR("stat %s: %s", g_sess_args.local_name, strerror(errno));
            return -1;
        }

        ctx->file_size = st.st_size;
        ctx->file_desc = open(g_sess_args.local_name, O_RDONLY);
    }
    else if (ctx->action == CODE_RRQ)
    {
        if (g_sess_args.remote_name[g_sess_args.remote_len - 1] == '/')
        {
            LOG_ERROR("%s: Remote file path is directory", g_sess_args.remote_name);
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
                LOG_ERROR("Local file name %s%s will be too long", g_sess_args.local_name, filename);
                return -1;
            }
            strncat(g_sess_args.local_name, filename, len);
            g_sess_args.local_len += len;
        }
        ctx->file_desc = open(g_sess_args.local_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    }

    if (ctx->file_desc < 0)
    {
        LOG_ERROR("Unable to open local file %s: %s", g_sess_args.local_name, strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Convert hostname or ip address from string to
 * network form and stores in dest_addr pointer.
 */
int parse_ip_address(const char *ip_addr, char *port_no, tftp_context *ctx)
{
    uint16_t port = TFTP_PORT_NO;
    s_addr4 *ipv4 = (s_addr4 *)&(ctx->addr);
    s_addr6 *ipv6 = (s_addr6 *)&(ctx->addr);

    if (port_no && is_valid_portnum(port_no, &port) == false)
    {
        LOG_ERROR("Invalid port number received %s", port_no);
        return -1;
    }

    if (inet_pton(AF_INET, ip_addr, &(ipv4->sin_addr)) == 1)
    {
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        ctx->addr_len = sizeof(s_addr4);
    }
    else if (inet_pton(AF_INET6, ip_addr, &(ipv6->sin6_addr)) == 1)
    {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        ctx->addr_len = sizeof(s_addr6);
    }
    else
    {
        LOG_ERROR("Invalid IP address provided %s", ip_addr);
        return -1;
    }

    return 0;
}

/**
 *
 */
int init_client_request(tftp_context *ctx)
{
    int ret = 0;
    size_t curr_len = 0;
    size_t option_len = 0;
    char *curr_ptr = NULL;
    char option[OPTION_LEN] = {0};

    set_opcode(ctx->tx_buf, ctx->action);
    curr_len += ARGS_HDR_LEN;
    curr_ptr = ctx->tx_buf + ARGS_HDR_LEN;

    strncpy(curr_ptr, g_sess_args.remote_name, g_sess_args.remote_len);
    curr_ptr += g_sess_args.remote_len + 1;
    curr_len += g_sess_args.remote_len + 1;

    option_len = tftp_mode_to_str(ctx->mode, option);
    if (curr_len + option_len > DEF_BLK_SIZE)
    {
        LOG_ERROR("Remote file name is too long");
        return -1;
    }

    strncpy(curr_ptr, option, option_len);
    curr_ptr += option_len + 1;
    curr_len += option_len + 1;

    ret = insert_options(curr_ptr, DEF_BLK_SIZE - curr_len, ctx->blk_size, ctx->file_size, ctx->win_size);
    if (ret == -1)
    {
        LOG_ERROR("Remote file name is too long");
        return -1;
    }

    ctx->tx_len = curr_len + (size_t)ret;
    ctx->is_oack = (ret > 0);
#ifdef DEBUG
    print_tftp_request(ctx->tx_buf, ctx->tx_len);
#endif
    return 0;
}

/**
 * Parses the OACK packet sent by the server
 * Extracts the file size in case of download
 * Validates block size and window size acknowledgement
 */
int parse_oack_string(tftp_context *ctx)
{
    int ret = 0;
    pthread_t prog_t;
    size_t *blk_size = NULL;
    size_t *win_size = NULL;
    off_t *file_size = NULL;

#ifdef DEBUG
    print_tftp_request(ctx->rx_buf, (size_t)ctx->rx_len);
#endif

    if (ctx->blk_size != DEF_BLK_SIZE)
        blk_size = &(ctx->blk_size);

    if (ctx->win_size != DEF_WIN_SIZE)
        win_size = &(ctx->win_size);

    if (ctx->file_size == 0 && ctx->action == CODE_RRQ)
        file_size = &(ctx->file_size);

    ret = extract_options(ctx->rx_buf + ARGS_HDR_LEN, (size_t) ctx->rx_len - ARGS_HDR_LEN, blk_size, file_size, win_size);
    if (ret)
    {
        send_error_packet(ctx, EBADOPT);
        return -1;
    }

    if (ctx->BUF_SIZE != ctx->blk_size + DATA_HDR_LEN)
    {
        ctx->BUF_SIZE = ctx->blk_size + DATA_HDR_LEN;

        ctx->tx_buf = realloc(ctx->tx_buf, ctx->BUF_SIZE);
        if (ctx->tx_buf == NULL)
        {
            LOG_ERROR("realloc: %s", strerror(errno));
            send_error_packet(ctx, EUNDEF);
            return -1;
        }

        ctx->rx_buf = realloc(ctx->rx_buf, ctx->BUF_SIZE);
        if (ctx->rx_buf == NULL)
        {
            LOG_ERROR("realloc: %s", strerror(errno));
            send_error_packet(ctx, EUNDEF);
            return -1;
        }

        memset(ctx->tx_buf, 0, ctx->BUF_SIZE);
        memset(ctx->rx_buf, 0, ctx->BUF_SIZE);
    }

    if (ctx->file_size <= 0)
        is_prog_bar = false;


    if (is_prog_bar)
    {
        ret = pthread_create(&prog_t, NULL, progress_bar, ctx);
        if (ret != 0)
        {
            is_prog_bar = false;
            LOG_ERROR("pthread_create: %d", ret);
        }
    }

    if (ctx->action == CODE_RRQ)
    {
        ctx->r_block_num = 0;
        ctx->tx_len = DATA_HDR_LEN;
        set_opcode(ctx->tx_buf, CODE_ACK);
        set_blocknum(ctx->tx_buf, ctx->r_block_num);
        tftp_recv_file(ctx, true);
    }
    else if (ctx->action == CODE_WRQ)
    {
        tftp_send_file(ctx, false);
    }

    if (is_prog_bar)
        pthread_join(prog_t, NULL);

    return 0;
}

/**
 * Function that sets up the socket for future communication
 * Also performs some security check to be sure packet
 * originated from intended source.
 *
 * Returns the size of the data read in first packet, -1 on error.
 */
int tftp_connect(tftp_context *ctx)
{
    int ret = 0;
    int retries = TFTP_NUM_RETRIES;
    int wait_time = TFTP_TIMEOUT_MS;
    TFTP_OPCODE code = CODE_UNDEF;

    ssize_t bytes_sent = 0;
    uint16_t block_num = 0;
    struct pollfd pfd = {0};

    ctx->conn_sock = socket(ctx->addr.ss_family, SOCK_DGRAM, 0);
    if (ctx->conn_sock < 0)
    {
        LOG_ERROR("%s socket %s", __func__, strerror(errno));
        return -1;
    }

send_again:
    bytes_sent = sendto(ctx->conn_sock, ctx->tx_buf, ctx->tx_len, 0, (s_addr *)&(ctx->addr), ctx->addr_len);
    if (bytes_sent != (ssize_t)ctx->tx_len)
    {
        LOG_ERROR("%s sendto: %s", __func__, strerror(errno));
        return -1;
    }

recv_again:
    pfd.fd = ctx->conn_sock;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, wait_time);

    retries--;
    if (retries == 0)
    {
        LOG_ERROR("TFTP timeout");
        return -1;
    }

    if (ret == 0)
    {
        wait_time += (wait_time >> 1);
        if (wait_time > TFTP_MAXTIMEOUT_MS)
            wait_time = TFTP_MAXTIMEOUT_MS;
        goto send_again;
    }
    else if (ret < 0)
    {
        LOG_ERROR("%s poll: %s", __func__, strerror(errno));
        return -1;
    }

    ctx->rx_len = recvfrom(ctx->conn_sock, ctx->rx_buf, ctx->BUF_SIZE, 0, (s_addr *)&(ctx->addr), &ctx->addr_len);
    if (ctx->rx_len <= 0)
    {
        LOG_ERROR("%s recvfrom: %s", __func__, strerror(errno));
        return -1;
    }
    else if (ctx->rx_len < DATA_HDR_LEN)
    {
        LOG_ERROR("Received corrupted packet with length %ld", ctx->rx_len);
        goto recv_again;
    }

    code = get_opcode(ctx->rx_buf);
    block_num = get_blocknum(ctx->rx_buf);
    if(code == CODE_ERROR)
    {
        handle_error_packet(ctx->rx_buf, ctx->rx_len);
        return -1;
    }
    else if (code == CODE_ACK && block_num == 0 && ctx->action == CODE_WRQ)
    {
        goto connect_socket;
    }
    else if (code == CODE_DATA && block_num == 1 && ctx->action == CODE_RRQ)
    {
        goto connect_socket;
    }
    else if (code == CODE_OACK)
    {
        goto connect_socket;
    }

#ifdef DEBUG
    LOG_ERROR("Recieved unexpected opcode %d block num %d", code, block_num);
#endif
    goto recv_again;

connect_socket:
    ret = connect(ctx->conn_sock, (s_addr *)&(ctx->addr), ctx->addr_len);
    if (ret != 0)
    {
        LOG_ERROR("%s connect: %s", __func__, strerror(errno));
        return -1;
    }

    if (code == CODE_OACK)
    {
        ret = parse_oack_string(ctx);
        if (ret != 0)
            return -1;
    }
    else if (ctx->action == CODE_RRQ)
    {
        tftp_recv_file(ctx, false);
    }
    else if (ctx->action == CODE_WRQ)
    {
        tftp_send_file(ctx, false);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    tftp_context *ctx = &(g_sess_args.tftp_ctx);
    TFTP_OPCODE action = CODE_UNDEF;
    size_t win_size = DEF_WIN_SIZE;
    size_t block_size = DEF_BLK_SIZE;

#ifdef TIMER_ON
    double elapsed = 0;
    struct timespec start = {0};
    struct timespec end = {0};
#endif

    g_exe_name = argv[0];
    memset(&g_sess_args, 0, sizeof(tftp_client));

    ret = register_sighandler(handle_signal);
    if (ret != 0)
        return EXIT_FAILURE;

    while ((ret = getopt(argc, argv, "l:r:b:w:gpqh")) != -1)
    {
        switch (ret)
        {
            case 'b':
            {
                if (!is_valid_blocksize(optarg, &block_size))
                {
                    printf("Invalid Block Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'w':
            {
                if (!is_valid_windowsize(optarg, &win_size))
                {
                    printf("Invalid Window Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'g':
            {
                if (action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                action = CODE_RRQ;
                break;
            }
            case 'p':
            {
                if (action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                action = CODE_WRQ;
                break;
            }
            case 'l':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Local path not provided");
                    return EXIT_FAILURE;
                }
                g_sess_args.local_len = strnlen(optarg, PATH_MAX);
                if (g_sess_args.local_len >= PATH_MAX)
                {
                    print_usage("Local path should be shorter than " TOSTRING(PATH_MAX));
                    return EXIT_FAILURE;
                }
                strncpy(g_sess_args.local_name, optarg, g_sess_args.local_len);
                break;
            }
            case 'r':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Remote path not provided");
                    return EXIT_FAILURE;
                }
                g_sess_args.remote_len = strnlen(optarg, PATH_LEN);
                if (g_sess_args.remote_len >= PATH_LEN)
                {
                    print_usage("Remote path is too long");
                    return EXIT_FAILURE;
                }
                strncpy(g_sess_args.remote_name, optarg, g_sess_args.remote_len);
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

    if (action == CODE_UNDEF)
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

    ret = init_tftp_context(ctx, action, block_size, win_size);
    if (ret)
        return EXIT_FAILURE;

    ret = parse_ip_address(argv[optind], argv[optind + 1], ctx);
    if (ret)
    {
        free_tftp_context(ctx);
        return EXIT_FAILURE;
    }

    ret = parse_parameters();
    if (ret)
    {
        free_tftp_context(ctx);
        return EXIT_FAILURE;
    }

    ret = init_client_request(ctx);
    if (ret)
    {
        free_tftp_context(ctx);
        return EXIT_FAILURE;
    }

#ifdef TIMER_ON
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    ret = tftp_connect(ctx);
    if (ret)
    {
        free_tftp_context(ctx);
        return EXIT_FAILURE;
    }

#ifdef TIMER_ON
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (double)(end.tv_sec - start.tv_sec) * 1000.0 +
              (double)(end.tv_nsec - start.tv_nsec) / 1e6;
    LOG_INFO("Elapsed time: %.3f ms", elapsed);
#endif

    fflush(stderr);
    fflush(stdout);
    return 0;
}