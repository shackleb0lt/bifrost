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
char *get_dest_addr(const char *input, struct sockaddr_in *dest_addr)
{
    int ret = 0;
    struct addrinfo hint;
    struct addrinfo *res;
    static char ipstr[INET_ADDRSTRLEN] = {0};

    dest_addr->sin_family = AF_INET;
    dest_addr->sin_port = htons(TFTP_PORT_NO);

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

void display_error_packet(tftp_pkt *rx_pkt, ssize_t bytes_read)
{
    TFTP_ERRCODE err_code = ntohs(rx_pkt->un.block);
    if(bytes_read == 4 || rx_pkt->data[0] == '\0')
    {
        fprintf(stderr, "server error: %s\n", tftp_err_to_str(err_code));
        return;
    }
    fprintf(stderr, "server error: %.64s\n", rx_pkt->data);
}

size_t construct_first_packet(char *tx_buf)
{
    size_t tx_len = 0;
    tftp_pkt *tx_pkt = (tftp_pkt *)tx_buf;
    char *curr_ptr = tx_pkt->un.args;

    tx_pkt->opcode = htons((uint16_t)g_sess_args.action);

    strncpy(curr_ptr, g_sess_args.remote_name, g_sess_args.remote_len);
    curr_ptr += g_sess_args.remote_len + 1;

    strncpy(curr_ptr, g_sess_args.mode_str, g_sess_args.mode_len);
    curr_ptr += g_sess_args.mode_len + 1;

    tx_len = (size_t)(curr_ptr - tx_buf);
    return tx_len;
}

size_t construct_next_packet(char *tx_buf, size_t prev_block)
{
    size_t tx_len = 0;
    ssize_t bytes_read = 0;
    tftp_pkt *tx_pkt = (tftp_pkt *) tx_buf;
    char *curr_ptr = NULL;

    tx_len = sizeof(uint16_t) << 1;
    if(g_sess_args.action == CODE_RRQ)
    {
        tx_pkt->opcode = htons((uint16_t) CODE_ACK);
        tx_pkt->un.block = htons((uint16_t) prev_block);
        return tx_len;
    }
    
    tx_pkt->opcode = htons((uint16_t) CODE_DATA);
    tx_pkt->un.block = htons((uint16_t) prev_block + 1);
    curr_ptr = tx_pkt->data;

    bytes_read = read(g_sess_args.local_fd, curr_ptr, g_sess_args.block_size);
    if(bytes_read <= 0)
        return 0;

    tx_len += (size_t) bytes_read;
    return tx_len;
}

size_t construct_error_packet(char *tx_buf, TFTP_ERRCODE err_code, char *err_msg)
{
    int tx_len = 0;
    tftp_pkt *tx_pkt = (tftp_pkt *) tx_buf;
    char *curr_ptr = tx_pkt->data;

    tx_pkt->opcode = htons((uint16_t) CODE_ERROR);
    tx_pkt->un.block = htons((uint16_t) err_code);

    tx_len = sizeof(uint16_t) << 1;

    if(err_msg)
    {
        tx_len += snprintf(curr_ptr, g_sess_args.block_size - 1, "%s", err_msg);
        return (size_t) tx_len;
    }

    tx_len += snprintf(curr_ptr, g_sess_args.block_size - 1, "%s", tftp_err_to_str(err_code));
    return (size_t) tx_len;
}

void perform_download()
{
    int ret = 0;
    int conn_fd = -1;
    struct pollfd pfd = {0};
    struct in_addr recv_addr = {0};
    struct sockaddr *addr = NULL;
    socklen_t s_len = SOCKADDR_SIZE;

    bool is_first_pkt = true;
    bool is_finished = false;

    size_t e_block_num = 1;
    size_t r_block_num = 1;
    ssize_t bytes_sent = 0;
    ssize_t bytes_read = 0;

    size_t tx_len = 0;
    tftp_pkt *rx_pkt = NULL;

    TFTP_OPCODE r_opcode = CODE_UNDEF;

    int retries = TFTP_NUM_RETRIES;
    int wait_time = TFTP_TIMEOUT_MS;

    const size_t BUF_SIZE = g_sess_args.block_size + 4;
    char *tx_buf = (char *)malloc(BUF_SIZE);
    char *rx_buf = (char *)malloc(BUF_SIZE);

    if (!tx_buf || !rx_buf)
    {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        return;
    }

    memset(tx_buf, 0, BUF_SIZE);
    memset(rx_buf, 0, BUF_SIZE);

    rx_pkt = (tftp_pkt *)rx_buf;
    addr = (struct sockaddr *)(&g_sess_args.server);
    recv_addr.s_addr = g_sess_args.server.sin_addr.s_addr;
    conn_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn_fd < 0)
    {
        fprintf(stderr, "socket %s\n", strerror(errno));
        free(tx_buf);
        free(rx_buf);
        return;
    }

send_packet:
    if (is_first_pkt)
        tx_len = construct_first_packet(tx_buf);
    else
        tx_len = construct_next_packet(tx_buf, r_block_num);
    // Check tx_len for write and send error packet

    retries = TFTP_NUM_RETRIES;
    wait_time = TFTP_TIMEOUT_MS;

send_again:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, addr, SOCKADDR_SIZE);
    if(bytes_sent <= 0)
    {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        goto exit_transfer;
    }
    if (is_finished)
    {
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
            fprintf(stderr, "Connection Stalled\n");
            goto exit_transfer;
        }
        wait_time += (wait_time >> 1);
        if (wait_time > TFTP_MAXTIMEOUT_MS)
            wait_time = TFTP_MAXTIMEOUT_MS;
        goto send_again;
    }
    else if (ret < 0)
    {
        fprintf(stderr, "epoll failure: %s\n", strerror(errno));
        goto exit_transfer;
    }

    if (is_first_pkt)
    {
        is_first_pkt = false;
        bytes_read = recvfrom(conn_fd, rx_buf, BUF_SIZE, 0, addr, &s_len);
        if (recv_addr.s_addr != g_sess_args.server.sin_addr.s_addr)
        {
            fprintf(stderr, "Received response from unknown IP address\n");
            goto exit_transfer;
        }

        ret = connect(conn_fd, addr, SOCKADDR_SIZE);
        if (ret != 0)
        {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            tx_len = construct_error_packet(tx_buf, EUNDEF, "connect failed");
            goto send_err_packet;
        }
    }
    else
    {
        bytes_read = recv(conn_fd, rx_buf, BUF_SIZE, 0);
    }

    if (bytes_read <= 0)
    {
        fprintf(stderr, "recv: %s\n", strerror(errno));
        tx_len = construct_error_packet(tx_buf, EUNDEF, strerror(errno));
        goto send_err_packet;
    }

    r_opcode = ntohs(rx_pkt->opcode);
    r_block_num = ntohs(rx_pkt->un.block);

    if (r_opcode == CODE_DATA)
    {
        if (r_block_num == e_block_num)
        {
            bytes_sent = write(g_sess_args.local_fd, rx_pkt->data, (size_t)(bytes_read - 4));
            e_block_num++;
            if (bytes_sent != (bytes_read - 4))
            {
                fprintf(stderr, "write: %s\n", strerror(errno));
                tx_len = construct_error_packet(tx_buf, ENOSPACE, strerror(errno));
                goto send_err_packet;
            }

            if ((size_t)(bytes_read - 4) < g_sess_args.block_size)
                is_finished = true;

            goto send_packet;
        }
    }
    else if (r_opcode == CODE_ERROR)
    {
        display_error_packet(rx_pkt, bytes_read);
        goto exit_transfer;
    }

    goto recv_again;

send_err_packet:
    bytes_sent = sendto(conn_fd, tx_buf, tx_len, 0, addr, SOCKADDR_SIZE);

exit_transfer:
    close(conn_fd);
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

    hostname = get_dest_addr(argv[optind], &(g_sess_args.server));
    if (hostname == NULL)
    {
        fprintf(stderr, "Destination IP %s could not be resolved\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (parse_parameters())
    {
        return EXIT_FAILURE;
    }

    perform_download();
    close(g_sess_args.local_fd);
    return 0;
}