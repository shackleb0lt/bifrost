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

#include "serv_tftp.h"

bool g_running = true;
char g_serv_path[PATH_MAX];
char *g_exe_name = NULL;
uint32_t g_thread_count = 0;

void print_usage(char *err_str)
{
    if (err_str != NULL && *err_str != '\0')
        LOG_RAW("Error: %s\n", err_str);

    LOG_RAW("\nUsage:\n");
    LOG_RAW("  %s [OPTION]\n\n", g_exe_name);
    LOG_RAW("Options:\n");
    LOG_RAW("  %-18s Interface address to host server on\n", "-i IP_ADDR");
    LOG_RAW("  %-18s Port number to bind the server to\n",   "-p PORT_NO");
    LOG_RAW("  %-18s Server root directory\n",   "-s PATH");;
    LOG_RAW("  %-18s show usage and exit\n",     "-h");
    LOG_RAW("Note: By default binds to port %d\n", TFTP_SERVER_PORT);
    LOG_RAW("    : By default listens on all interfaces\n");
    LOG_RAW("    : Default server directory is %s\n", TFTP_SERVER_PATH);
}

void handle_signal(int sig)
{
    struct sigaction sa;
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);

    g_running = false;
}

int redirect_output()
{
    int fd = open(TFTP_SERVER_LOG, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0)
    {
        fprintf(stderr, "Failed to initialise log file, open: %s\n", strerror(errno));
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) < 0)
    {
        fprintf(stderr, "dup2 stdout: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (dup2(fd, STDERR_FILENO) < 0)
    {
        fprintf(stderr, "dup2 stderr: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int initiate_server(char *ip_addr, uint16_t port, char *path)
{
    int opt = 0;
    int sock_fd = -1;
    socklen_t addr_len = 0;
    struct sockaddr_storage addr = {0};

    if (realpath(path, g_serv_path) == NULL)
    {
        LOG_ERROR("Invalid server root %s: %s", path, strerror(errno));
        return -1;
    }

    strcat(g_serv_path, "/");
    memset(&addr, 0, sizeof(addr));
    if (ip_addr == NULL)
    {
        s_addr6 *server_addr = (s_addr6 *)&addr;
        server_addr->sin6_family = AF_INET6;
        server_addr->sin6_port   = htons(port);
        server_addr->sin6_addr   = in6addr_any;
        addr_len = sizeof(s_addr6);
    }
    else
    {
        s_addr4 *ipv4 = (s_addr4 *)&addr;
        s_addr6 *ipv6 = (s_addr6 *)&addr;

        if (inet_pton(AF_INET, ip_addr, &(ipv4->sin_addr)) == 1)
        {
            ipv4->sin_port = htons(port);
            ipv4->sin_family = AF_INET;
            addr_len = sizeof(s_addr4);
        }
        else if (inet_pton(AF_INET6, ip_addr, &(ipv6->sin6_addr)) == 1)
        {
            ipv6->sin6_port = htons(port);
            ipv6->sin6_family = AF_INET6;
            addr_len = sizeof(s_addr6);
        }
        else
        {
            LOG_ERROR("Invalid interface ip address %s", ip_addr);
            return -1;
        }
    }

    sock_fd = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        LOG_ERROR("socket: %s", strerror(errno));
        return -1;
    }

    opt = 0;
    if (addr.ss_family == AF_INET6 &&
        setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0)
    {
        LOG_ERROR("setsockopt IPV6_V6ONLY: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    opt = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        LOG_ERROR("setsockopt SO_REUSEADDR: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    if (bind(sock_fd, (s_addr *)&addr, addr_len) < 0)
    {
        LOG_ERROR("bind: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int connect_to_client(tftp_request *req)
{
    req->conn_sock = socket(req->addr.ss_family, SOCK_DGRAM, 0);
    if (req->conn_sock < 0)
    {
        LOG_ERROR("%s socket: %s", __func__, strerror(errno));
        return -1;
    }

    if (connect(req->conn_sock, (s_addr *)&(req->addr), req->addr_len) < 0)
    {
        LOG_ERROR("%s connect: %s", __func__, strerror(errno));
        close(req->conn_sock);
        return -1;
    }

    return 0;
}

size_t parse_filename(tftp_request *req, char *filename)
{
    char *ptr = NULL;
    struct stat st = {0};
    char temp[PATH_MAX] = {0};
    char fullname[PATH_MAX] = {0};
    LOG_INFO("%s", filename);

    snprintf(temp, PATH_MAX, "%s%s", g_serv_path, filename);
    ptr = strrchr(temp, '/') + 1; // strrchr can never return null due to g_serve_path
    if ((*ptr) == '\0')
    {
        LOG_ERROR("Path is a directory %s", temp);
        send_error_packet(req->conn_sock, "Provided path is a directory", EUNDEF);
        return 0;
    }

    if (req->type == CODE_RRQ)
    {
        if (realpath(temp, fullname) == NULL)
        {
            LOG_ERROR("Invalid path received %s: %s", temp, strerror(errno));
            send_error_packet(req->conn_sock, NULL, ENOTFOUND);
            return 0;
        }
        
        if (strncmp(fullname, g_serv_path, strlen(g_serv_path)) != 0)
        {
            LOG_ERROR("Illegal attempt to access %s", fullname);
            send_error_packet(req->conn_sock, NULL, EACCESS);
            return 0;
        }

        if (stat(fullname, &st) == -1)
        {
            LOG_ERROR("stat %s: %s", fullname, strerror(errno));
            send_error_packet(req->conn_sock, NULL, EACCESS);
            return 0;
        }

        if (S_ISREG(st.st_mode) == false)
        {
            LOG_ERROR("Path is a directory %s", fullname);
            send_error_packet(req->conn_sock, "Requested filepath is a directory", EBADOP);
            return 0;
        }

        req->file_size = st.st_size;
        req->file_desc = open(fullname, O_RDONLY);
    }
    else if (req->type == CODE_WRQ)
    {
        char c = (*ptr);
        (*ptr) = '\0';

        if (realpath(temp, fullname) == NULL)
        {
            LOG_ERROR("Invalid path received %s: %s", temp, strerror(errno));
            send_error_packet(req->conn_sock, NULL, ENOTFOUND);
            return 0;
        }

        strcat(fullname, "/");
        if (strncmp(fullname, g_serv_path, strlen(g_serv_path)) != 0)
        {
            LOG_ERROR("Illegal attempt to access %s", fullname);
            send_error_packet(req->conn_sock, NULL, EACCESS);
            return 0;
        }

        (*ptr) = c;
        strcat(fullname, ptr); // Try with path/.. later
        if (stat(fullname, &st) == 0 && S_ISDIR(st.st_mode))
        {
            LOG_ERROR("Path is prexisting directory %s", fullname);
            send_error_packet(req->conn_sock, "Upload filepath is prexisting directory", EBADOP);
            return 0;
        }

        req->file_size = 0;
        req->file_desc = open(fullname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    }

    if (req->file_desc < 0)
    {
        LOG_ERROR("open %s: %s", fullname, strerror(errno));
        send_error_packet(req->conn_sock, NULL, EUNDEF);
        return 0;
    }

    return strlen(filename) + 1;
}

int validate_parameters(tftp_request *req)
{
    size_t curr_len = 0;

    char *buf = req->data + ARGS_HDR_LEN;
    size_t len = (size_t)req->data_len - ARGS_HDR_LEN;

    req->t_size = -1;
    req->blk_size = DEF_BLK_SIZE;
    req->win_size = DEF_WIN_SIZE;
    req->BUF_SIZE = req->blk_size + DATA_HDR_LEN;

    curr_len = parse_filename(req, buf);
    if (curr_len == 0)
        return -1;
    else if (curr_len == len)
        return 0; // Add code to send a missing mode error packet later
    
    buf += curr_len;
    len -= curr_len;

    curr_len = strlen(buf) + 1;
    if (curr_len == len)
        return 0; // We don't use tftp mode, assume everything is binary

    buf += curr_len;
    len -= curr_len;
    if (extract_options(buf, len, &req->blk_size, &req->t_size, &req->win_size) < 0)
    {
        send_error_packet(req->conn_sock, NULL, EBADOPT);
        close(req->file_desc);
        return -1;
    }

    if (req->t_size != -1)
    {
        if (req->type == CODE_WRQ)
            req->file_size = req->t_size;
        else if (req->type == CODE_RRQ)
            req->t_size = req->file_size;
    }

    req->BUF_SIZE = req->blk_size + DATA_HDR_LEN;

    set_opcode(req->tx_buf, CODE_OACK);
    req->state = SEND_OACK;
    req->tx_len = ARGS_HDR_LEN;
    req->tx_len += insert_options(req->tx_buf + ARGS_HDR_LEN, req->blk_size, req->t_size, req->win_size);

    print_tftp_request(req->tx_buf, req->tx_len);
    return 0;
}

int tftp_send_file(tftp_request *req)
{
    TFTP_SERVER_STATE prev_state = RRQ_RECV;
    
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
            case SEND_OACK:
            {
                bytes_sent = send(req->conn_sock, req->tx_buf, req->tx_len, 0);
                if (bytes_sent < 0)
                {
                    LOG_ERROR("%s send OACK %s", __func__, strerror(errno));
                    return -1;
                }
                prev_state = SEND_OACK;
                req->state = WAIT_PKT;
                break;
            }
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
                    prev_state = SEND_DATA;
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
                    if (prev_state == SEND_DATA)
                    {
                        w_block_num = 0;
                        e_block_num -= req->win_size;
                    }
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
                if (r_opcode != CODE_ACK)
                {
                    // If non ack packet is received, discard
                    // And  wait for another packet
                    attempts++;
                    break;
                }

                if (prev_state == SEND_OACK && r_block_num == 0)
                {
                    req->state = SEND_DATA;
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
                e_block_num = l_block_num + 1;
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

int tftp_recv_file(tftp_request *req)
{
    TFTP_SERVER_STATE prev_state = WRQ_RECV;
    
    size_t w_block_num = 0;
    // size_t e_block_num = 1;
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
            case SEND_OACK:
            {
                bytes_sent = send(req->conn_sock, req->tx_buf, req->tx_len, 0);
                if (bytes_sent < 0)
                {
                    LOG_ERROR("%s send OACK %s", __func__, strerror(errno));
                    return -1;
                }
                prev_state = SEND_OACK;
                req->state = WAIT_PKT;
                break;
            }
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

                if (prev_state != WRQ_RECV && req->rx_len < req->blk_size)
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

void *handle_tftp_request(void *arg)
{
    tftp_request *req = (tftp_request *)arg;
    char ip_str[INET6_ADDRSTRLEN] = {0};
    int port = 0;
    int ret = 0;

    if (req->addr.ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&(req->addr);
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
        port = ntohs(ipv4->sin_port);
    }
    else if (req->addr.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&(req->addr);
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
        port = ntohs(ipv6->sin6_port);
    }

    LOG_RAW("_____________________________________________________________________\n");
    LOG_INFO("Incoming request from ip [%s] port [%d] len [%ld]", ip_str, port, req->data_len);

    ret = connect_to_client(req);
    if (ret < 0)
    {
        g_thread_count--;
        return NULL;
    }

    if (req->data_len <= ARGS_HDR_LEN)
    {
        send_error_packet(req->conn_sock, NULL, EBADOP);
        goto exit_transfer;
    }

    req->data[REQUEST_SIZE - 1] = '\0';

    print_tftp_request(req->data, (size_t) req->data_len);

    req->type = get_opcode(req->data);
    if (req->type != CODE_RRQ && req->type != CODE_WRQ)
    {
        send_error_packet(req->conn_sock, NULL, EBADOP);
        goto exit_transfer;
    }

    ret = validate_parameters(req);
    if (ret < 0)
    {
        goto exit_transfer;
    }

    if (req->type == CODE_RRQ)
    {
        if (req->state != SEND_OACK)
            req->state = SEND_DATA;
        ret = tftp_send_file(req);
    }
    else if (req->type == CODE_WRQ)
    {
        if (req->state != SEND_OACK)
            req->state = SEND_ACK;
        ret = tftp_recv_file(req);
    }

exit_transfer:
    close(req->conn_sock);
    free(req);
    g_thread_count--;
    return NULL;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int server_sock = 0;
    tftp_request *req = NULL;

    char *ip_addr = NULL;
    char *serv_path = TFTP_SERVER_PATH;
    uint16_t port = TFTP_SERVER_PORT;

    g_exe_name = argv[0];

    ret = register_sighandler(handle_signal);
    if (ret < 0)
        return EXIT_FAILURE;
    
    while ((ret = getopt(argc, argv, "i:p:s:h")) != -1)
    {
        switch (ret)
        {
            case 'i':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("IP Address not provided");
                    return EXIT_FAILURE;
                }
                ip_addr = optarg;
                break;
            }
            case 'p':
            {
                if (is_valid_portnum(optarg, &port) == false)
                {
                    print_usage("Invalid port number");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 's':
            {
                if (optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Server root directory path not provided");
                    return EXIT_FAILURE;
                }
                serv_path = optarg;
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

    server_sock = initiate_server(ip_addr, port, serv_path);
    if (server_sock < 0)
        return EXIT_FAILURE;

    if (ip_addr == NULL)
        LOG_INFO("TFTP Server is listening on addr [::] port %d (dual-stack enabled)", port);
    else
        LOG_INFO("TFTP Server is listening on addr %s port %d (dual-stack enabled)", ip_addr, port);

    ret = redirect_output();
    if (ret < 0)
        return EXIT_FAILURE;
    
    while (g_running)
    {
        if (req == NULL)
        {
            req = (tftp_request *) malloc(sizeof(tftp_request));
            if (req == NULL)
            {
                LOG_ERROR("%s malloc: %s", __func__, strerror(errno));
                break;
            }
        }

        memset(req, 0, sizeof(tftp_request));
        req->addr_len = sizeof(req->addr);
        req->data_len = recvfrom(server_sock, req->data, REQUEST_SIZE, 0, (s_addr *)&(req->addr), &(req->addr_len));
        if (req->data_len <= 0)
        {
            if (g_running)
                LOG_ERROR("recvfrom: %s", strerror(errno));

            continue;
        }

        if (g_thread_count >= MAX_SERVER_THREADS)
        {
            req->data_len = snprintf(req->data, REQUEST_SIZE, "Error: Too many connections, try again later.");
            sendto(server_sock, req->data, (size_t)req->data_len, 0, (s_addr *)&(req->addr), req->addr_len);
            continue;
        }

        pthread_t client_tid = 0;
        ret = pthread_create(&client_tid, NULL, handle_tftp_request, req);
        if (ret != 0)
        {
            LOG_ERROR("pthread_create: %d", ret);
            continue;
        }

        g_thread_count++;
        pthread_detach(client_tid);
        req = NULL;
    }

    close(server_sock);
    LOG_INFO("Server shutdown");

    return EXIT_SUCCESS;
}