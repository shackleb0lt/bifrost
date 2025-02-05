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

int initiate_server()
{
    int sock_fd = -1;
    int opt = 1;
    s4_addr saddr = {0};
    socklen_t sa_len = SOCKADDR_SIZE;

    memset(&saddr, 0, sa_len);
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(TFTP_SERVER_PORT);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        LOG_ERROR("socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        LOG_ERROR("setsockopt: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    if (bind(sock_fd, (s_addr *)&saddr, sa_len) < 0)
    {
        LOG_ERROR("bind: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int connect_to_client(tftp_context *ctx)
{
    s4_addr temp_addr;
    ctx->conn_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->conn_sock < 0)
    {
        LOG_ERROR("client socket: %s", strerror(errno));
        return -1;
    }

    memset(&temp_addr, 0, SOCKADDR_SIZE);
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    temp_addr.sin_port = 0;

    if (bind(ctx->conn_sock, (s_addr *)&temp_addr, SOCKADDR_SIZE) < 0) {
        LOG_ERROR("%s bind: %s", __func__, strerror(errno));
        close(ctx->conn_sock);
        return -1;
    }

    if (connect(ctx->conn_sock, (s_addr *)&(ctx->addr), SOCKADDR_SIZE) < 0)
    {
        LOG_ERROR("%s connect: %s", __func__, strerror(errno));
        close(ctx->conn_sock);
        return -1;
    }

    return 0;
}

size_t parse_filename(tftp_context *ctx, char *filename)
{
    char *ptr = NULL;
    struct stat st = {0};
    char temp[PATH_MAX] = {0};
    char fullname[PATH_MAX] = {0};
    char basename[PATH_LEN] = {0};

    snprintf(temp, PATH_MAX, "%s%s", TFTP_SERVER_PATH, filename);
    ptr = strrchr(temp, '/') + 1;
    if ((*ptr) == '\0')
    {
        LOG_ERROR("Path is a directory %s", temp);
        snprintf(ctx->err_str, DEF_BLK_SIZE, "Path is a directory");
        send_error_packet(ctx, EUNDEF);
        return 0;
    }

    if (ctx->action == CODE_WRQ)
    {
        strncpy(basename, ptr, PATH_LEN - 1);
        (*ptr) = '\0';
    }

    if (realpath(temp, fullname) == NULL)
    {
        LOG_ERROR("Invalid filename %s: %s", temp, strerror(errno));
        send_error_packet(ctx, ENOTFOUND);
        return 0;
    }

    if (strncmp(fullname, TFTP_SERVER_PATH, strlen(TFTP_SERVER_PATH)) != 0)
    {
        LOG_ERROR("Illegal attempt to access %s", fullname);
        send_error_packet(ctx, EACCESS);
        return 0;
    }

    if (ctx->action == CODE_RRQ)
    {
        if (stat(fullname, &st) == -1)
        {
            LOG_ERROR("stat %s: %s", fullname, strerror(errno));
            send_error_packet(ctx, EUNDEF);
            return 0;
        }

        if (S_ISREG(st.st_mode) == false)
        {
            LOG_ERROR("Path is a directory %s", fullname);
            snprintf(ctx->err_str, DEF_BLK_SIZE, "Path is a directory");
            send_error_packet(ctx, EBADOP);
            return 0;
        }

        ctx->file_size = st.st_size;
        ctx->file_desc = open(fullname, O_RDONLY);
    }
    else if (ctx->action == CODE_WRQ)
    {
        strcat(fullname, "/");
        strcat(fullname, basename);
        if (stat(fullname, &st) == 0 && S_ISDIR(st.st_mode))
        {
            LOG_ERROR("Path is prexisting directory %s", fullname);
            snprintf(ctx->err_str, DEF_BLK_SIZE, "Path is prexisting directory");
            send_error_packet(ctx, EBADOP);
            return 0;
        }

        fflush(stdout);
        ctx->file_size = 0;
        ctx->file_desc = open(fullname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    }

    if (ctx->file_desc < 0)
    {
        LOG_ERROR("open %s: %s", filename, strerror(errno));
        return 0;
    }

    return strlen(filename) + 1;
}

int validate_parameters(tftp_context *ctx, char *buf, size_t len)
{
    int ret = 0;
    off_t temp_size = -1;
    size_t curr_len = 0;

    ctx->blk_size = DEF_BLK_SIZE;
    ctx->win_size = DEF_WIN_SIZE;

    curr_len = parse_filename(ctx, buf);
    if (curr_len == 0)
        return -1;
    else if (curr_len == len)
        goto allocate_buffer; // Send a missing mode error packet later
    
    buf += curr_len;
    len -= curr_len;

    curr_len = strlen(buf) + 1;
    if (curr_len == len)
        goto allocate_buffer;

    buf += curr_len;
    len -= curr_len;

    if (extract_options(buf, len, &ctx->blk_size, &temp_size, NULL) < 0)
    {
        send_error_packet(ctx, EBADOPT);
        close(ctx->file_desc);
        return -1;
    }

allocate_buffer:
    ctx->BUF_SIZE = ctx->blk_size + DATA_HDR_LEN;
    ctx->tx_buf = (char *) malloc(ctx->BUF_SIZE);
    if (ctx->tx_buf == NULL)
    {
        LOG_ERROR("%s: malloc tx_buf: %s", __func__, strerror(errno));
        send_error_packet(ctx, EUNDEF);
        close(ctx->file_desc);
        return -1;
    }

    ctx->rx_buf = (char *) malloc(ctx->BUF_SIZE);
    if (ctx->rx_buf == NULL)
    {
        LOG_ERROR("%s: malloc rx_buf: %s", __func__, strerror(errno));
        send_error_packet(ctx, EUNDEF);
        close(ctx->file_desc);
        free(ctx->tx_buf);
        return -1;
    }

    memset(ctx->tx_buf, 0, ctx->BUF_SIZE);
    memset(ctx->rx_buf, 0, ctx->BUF_SIZE);

    if (temp_size != -1)
    {
        if (ctx->action == CODE_WRQ)
            ctx->file_size = temp_size;
        else if (ctx->action == CODE_RRQ)
            temp_size = ctx->file_size;
    }

    ret = insert_options(ctx->tx_buf + ARGS_HDR_LEN, ctx->BUF_SIZE - ARGS_HDR_LEN, ctx->blk_size, temp_size, DEF_WIN_SIZE);
    if (ret < 0)
    {
        send_error_packet(ctx, EUNDEF);
        return 1;
    }
    else if (ret == 0)
    {
        return 0;
    }

    set_opcode(ctx->tx_buf, CODE_OACK);
    ctx->tx_len = ARGS_HDR_LEN + (size_t) ret;

    print_tftp_request(ctx->tx_buf, ctx->tx_len);
    LOG_RAW("_____________________________________________________________________\n");

    if (ctx->action == CODE_RRQ)
    {
        tftp_send_file(ctx, true);
    }
    else if (ctx->action == CODE_WRQ)
    {
        tftp_recv_file(ctx, true);
    }

    return 1;
}

void *handle_tftp_request(void *arg)
{
    tftp_request *req = (tftp_request *)arg;
    char ip_str[INET6_ADDRSTRLEN] = {0};
    tftp_context ctx = {0};
    int ret = 0;

    memset(&ctx, 0, sizeof(tftp_context));
    ctx.a_len = SOCKADDR_SIZE;
    memcpy(&(ctx.addr), &(req->client_addr), ctx.a_len);

    inet_ntop(AF_INET, &(req->client_addr.sin_addr), ip_str, INET6_ADDRSTRLEN);
    LOG_RAW("_____________________________________________________________________\n");
    LOG_INFO("Incoming request from %s %d", ip_str, ntohs(req->client_addr.sin_port));

    ret = connect_to_client(&ctx);
    if (ret < 0)
        return NULL;

    if (req->data_len <= ARGS_HDR_LEN)
    {
        send_error_packet(&ctx, EBADOP);
        goto exit_transfer;
    }

    req->data[REQUEST_SIZE - 1] = '\0';

    print_tftp_request(req->data, (size_t) req->data_len);

    ctx.action = get_opcode(req->data);
    if (ctx.action != CODE_RRQ && ctx.action != CODE_WRQ)
    {
        send_error_packet(&ctx, EBADOP);
        goto exit_transfer;
    }

    ret = validate_parameters(&ctx, req->data + ARGS_HDR_LEN, (size_t)req->data_len - ARGS_HDR_LEN);
    if (ret < 0)
    {
        goto exit_transfer;
    }
    else if (ret > 0)
    {
        goto cleanup_ctx;
    }

    LOG_RAW("_____________________________________________________________________\n");

    if (ctx.action == CODE_RRQ)
    {
        tftp_send_file(&ctx, false);
    }
    else if (ctx.action == CODE_WRQ)
    {
        ctx.r_block_num = 0;
        ctx.tx_len = DATA_HDR_LEN;
        set_opcode(ctx.tx_buf, CODE_ACK);
        set_blocknum(ctx.tx_buf, ctx.r_block_num);
        tftp_recv_file(&ctx, true);
    }

cleanup_ctx:
    free(ctx.tx_buf);
    free(ctx.rx_buf);
    close(ctx.file_desc);
exit_transfer:
    free(req);
    close(ctx.conn_sock);
    return NULL;
}

int main()
{
    int ret = 0;
    int server_sock = 0;
    socklen_t s_len = SOCKADDR_SIZE;
    pthread_t client_th = 0;
    tftp_request *req = NULL;

    ret = redirect_output();
    if (ret < 0)
        return EXIT_FAILURE;

    ret = register_sighandler(handle_signal);
    if (ret < 0)
        return EXIT_FAILURE;

    server_sock = initiate_server();
    if (server_sock < 0)
        return EXIT_FAILURE;

    LOG_INFO("Server is running");

    while (g_running)
    {
        if (req == NULL)
        {
            req = (tftp_request *)malloc(sizeof(tftp_request));
            if (req == NULL)
            {
                LOG_ERROR("malloc: %s", strerror(errno));
                break;
            }
        }

        memset(req, 0, sizeof(tftp_request));

        req->data_len = recvfrom(server_sock, req->data, REQUEST_SIZE, 0, (s_addr *)&(req->client_addr), &s_len);
        if (req->data_len <= 0)
        {
            if (g_running)
                LOG_ERROR("recvfrom: %s", strerror(errno));

            continue;
        }

        ret = pthread_create(&client_th, NULL, handle_tftp_request, req);
        if (ret != 0)
        {
            LOG_ERROR("pthread_create: %d", ret);
            continue;
        }
        pthread_detach(client_th);
        req = NULL;
    }

    close(server_sock);
    LOG_INFO("Server shutdown");

    return EXIT_SUCCESS;
}

/**
 *  - Use 512 bytes for sending client request not blk_size string.
 * 
 *  - Check for MSG_TRUNC during incoming request
 *  - Remove MAX_FILE_SIZE limit as we have blk num roll over
 *  - Use threadpools
 *  - Implement window size
 *  - Add debug mode 
 */