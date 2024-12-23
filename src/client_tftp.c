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

char * g_exe_name = NULL;
tftp_session *g_sess_args = NULL;

/**
 * Prints the usage of the tftp client binary
 */
void print_usage(char *err_str)
{
    if(err_str != NULL && *err_str != '\0')
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
 * Parse the blocksize string and convert it to a number
 * Check if it falls within acceptable limit of 8 to 65464 bytes
 * Stores the parsed number in location pointed by block_size parameter 
 * @return true if valid, false otherwise
 */
bool is_valid_blocksize(char *size, uint16_t *block_size)
{
    uint16_t total = 0;
    uint32_t index = 0;

    if (size == NULL || *size == '\0')
        return false;

    for (index = 0; size[index] != '\0'; index++)
    {
        if (size[index] < '0' || size[index] > '9')
            return false;
        total *= 10;
        total += (uint8_t)(size[index] - '0');
    }

    if(total < MIN_BLK_SIZE || total > MAX_BLK_SIZE)
        return false;

    *block_size = total;
    return true;
}

/**
 * Parses the local and file names for validity
 * Autocompletes the destination path if it's a directory
 * by using the filename of source path.
 * Also opens the local file and stores the descriptor in args
 * @return true if valid filenames, false otherwise 
 */
bool parse_filenames(tftp_session *args)
{
    char *filename = NULL;
    size_t len = 0;

    args->local_fd = -1;
    if(args->action == CODE_WRQ)
    {
        if(args->local_file_name[args->local_len-1] == '/')
        {
            fprintf(stderr, "%s: local file path is directory\n", args->local_file_name);
            return false;
        }
    
        if(access(args->local_file_name, F_OK | R_OK) != 0)
        {
            fprintf(stderr, "%s: %s\n", args->local_file_name, strerror(errno));
            return false;
        }
        
        if(args->remote_file_name[args->remote_len-1] == '/')
        {
            filename = strrchr(args->local_file_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN);
            }
            else
            {
                filename = args->local_file_name;
                len = args->local_len;
            }
            
            if((args->remote_len + len) >= PATH_LEN)
            {
                fprintf(stderr, "Destination file name %s%s is too long",args->remote_file_name, filename);
                return false;
            }
            strncat(args->remote_file_name, filename, len);
        }

        args->local_fd = open(args->local_file_name, O_RDONLY);
    }
    else if(args->action == CODE_RRQ)
    {
        if(args->remote_file_name[args->remote_len-1] == '/')
        {
            fprintf(stderr, "%s: Remote file path is directory\n", args->remote_file_name);
            return false;
        }
    
        if(args->local_file_name[args->local_len-1] == '/')
        {
            filename = strrchr(args->remote_file_name, '/');
            if (filename != NULL)
            {
                filename++;
                len = strnlen(filename, PATH_LEN - 1);
            }
            else
            {
                filename = args->remote_file_name;
                len = args->remote_len;
            }
            
            if((args->remote_len + len) >= PATH_MAX)
            {
                fprintf(stderr, "Local file name %s%s will be too long\n",args->remote_file_name, filename);
                return false;
            }
            strncat(args->local_file_name, filename, len);
        }
        args->local_fd = open(args->local_file_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    }
    else
        return false;

    if(args->local_fd < 0)
    {
        fprintf(stderr, "Unable to open local file %s: %s\n", args->local_file_name, strerror(errno));
        return false;
    }

    return true;
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

    if(g_sess_args)
    {
        close(g_sess_args->local_fd);
        g_sess_args = NULL;
    }
    exit(128 + sig);
}

/**
 * Convert hostname or ipv4 address from string to 
 * network form and stores in dest_addr pointer.
 * @returns A static string which hold presentation form
 */
char *get_dest_addr(const char *input, ipv4addr dest_addr)
{
    int ret = 0;
    struct addrinfo hint;
    struct addrinfo *res;
    static char ipstr[INET_ADDRSTRLEN] = {0};

    // Check if string is of the form "X.X.X.X"
    ret = inet_pton(AF_INET, input, dest_addr);
    if (ret == 1)
    {
        strncpy(ipstr, input, INET_ADDRSTRLEN - 1);
        return ipstr;
    }

    // If a hostname was provided retreive it's ip address 
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_RAW;
    hint.ai_protocol = IPPROTO_ICMP;
    hint.ai_flags = 0;

    ret = getaddrinfo(input, NULL, &hint, &res);
    if (ret != 0 || res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return NULL;
    }
    dest_addr->s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    inet_ntop(AF_INET, dest_addr, ipstr, INET_ADDRSTRLEN);
    return ipstr;
}

int main(int argc, char * argv[])
{
    int ret = 0;
    char * hostname = NULL;
    tftp_session sess_args = {0};
    struct in_addr server_ip = {0};

    g_exe_name = argv[0];

    ret = register_sighandler(handle_signal);
    if (ret != 0)
        return EXIT_FAILURE;

    memset(&sess_args, 0, sizeof(tftp_session));
    sess_args.blk_size = DEF_BLK_SIZE;
    sess_args.mode = MODE_OCTET;

    while ((ret = getopt(argc, argv, "l:r:b:gph")) != -1)
    {
        switch (ret)
        {
            case 'b':
            {
                if(!is_valid_blocksize(optarg, &(sess_args.blk_size)))
                {
                    printf("Invalid Block Size %s\n", optarg);
                    print_usage("");
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'g':
            {
                if(sess_args.action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                sess_args.action = CODE_RRQ;
                break;
            }
            case 'p':
            {
                if(sess_args.action != CODE_UNDEF)
                {
                    print_usage("Either -g or -p can be passed, not both");
                    return EXIT_FAILURE;
                }
                sess_args.action = CODE_WRQ;
                break;
            }
            case 'l':
            {
                if(optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Local path not provided");
                    return EXIT_FAILURE;
                }
                sess_args.local_len = strnlen(optarg, PATH_MAX);
                if(sess_args.local_len >= PATH_MAX)
                {
                    print_usage("Local path should be shorter than "TOSTRING(PATH_MAX));
                    return EXIT_FAILURE;
                }
                strncpy(sess_args.local_file_name, optarg, sess_args.local_len);
                break;
            }
            case 'r':
            {
                if(optarg == NULL || *optarg == '\0' || *optarg == '-')
                {
                    print_usage("Remote path not provided");
                    return EXIT_FAILURE;
                }
                sess_args.remote_len = strnlen(optarg, PATH_LEN);
                if(sess_args.remote_len >= PATH_LEN)
                {
                    print_usage("Remote path is too long");
                    return EXIT_FAILURE;
                }
                strncpy(sess_args.remote_file_name, optarg, sess_args.remote_len);
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

    if(sess_args.action == CODE_UNDEF)
    {
        print_usage("Either -g or -p option is required");
        return EXIT_FAILURE;
    }

    if(sess_args.local_len == 0)
    {
        print_usage("Need to specify local path");
        return EXIT_FAILURE;
    }

    if(sess_args.remote_len == 0)
    {
        print_usage("Need to specify remote path");
        return EXIT_FAILURE;
    }

    if (argv[optind] == NULL)
    {
        print_usage("Missing destination argument");
        return EXIT_FAILURE;
    }

    hostname = get_dest_addr(argv[optind], &server_ip);
    if(hostname == NULL)
    {
        fprintf(stderr, "Destination IP %s could not be resolved\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if(!parse_filenames(&sess_args))
    {
        return EXIT_FAILURE;
    }

    g_sess_args = &sess_args;
    printf("local: %s\n", sess_args.local_file_name);
    printf("remote: %s\n", sess_args.remote_file_name);
    close(sess_args.local_fd);
    return 0;
}
