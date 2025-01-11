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

/**
 * Converts tftp error code to string
 * Returns a pointer to string literal
 */
const char *tftp_err_to_str(TFTP_ERRCODE err_code)
{
    if(err_code > EBADOPT)
        err_code = EUNDEF;
    return err_strs[err_code];
}

/**
 * Returns a string literal corresponding to the
 * mode type received, returns "octet" by default
 */
size_t tftp_mode_to_str(TFTP_MODE mode, char **mode_str)
{
    char *str = NULL;
    if (mode == MODE_MAIL)
        str = "mail";
    else if (mode == MODE_NETASCII)
        str = "netascii";
    else
        str= "octet";
    
    *mode_str = str;
    return strlen(str);
}

/**
 * Parse the blocksize string and convert it to a number
 * Check if it falls within acceptable limit of 8 to 65464 bytes
 * Stores the parsed number in location pointed by block_size parameter
 * @return true if valid, false otherwise
 */
bool is_valid_blocksize(char *size_str, size_t *block_size)
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

        if(total > MAX_BLK_SIZE)
            return false;
    }

    if (total < MIN_BLK_SIZE)
        return false;

    *block_size = total;
    return true;
}

/**
 * Scans the string received in OACK by client or in Request by server
 * If an option with name opt is present return it's value as str
 * 
 * Returns NULL if such an option was not found  
 */
char *get_option_val(const char *opt, char *oack_str, ssize_t len)
{
    int i = 0;
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
        fprintf(stderr, "sigaction: SIGTERM");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGINT");
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGHUP");
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGHUP");
        return -1;
    }
    return 0;
}