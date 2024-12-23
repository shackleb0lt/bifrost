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

/**
 * Returns a string literal corresponding to the 
 * mode type received, returns "octet" by default
 */
const char *get_tftp_mode_str(TFTP_MODE mode)
{
    if(mode == MODE_MAIL)
        return "mail";
        
    else if(mode == MODE_NETASCII)
        return "netascii";

    return "octet";
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
