#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#define NODE0 "node0"
#define NODE1 "node1"
#define DATE "DATE"

void
fatal(const char *func, int rv)
{
        fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
        exit(1);
}

char *
date(void)
{
        time_t now = time(&now);
        struct tm *info = localtime(&now);
        char *text = asctime(info);
        text[strlen(text)-1] = '\0'; // remove '\n'
        return (text);
}

int
node0(const char *url)
{
        nng_socket sock;
        int rv;

        if ((rv = nng_rep0_open(&sock)) != 0) {
                fatal("nng_rep0_open", rv);
        }
          if ((rv = nng_listen(sock, url, NULL, 0)) != 0) {
                fatal("nng_listen", rv);
        }
        for (;;) {
                char *buf = NULL;
                size_t sz;
                if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
                        fatal("nng_recv", rv);
                }
//                if ((sz == (strlen(DATE) + 1)) && (strcmp(DATE, buf) == 0)) {
                        printf("NODE0: RECEIVED :%s:\n", buf);
                        char *d = date();
                        printf("NODE0: SENDING DATE %s\n", d);
                        if ((rv = nng_send(sock, d, strlen(d) + 1, 0)) != 0) {
                                fatal("nng_send", rv);
                        }
//                }
                nng_free(buf, sz);
        }
}

int
node1(const char *url, char *name)
{
        nng_socket sock;
        int rv;
        size_t sz;
        char *buf = NULL;
        int i;

        if ((rv = nng_req0_open(&sock)) != 0) {
                fatal("nng_socket", rv);
        }
        if ((rv = nng_dial(sock, url, NULL, 0)) != 0) {
                fatal("nng_dial", rv);
        }
        for (i = 0;;i++){
        printf("NODE1(%s): SENDING DATE REQUEST %s\n", name, DATE);
        if ((rv = nng_send(sock, name, strlen(name)+1, 0)) != 0) {
                fatal("nng_send", rv);
        }
        if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
                fatal("nng_recv", rv);
        }
        printf("count %d, NODE1: RECEIVED DATE %s\n", i, buf);  
//        nng_msleep(10);
        }
        nng_free(buf, sz);
        nng_close(sock);
        return (0);
}

int
main(int argc, char **argv)
{
        if ((argc > 1) && (strcmp(NODE0, argv[1]) == 0))
                return (node0(argv[2]));

        if ((argc > 2) && (strcmp(NODE1, argv[1]) == 0))
                return (node1(argv[2], argv[3]));

      fprintf(stderr, "Usage: reqrep %s|%s <URL> ...\n", NODE0, NODE1);
      return (1);
}
