#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "slb.pb-c.h"

enum Op {
    DUMB,
    ADD_SA,
    DEL_SA,
    STATUS,
};

void
fatal(const char *func, int rv)
{
        fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
        exit(1);
}

void dump(uint8_t *buf, int len) {
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }
    printf("\n");
}

int construct_add_sa(char *buf, char *src_ip, int smask, char *dst_ip, int dmask,
        char *tmpl_src_ip, char *tmpl_dst_ip, uint32_t spi) {

    Slb__AddSaReq req;

    slb__add_sa_req__init(&req);
    int len;
    struct in_addr addr_src, addr_dst, addr_tmpl_src, addr_tmpl_dst;

    assert(inet_pton(AF_INET, src_ip, &addr_src) == 1);
    req.host_src.len = sizeof(struct in_addr);
    req.host_src.data = (void*)&addr_src;
    req.host_src_mask = (uint32_t)smask;

    assert(inet_pton(AF_INET, dst_ip, &addr_dst) == 1);
    req.host_dst.len = sizeof(struct in_addr);
    req.host_dst.data = (void*)&addr_dst;
    req.host_dst_mask = (uint32_t)dmask;

    assert(inet_pton(AF_INET, tmpl_src_ip, &addr_tmpl_src) == 1);
    req.tmpl_host_src.len = sizeof(struct in_addr);
    req.tmpl_host_src.data = (void*)&addr_tmpl_src;

    assert(inet_pton(AF_INET, tmpl_dst_ip, &addr_tmpl_dst) == 1);
    req.tmpl_host_dst.len = sizeof(struct in_addr);
    req.tmpl_host_dst.data = (void*)&addr_tmpl_dst;
    req.spi = spi;

    // include header here
    len = slb__add_sa_req__get_packed_size(&req) + 8; // 8 is sizeof(len) + sizeof(op)

    if (!buf) {
        return len;
    }

    slb__add_sa_req__pack(&req, buf + 8);
    *(uint32_t*)buf = htonl(len);
    *(uint32_t*)(buf + 4) = htonl(ADD_SA);

//    printf("pack return %d\n", len);
//    dump(buf, len);
     
    /*
    //unpack
    req2 = slb__add_sa_req__unpack(NULL, len, buf1);
    if (!req2) {
        printf("reply unpack failed\n");
        return -1;
    }
    printf("host src %s\n", req2->host_src);
    printf("host dst %s\n", req2->host_dst);
    printf("spi 0x%x:\n", req2->spi);
    printf("finished\n");
    free(buf1);
    slb__add_sa_req__free_unpacked(req2, NULL);
    */
    return len;
}

int construct_del_sa(char *buf, char *src_ip, int smask, char *dst_ip, int dmask,
        char *tmpl_src_ip, char *tmpl_dst_ip, uint32_t spi) {

    Slb__DelSaReq req;

    slb__del_sa_req__init(&req);
    int len;
    struct in_addr addr_src, addr_dst, addr_tmpl_src, addr_tmpl_dst;

    assert(inet_pton(AF_INET, src_ip, &addr_src) == 1);
    req.host_src.len = sizeof(struct in_addr);
    req.host_src.data = (void*)&addr_src;
    req.host_src_mask = (uint32_t)smask;

    assert(inet_pton(AF_INET, dst_ip, &addr_dst) == 1);
    req.host_dst.len = sizeof(struct in_addr);
    req.host_dst.data = (void*)&addr_dst;
    req.host_dst_mask = (uint32_t)dmask;

    assert(inet_pton(AF_INET, tmpl_src_ip, &addr_tmpl_src) == 1);
    req.tmpl_host_src.len = sizeof(struct in_addr);
    req.tmpl_host_src.data = (void*)&addr_tmpl_src;

    assert(inet_pton(AF_INET, tmpl_dst_ip, &addr_tmpl_dst) == 1);
    req.tmpl_host_dst.len = sizeof(struct in_addr);
    req.tmpl_host_dst.data = (void*)&addr_tmpl_dst;
    req.spi = spi;

    // include header here
    len = slb__del_sa_req__get_packed_size(&req) + 8; // 8 is sizeof(len) + sizeof(op)

    if (!buf) {
        return len;
    }

    slb__del_sa_req__pack(&req, buf + 8);
    *(uint32_t*)buf = htonl(len);
    *(uint32_t*)(buf + 4) = htonl(DEL_SA);

    return len;
}

int resolve_resp(char *buf, int len) {

    Slb__StatusResp *resp;
    int msglen = ntohl(*(int*)buf);

    if (msglen != len) {
        printf("len %d != %d\n", msglen, len);
        return -1;
    }
    int op = ntohl(*(int*)(buf+4));
    if (op != STATUS) {
        printf("return is not status, ignore %d\n", op);
        return -1;
    }

    resp = slb__status_resp__unpack(NULL, len - 8, buf + 8);
    if (!resp) {
        printf("reply unpack failed\n");
        return -1;
    }
    printf("host status is  %d\n", resp->status);
    slb__status_resp__free_unpacked(resp, NULL);

    return (int)resp->status;
}

int
node1(const char *url, uint32_t spi, char *srcip, char *dstip, char *tmplsrcip, char *tmpldstip, int del)
{
        nng_socket sock;
        int rv;
        size_t recv_sz;
        char *buf = NULL, *recvbuf = NULL;
        int i;

        if ((rv = nng_req0_open(&sock)) != 0) {
                fatal("nng_socket", rv);
        }
        if ((rv = nng_dial(sock, url, NULL, 0)) != 0) {
                fatal("nng_dial", rv);
        }

//        struct timespec t1, t2;
//        clock_gettime(CLOCK_REALTIME, &t1);
        int total_i = 1;
        for (i = 1; i <= total_i;i++){

            // construct data here
            int bufsize;
            char * srcpos = strchr(srcip, '/');
            char * dstpos = strchr(dstip, '/');
            if (!srcpos || !dstpos) {
                fatal("need netmask for src and dst subnet", -1);
            }
            *srcpos = '\0';
            *dstpos = '\0';
            int srcmask = atoi(srcpos+1);
            int dstmask = atoi(dstpos+1);

            if (!del)  {
                bufsize = construct_add_sa(NULL, srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi);
                if (bufsize < 0) {
                    printf("some error\n");
                    return -1;
                }
                buf = malloc(bufsize);
                if (!buf) {
                    printf("can not alloc mem %d size\n", bufsize);
                    return -1;
                }
                assert(construct_add_sa(buf, srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi) == bufsize);
                printf("add_sa: send src %s/%d dst %s/%d tmplsrc %s tmpdst %s spi %d\n", srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi);
            } else {
                bufsize = construct_del_sa(NULL, srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi);
                if (bufsize < 0) {
                    printf("some error\n");
                    return -1;
                }
                buf = malloc(bufsize);
                if (!buf) {
                    printf("can not alloc mem %d size\n", bufsize);
                    return -1;
                }
                assert(construct_del_sa(buf, srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi) == bufsize);
                printf("del_sa: send src %s/%d dst %s/%d tmplsrc %s tmpdst %s spi %d\n", srcip, srcmask, dstip, dstmask, tmplsrcip, tmpldstip, spi);
            }

            if ((rv = nng_send(sock, buf, bufsize, 0)) != 0) {
                    fatal("nng_send", rv);
            }
            if ((rv = nng_recv(sock, &recvbuf, &recv_sz, NNG_FLAG_ALLOC)) != 0) {
                    fatal("nng_recv", rv);
            }
            resolve_resp(recvbuf, recv_sz);
//            printf("count %d, receive data size %d\n", i, recv_sz);  
//            dump(recvbuf, recv_sz);
//            nng_msleep(1000);
        }
//        clock_gettime(CLOCK_REALTIME, &t2);
//        printf("count %d, time %ld\n", i, ((t2.tv_sec - t1.tv_sec) * 1000000000 + t2.tv_nsec - t1.tv_nsec) / 1000000);
        nng_free(buf, recv_sz);
        nng_close(sock);
        return (0);
}

// only send
int
main(int argc, char **argv)
{
    if (argc == 8) {
        return node1(argv[1], strtol(argv[2], NULL, 0), argv[3], argv[4], argv[5], argv[6], atoi(argv[7]));
    }

    fprintf(stderr, "Usage addsa: reqrep <URL> spi src dst tmplsrc tmpldst 0\n");
    fprintf(stderr, "Usage addsa: reqrep <URL> spi src dst tmplsrc tmpldst 1\n");
    return 1;
}
