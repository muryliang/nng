#include <stdio.h>
#include <stdlib.h>
#include "slb.pb-c.h"

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

int main(int ac, char *av[]) {

    Slb__AddSaReq req, *req2;

    slb__add_sa_req__init(&req);
    uint8_t arr[4] = {0x1, 0x2, 0x3, 0x4};
    int len;
    uint8_t *buf1;

    req.host_src = "192.168.1.1";
    req.host_dst = "192.168.2.1";
    req.spi = 0x12345678;

    len = slb__add_sa_req__get_packed_size(&req);
    printf("req size is %d\n", len);

    buf1 = malloc(len);
    if (!buf1) {
        return -1;
    }
    len = slb__add_sa_req__pack(&req, buf1);
    printf("pack return %d\n", len);

     
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
    return 0;
}
