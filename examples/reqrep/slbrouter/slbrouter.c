// +build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <bpf_endian.h>
#include <linux/bpf.h>
// #include <common.h>
#include <bpf_helpers.h>
#include <parsing_helpers.h>
// #include "../vmlinux/vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct macaddr {
    __u8 mac[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct macaddr);
} redirect_map SEC(".maps");


SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	int action = XDP_PASS;
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
    struct iphdr *iphdr;
	struct hdr_cursor nh;
	int eth_type;
    int ip_type;

	nh.pos = data;
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (bpf_ntohs(eth_type) != ETH_P_IP) {
		goto out;
    }
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (ip_type != IPPROTO_ICMP) {
        goto out;
    }

	int icmp_type;
	struct icmphdr_common *icmphdr;
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (icmp_type != ICMP_ECHO) {
		goto out;
	}

	struct macaddr *rec;
    // combine saddr and daddr as key for internal redirect
    // this is for test internal, on little endian machine like this
    // local is lower bit, remote is upper bit
    __u64 key = (__u64)iphdr->saddr << 32 | (__u64)iphdr->daddr;
	rec = bpf_map_lookup_elem(&redirect_map, &key);
	if (!rec) {
		bpf_printk("null kookup\n");
//		action = XDP_ABORTED;
		goto out;
	}
    bpf_printk("redir icmp package from %x %x\n", eth->h_source[0], eth->h_source[5]);
    bpf_printk("redir icmp package to %x %x\n", rec->mac[0], rec->mac[5]);
    action = XDP_DROP;
out:
	return action;
}

#if 0
SEC("xdp")
int xdp_pass_ig(struct xdp_md *ctx) {
	return XDP_PASS;
}

SEC("xdp")
int xdp_icmp(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	int pkt_sz     = data_end - data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	//	__u16 echo_reply, old_csum;
	struct icmphdr_common *icmphdr;
	//	struct icmphdr_common icmphdr_old;
	//	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_ARP)) {
		bpf_printk("packet arp got: %d", pkt_sz);
		goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		//		swap_src_dst_ipv4(iphdr);
		//		echo_reply = ICMP_ECHOREPLY;
		bpf_printk("packet icmp got: %d", pkt_sz);
	} else if (eth_type == bpf_htons(ETH_P_IPV6) && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		//		swap_src_dst_ipv6(ipv6hdr);
		//		echo_reply = ICMPV6_ECHO_REPLY;
		bpf_printk("packet icmp6 got: %d", pkt_sz);
	} else {
		goto out;
	}

out:
	return XDP_PASS;
}

SEC("xdp")
int xdp_redirect_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ip_esp_hdr *esphdr;
	int eth_type, ip_type;
	int action = XDP_PASS;
	int i;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}
	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	// inside ip, we may see udp(esp) or udp(marker(ike))
	// or just raw esp
	unsigned char modify_dst11[ETH_ALEN] = {0xc2, 0xeb, 0xea, 0xec, 0xa5, 0x4d};
	unsigned char modify_dst12[ETH_ALEN] = {0x5a, 0x8e, 0xf4, 0x11, 0xe0, 0xf5};
	unsigned char *modify_dst            = NULL;
	unsigned char local_dst[ETH_ALEN]    = {0xe2, 0x9d, 0xd3, 0xa9, 0x18, 0x9f};

	for (i = 0; i < ETH_ALEN; i++) {
		if (eth->h_dest[i] != local_dst[i]) {
			goto out;
		}
	}

	// we have udp or esp here
	if (ip_type == IPPROTO_UDP) {
		struct udphdr *udphdr;
		int udplen;
		udplen = parse_udphdr(&nh, data_end, &udphdr);
		if (udplen < -1) {
			goto out;
		}
		if (nh.pos + 4 > data_end) {
			goto out;
		}
		if (bpf_ntohs(udphdr->source) != 4500 || bpf_ntohs(udphdr->dest) != 4500 || *(int *)nh.pos == 0) {
			goto out;
		}
		nh.pos += 4;
	} else if (ip_type != IPPROTO_ESP) {
		goto out;
	}

	// check esphdr head here for spi, currently only test 2 pc for lb
	// on to modify_dst1, another to modify_dst2, do the same according
	// to inner ip for xdp_redirect_internal
	esphdr = nh.pos;
	if ((void *)(esphdr + 1) > data_end) {
		goto out;
	}
	int spi = bpf_ntohl(esphdr->spi);
	if (spi == 0x1 || spi == 0x2) {
		modify_dst = modify_dst11;
		bpf_printk("esp forward to 11\n");
	} else if (spi == 0x3 || spi == 0x4) {
		modify_dst = modify_dst12;
		bpf_printk("esp forward to 12\n");
	} else {
		bpf_printk("unknown spi for test %d\n", spi);
		goto out;
	}

	// only redirect esp package
	__builtin_memcpy(eth->h_dest, modify_dst, ETH_ALEN);
	__builtin_memcpy(eth->h_source, local_dst, ETH_ALEN);
	//	action = bpf_redirect(ifindex, 0);
	action = XDP_TX;
	//    bpf_printk("esp redirected ifindex %d", ctx->ingress_ifindex);

out:
	return action;
}

// redirect internal packet to dst address to the fixed ether swan11
SEC("xdp")
int xdp_redirect_internal(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	int eth_type, ip_type;
	int action = XDP_PASS;
	int i;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}
	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type == -1) {
		goto out;
	}
	// inside ip, we may see udp(esp) or udp(marker(ike))
	// or just raw esp
	unsigned char local_dst[ETH_ALEN] = {
		0x66,
		0x43,
		0x72,
		0xdf,
		0x90,
		0x7e,
	};
	unsigned char local_ip[4] = {
		192,
		168,
		108,
		51,
	};

	for (i = 0; i < ETH_ALEN; i++) {
		if (eth->h_dest[i] != local_dst[i]) {
			goto out;
		}
	}

	int should_redir    = 0;
	unsigned char *dptr = (void *)&iphdr->daddr;
	for (i = 0; i < 4; i++) {
		if (dptr[i] != local_ip[i]) {
			// this is local's vip
			should_redir = 1; // not for local, redirect it, 50 also redirect
							  // arp will pass, so first arp for 50, get mac, then pass pkg to here, check not 51, redirect it
			break;
		}
	}
	if (should_redir == 0) { // dst is 51, pass it
		goto out;
	}

	// subnet 108 to 109
	unsigned char src_ip1[4] = {
		192,
		168,
		108,
		0,
	};
	// subnet 110 to 111
	unsigned char src_ip2[4] = {
		192,
		168,
		110,
		0,
	};

	unsigned char *modify_dst            = NULL;
	unsigned char modify_dst11[ETH_ALEN] = {
		0x5e,
		0xe8,
		0x95,
		0xea,
		0x79,
		0x6d,
	};
	unsigned char modify_dst12[ETH_ALEN] = {
		0xea,
		0x5b,
		0xbc,
		0x2e,
		0xc3,
		0x91,
	};

	unsigned char *sptr = (void *)&iphdr->saddr;
	int should_assign   = 1;
	for (i = 0; i < 3; i++) { // only compare subnet for test
		if (sptr[i] != src_ip1[i]) {
			should_assign = 0;
			break;
		}
	}
	if (should_assign) {
		modify_dst = modify_dst11;
		bpf_printk("subnet forward to 11\n");
	}

	if (!modify_dst) {
		should_assign = 1;
		for (i = 0; i < 3; i++) { // only compare subnet for test
			if (sptr[i] != src_ip2[i]) {
				should_assign = 0;
				break;
			}
		}
		if (should_assign) {
			modify_dst = modify_dst12;
			bpf_printk("subnet forward to 12\n");
		}
	}

	if (!modify_dst) {
		bpf_printk("src ip not in subnet domain %d.%d.%d.%d\n", sptr[0], sptr[1], sptr[2], sptr[3]);
		goto out;
	}

	// only redirect esp package
	__builtin_memcpy(eth->h_dest, modify_dst, ETH_ALEN);
	/*
	 * if don't change this, some bug happened to bridge,
	 * after first pkt redirected, brctl showmacs will learn
	 * source mac as comming from here port, so next forward
	 * to that wrong port, and pkt missed
	 */
	__builtin_memcpy(eth->h_source, local_dst, ETH_ALEN);
	//	action = bpf_redirect(ifindex, 0);
	action = XDP_TX;
	//    bpf_printk("subnet redirected ifindex %d", ctx->ingress_ifindex);

out:
	return action;
}

SEC("xdp")
int xdp_show_udp(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	int eth_type, ip_type;
	int action = XDP_PASS;
	int i;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	unsigned char local_dst[ETH_ALEN] = {0xc2, 0xeb, 0xea, 0xec, 0xa5, 0x4d};

	for (i = 0; i < ETH_ALEN; i++) {
		if (eth->h_dest[i] != local_dst[i]) {
			goto out;
		}
	}

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}
	ip_type = parse_iphdr(&nh, data_end, &iphdr);

	// we have udp or esp here
	if (ip_type == IPPROTO_UDP) {
		struct udphdr *udphdr;
		int udplen;
		udplen = parse_udphdr(&nh, data_end, &udphdr);
		if (udplen == -1) {
			goto out;
		}
		char *check = (char *)&udphdr->check;
		bpf_printk("udp check here is 0x%02x%02x", check[0], check[1]);
	} else {
		goto out;
	}

	//    bpf_printk("esp redirected ifindex %d", ctx->ingress_ifindex);

out:
	return action;
}
#endif
