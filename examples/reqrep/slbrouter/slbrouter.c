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

#define INNER_INDEX 0
#define OUTER_INDEX 1

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct macaddr);
} redirect_map SEC(".maps");

// no need to use ip arr, just test hash of daddr|saddr
// if no match, just xdp_pass
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct macaddr);
} mac_arr SEC(".maps");


SEC("xdp")
int xdp_pass_test(struct xdp_md *ctx) {
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

#if 1
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
int xdp_redirect_outer(struct xdp_md *ctx) {
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

    // get local mac 
	struct macaddr *local_mac_rec;
    __u32 local_mac_key = OUTER_INDEX;
	local_mac_rec = bpf_map_lookup_elem(&mac_arr, &local_mac_key);
	if (!local_mac_rec) {
		bpf_printk("no outer local mac found\n");
		goto out;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (eth->h_dest[i] != local_mac_rec->mac[i]) {
			goto out;
		}
	}

	ip_type = parse_iphdr(&nh, data_end, &iphdr);

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
//		if (bpf_ntohs(udphdr->source) != 4500 || bpf_ntohs(udphdr->dest) != 4500 || *(int *)nh.pos == 0) {
//		source may not be 4500 if remote sit behind nat
//		for espinudp, packet must be 4500 udp port + first 4 byte not zero
		if (bpf_ntohs(udphdr->dest) != 4500 || *(int *)nh.pos == 0) {
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
    struct macaddr *redir_mac_rec;
    __u64 redir_key = (__u64)esphdr->spi << 32 | (__u64)0;

	redir_mac_rec = bpf_map_lookup_elem(&redirect_map, &redir_key);
	if (!redir_mac_rec) {
		goto out;
	}

	// only redirect esp package
	__builtin_memcpy(eth->h_dest, redir_mac_rec->mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, local_mac_rec->mac, ETH_ALEN);
	//	action = bpf_redirect(ifindex, 0);
	action = XDP_TX;
	bpf_printk("esp redirected spi 0x%x\n", bpf_ntohl(esphdr->spi));

out:
	return action;
}

// redirect internal packet for inner_vip
SEC("xdp")
int xdp_redirect_inner(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	int eth_type, ip_type;
	int action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}

    // get local mac 
	struct macaddr *local_mac_rec;
    __u32 local_mac_key = OUTER_INDEX;
	local_mac_rec = bpf_map_lookup_elem(&mac_arr, &local_mac_key);
	if (!local_mac_rec) {
		bpf_printk("no outer local mac found\n");
		goto out;
	}

    int i;
	for (i = 0; i < ETH_ALEN; i++) {
		if (eth->h_dest[i] != local_mac_rec->mac[i]) {
			goto out;
		}
	}

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type == -1) {
		goto out;
	}

    // get redir mac
    struct macaddr *redir_mac_rec;
    __u64 redir_key = (__u64)iphdr->saddr << 32 | (__u64)iphdr->daddr;

	redir_mac_rec = bpf_map_lookup_elem(&redirect_map, &redir_key);
	if (!redir_mac_rec) {
		goto out;
	}

	__builtin_memcpy(eth->h_source, local_mac_rec->mac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, redir_mac_rec->mac, ETH_ALEN);

	action = XDP_TX;
	bpf_printk("subnet redirected src 0x%x, dst 0x%x\n", iphdr->saddr, iphdr->daddr);

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
