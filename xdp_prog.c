#include <bits/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/byteorder/little_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

static __u32 (*bpf_tcp_raw_gen_syncookie_v4)(struct iphdr *iph, struct tcphdr *th, __u32 th_len) = (void *) BPF_FUNC_tcp_raw_gen_syncookie_ipv4; // helper for cookie generation ipv4
static __u32 (*bpf_tcp_raw_gen_syncookie_v6)(struct iphdr *iph, struct tcphdr *th, __u32 th_len) = (void *) BPF_FUNC_tcp_raw_gen_syncookie_ipv6; // helper for cookie generation ipv6

SEC("xdp_syn_cookie")
int handle_syn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data; //eth
    if((void *)(eth + 1) > data_end) return XDP_PASS;

    // IPv4
    if(eth->h_proto == __constant_htons(ETH_P_IP)){

        struct iphdr *ip = (struct iphdr*)(eth + 1); //ip
        if((void *)(ip + 1) > data_end) return XDP_PASS;

        struct tcphdr *tcp = (struct tcphdr*)(ip + 1); // tcp
        if((void *)(tcp + 1) > data_end) return XDP_PASS;

        if(tcp->syn && !tcp->ack){ // is packet syn && !ack?

            __u32 cookie;
       
            // generate SYN cookie
            cookie = bpf_tcp_raw_gen_syncookie_v4(ip, tcp, sizeof(*tcp));
            if (!cookie) return XDP_DROP;

            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

            __be32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            __be16 tmp_port = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = tmp_port;

            tcp->ack = 1;
            tcp->syn = 1;

            ip->check = 0;
            ip->check = ~bpf_csum_diff(0, 0, ip, sizeof(*ip), 0) & 0xffff;

            tcp->check = 0;
            __u32 csum = bpf_csum_diff(0, 0, tcp, sizeof(*tcp), 0);
            csum = bpf_csum_diff(0, 0, &ip->saddr, sizeof(ip->saddr), csum);
            csum = bpf_csum_diff(0, 0, &ip->daddr, sizeof(ip->daddr), csum);
            tcp->check = ~((csum & 0xffff) + (csum >> 16));

            return XDP_TX;

        } else if(tcp->ack && !tcp->syn){ // is packet ack && !syn?
            __u32 cookieRec = bpf_ntohl(tcp->ack_seq) - 1;
            __u32 cookieExp = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, sizeof(*tcp));

            if (!cookieRec || !cookieExp) return XDP_DROP;

            if(cookieRec != cookieExp) return XDP_DROP;

            return XDP_PASS;

        } else {
            return XDP_DROP;
        }

    // IPv6
    } else if(eth->h_proto == __constant_htons(ETH_P_IPV6)) {

    }


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

