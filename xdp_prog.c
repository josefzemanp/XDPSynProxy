#include <bits/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // ip address
    __type(value, __u32); // cookie
} cookie_map SEC(".maps");

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


            bpf_map_update_elem(&cookie_map, &ip->saddr, &cookie, BPF_ANY); // save cookie

            tcp->ack = 1;
            tcp->syn = 1;
            tcp->seq = 0;
            tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);

            tcp->check = 0;
            tcp->check = bpf_csum_diff((__be32 *)&ip->saddr, sizeof(ip->saddr), (__be32 *)&ip->daddr, sizeof(ip->daddr), 0);
            tcp->check = bpf_csum_diff((__be32 *)&tcp, sizeof(*tcp), 0, 0, tcp->check);

            ip->check = 0;
            ip->check = bpf_csum_diff((__be32 *)&ip, sizeof(*ip), 0, 0, 0);

            return XDP_TX;

        } else if(tcp->ack && !tcp->syn){ // is packet ack && !syn?
            __u32 *cookieExists = bpf_map_lookup_elem(&cookie_map, &ip->saddr);

            if (!cookieExists) return XDP_DROP;

            __u32 cookieRec = bpf_ntohl(tcp->seq);
            if (cookieRec != *cookieExists) return XDP_DROP;

            bpf_map_delete_elem(&cookie_map, &ip->saddr);

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

