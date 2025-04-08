#include <bits/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // ip address
    __type(value, __u32); // cookie
} cookie_map SEC(".maps");

static __u32 (*bpf_tcp_raw_gen_syncookie)(struct iphdr *iph, struct tcphdr *th, __u32 th_len) = (void *) BPF_FUNC_tcp_raw_gen_syncookie_ipv4; // helper for cookie generation

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
        if((void *)(tcp + 1) > data_end) return XDP_PASS;\

        if(tcp->syn && !tcp->ack){ // check syn packet

            __u32 cookie;
        
            // generate SYN cookie
            cookie = bpf_tcp_raw_gen_syncookie(ip, tcp, sizeof(*tcp));
            if (!cookie) return XDP_DROP;


            bpf_map_update_elem(&cookie_map, &ip->saddr, &cookie, BPF_ANY); // save cookie


            /* 

                end answer (SYN+ACK) with cookie
                hecksums
                pseudoH

            */


            /*

                ACK expected cookie check -> XDP_DROP || XDP_PASS
                delete cookie from map

            */
        } else if(tcp->ack && !tcp->syn){ // check ack packet


        }

    // IPv6 
    } else if(eth->h_proto == __constant_htons(ETH_P_IPV6)) {


    }




    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
