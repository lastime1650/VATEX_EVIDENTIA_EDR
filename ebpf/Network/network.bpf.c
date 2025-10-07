#include "../helper.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

/*
    < Ring Buffer >
    Kernel -> User 
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} network_ringbuffer SEC(".maps");

/*
    <HASH MAP>
    User -> Kernel
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // Process ID ( except the User AGENT Event )
    __type(value, __u8); 
} user_hash SEC(".maps");

// ==========================
// IPv4 주소 → 문자열 변환
// ==========================
static __always_inline void ipv4_to_str(__u32 ip, char *out) {
    __u32 addr = __bpf_ntohl(ip);  // 네트워크 -> 호스트 바이트 순서
    __u8 b0 = (addr >> 24) & 0xFF;
    __u8 b1 = (addr >> 16) & 0xFF;
    __u8 b2 = (addr >> 8) & 0xFF;
    __u8 b3 = addr & 0xFF;

    int i = 0;
#define PUT_BYTE(b)                     \
    if (b >= 100) {                     \
        out[i++] = '0' + b / 100;       \
        out[i++] = '0' + (b / 10) % 10; \
        out[i++] = '0' + b % 10;        \
    } else if (b >= 10) {               \
        out[i++] = '0' + (b / 10);      \
        out[i++] = '0' + (b % 10);      \
    } else {                             \
        out[i++] = '0' + b;             \
    }

    PUT_BYTE(b0); out[i++] = '.';
    PUT_BYTE(b1); out[i++] = '.';
    PUT_BYTE(b2); out[i++] = '.';
    PUT_BYTE(b3);
    out[i] = '\0';
#undef PUT_BYTE
}

// ==========================
// 공통 패킷 처리 함수
// ==========================
static __always_inline int process_packet(struct __sk_buff *skb, bool is_ingress) {
    bpf_printk("[DEBUG] >> process_packet() start\n");

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    bpf_printk("[DEBUG] skb->len: %d, skb->ifindex: %d\n", skb->len, skb->ifindex);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("[DEBUG] drop: invalid ethhdr boundary\n");
        return TC_ACT_OK;
    }

    bpf_printk("[DEBUG] eth->h_proto: 0x%x\n", __bpf_ntohs(eth->h_proto));

    // IPv4 필터링
    if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
        bpf_printk("[DEBUG] non-IPv4 packet, skip\n");
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("[DEBUG] drop: invalid iphdr boundary\n");
        return TC_ACT_OK;
    }

    bpf_printk("[DEBUG] IPv4 packet detected, protocol=%d, ihl=%d\n", ip->protocol, ip->ihl);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_printk("[DEBUG] got current task struct: %p\n", task);

    // if AGENT_PROCESS ID, Return
    /*
        Key -> Process Id Type
        Value -> 0 or 1
    */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 key = pid_tgid >> 32; // 상위 32비트가 tgid   
    bpf_printk("[DEBUG] current pid_tgid: %llu, tgid(key): %llu\n", pid_tgid, key);

    u8* value_p = bpf_map_lookup_elem(&user_hash, &key);
    if (value_p) {
        bpf_printk("[DEBUG] found user_hash entry, value=%d\n", *value_p);
    } else {
        bpf_printk("[DEBUG] no user_hash entry for tgid=%llu\n", key);
    }

    if (value_p && *value_p == 1) {
        bpf_printk("[DEBUG] skip packet: AGENT_PROCESS detected\n");
        return TC_ACT_OK;
    }

    struct Network_event *e = bpf_ringbuf_reserve(&network_ringbuffer, sizeof(*e), 0);
    if (!e) {
        bpf_printk("[DEBUG] failed to reserve ringbuf entry\n");
        return TC_ACT_OK;
    }

    bpf_printk("[DEBUG] reserved ringbuf entry: %p\n", e);

    // make log header
    get_default_task_info(task, Network, &e->Header);
    bpf_printk("[DEBUG] header info filled\n");

    e->ifindex = skb->ifindex;
    e->pkt_len = skb->len;
    e->protocol = ip->protocol;
    e->is_INGRESS = is_ingress;
    bpf_printk("[DEBUG] basic event fields set, protocol=%d, ingress=%d\n", e->protocol, e->is_INGRESS);

    // IPv4 주소 변환
    ipv4_to_str(ip->saddr, e->ipSrc);
    ipv4_to_str(ip->daddr, e->ipDst);
    bpf_printk("[DEBUG] ipSrc: %x, ipDst: %x\n", ip->saddr, ip->daddr);

    // TCP / UDP 포트 추출
    e->portSrc = 0;
    e->portDst = 0;
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        void *l4hdr = (void *)ip + (ip->ihl * 4);
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4hdr;
            if ((void *)(tcp + 1) <= data_end) {
                e->portSrc = __bpf_ntohs(tcp->source);
                e->portDst = __bpf_ntohs(tcp->dest);
                bpf_printk("[DEBUG] TCP srcPort=%d dstPort=%d\n", e->portSrc, e->portDst);
            } else {
                bpf_printk("[DEBUG] invalid TCP header boundary\n");
            }
        } else {
            struct udphdr *udp = l4hdr;
            if ((void *)(udp + 1) <= data_end) {
                e->portSrc = __bpf_ntohs(udp->source);
                e->portDst = __bpf_ntohs(udp->dest);
                bpf_printk("[DEBUG] UDP srcPort=%d dstPort=%d\n", e->portSrc, e->portDst);
            } else {
                bpf_printk("[DEBUG] invalid UDP header boundary\n");
            }
        }
    } else {
        bpf_printk("[DEBUG] non-TCP/UDP protocol=%d\n", ip->protocol);
    }

    bpf_printk("[DEBUG] e->protocol: %d\n", e->protocol);
    bpf_ringbuf_submit(e, 0);
    bpf_printk("[DEBUG] submitted event to ringbuf\n");

    bpf_printk("[DEBUG] << process_packet() end\n");
    return TC_ACT_OK;
}


// ==========================
// Ingress Hook
// ==========================
SEC("tc/ingress")
int tc_ingress_prog(struct __sk_buff *skb) {
    return process_packet(skb, true);
}

// ==========================
// Egress Hook
// ==========================
SEC("tc/egress")
int tc_egress_prog(struct __sk_buff *skb) {
    return process_packet(skb, false);
}
