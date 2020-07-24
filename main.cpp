#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void usage()
{
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test eth0\n");
}

u_int32_t   get_mac_addr    (const u_char* packet, u_int8_t* src_ether, u_int8_t* dest_ether);
u_int32_t   get_ip_addr     (const u_char* packet, u_int32_t* tot_l, struct in_addr* src_ip, struct in_addr* dest_ip);
u_int32_t   get_tcp_port    (const u_char* packet, u_int16_t* src_port, u_int16_t* dest_port);
void        print_packet    (const u_char* packet, const u_int32_t* payload_l,
                             const u_int8_t* src_ether, const u_int8_t* dest_ether,
                             const struct in_addr* src_ip, const struct in_addr* dest_ip,
                             const u_int16_t* src_port, const u_int16_t* dest_port);

int main(int argc, char* argv[])
{
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1]; // interface name (eth0)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        u_int32_t tot_l, eth_hl, ip_hl, tcp_hl, payload_l;
        u_int16_t src_port, dest_port;
        u_int8_t src_ether[6], dest_ether[6];
        struct in_addr src_ip, dest_ip;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        /*
         * add code -----------
         * ethernet header (dest port, src port)
         * ip header (src ip , dest ip)
         * tcp header (src port, dest port)
         * payload (max 16 bytes)
         */

        u_int32_t pointer = 0;
        payload_l = (u_int32_t) header->caplen;
//        printf("received capture length %u\n", header->caplen);

        // ethernet
        eth_hl = get_mac_addr(packet, src_ether, dest_ether);
        if (eth_hl == 0) continue;   // check ip
        pointer += eth_hl;
        payload_l -= eth_hl;
//        printf("ether head length : %u\n", eth_hl);

        // ip
        ip_hl = get_ip_addr(packet+pointer, &tot_l, &src_ip, &dest_ip); // receive ip header length & total packet length (ip header + tcp header + payload)
        if (ip_hl == 0) continue;    // check tcp
        pointer += ip_hl;
        payload_l -= ip_hl;
//        printf("ip head length : %u\n", ip_hl);

        // tcp
        tcp_hl = get_tcp_port(packet+pointer, &src_port, &dest_port);   // receive tcp header length
        pointer += tcp_hl;
        payload_l -= tcp_hl;
//        printf("tcp head length : %u\n", tcp_hl);

        // data
//        payload_l = tot_l - ip_hl - tcp_hl;                         // get payload length
        print_packet(packet+pointer, &payload_l, src_ether, dest_ether,
                     &src_ip, &dest_ip, &src_port, &dest_port);     // print packet (max length: 16 bytes)

        printf("\n");
    }

    return 0;
}

u_int32_t get_mac_addr(const u_char* packet, u_int8_t* src_ether, u_int8_t* dest_ether)
{
    struct libnet_ethernet_hdr *ether_h;

    ether_h = (struct libnet_ethernet_hdr *) packet;
    memcpy(src_ether, ether_h->ether_shost, sizeof(u_int8_t)*6);
    memcpy(dest_ether, ether_h->ether_dhost, sizeof(u_int8_t)*6);

    if (ntohs(ether_h->ether_type) != ETHERTYPE_IP) return 0;

    return 14; // ethernet header length
}

u_int32_t get_ip_addr(const u_char* packet, u_int32_t* tot_l, struct in_addr* src_ip, struct in_addr* dest_ip)
{
    struct libnet_ipv4_hdr *ip4_h;

    ip4_h = (struct libnet_ipv4_hdr *) packet;
    memcpy(src_ip, &ip4_h->ip_src, sizeof(struct in_addr));
    memcpy(dest_ip, &ip4_h->ip_dst, sizeof(struct in_addr));

    if (ip4_h->ip_p != IPPROTO_TCP) return 0;

    // compute ip header length (bytes) and total packet length
    *tot_l = (u_int32_t) ntohs(ip4_h->ip_len);
    u_int32_t ip_hl = ip4_h->ip_hl * 4;

    return ip_hl;
}

u_int32_t get_tcp_port(const u_char* packet, u_int16_t* src_port, u_int16_t* dest_port)
{
    struct libnet_tcp_hdr *tcp_h;
    tcp_h = (struct libnet_tcp_hdr *) packet;

    *src_port = ntohs(tcp_h->th_sport);
    *dest_port = ntohs(tcp_h->th_dport);

    // compute ip header length (bytes)
    u_int32_t tcp_hl = tcp_h->th_off * 4;

    return tcp_hl;
}

void print_packet(const u_char* packet, const u_int32_t* payload_l,
                  const u_int8_t* src_ether, const u_int8_t* dest_ether,
                  const struct in_addr* src_ip, const struct in_addr* dest_ip,
                  const u_int16_t* src_port, const u_int16_t* dest_port)
{
    u_int8_t loop = *payload_l < 16 ? *payload_l : 16;

    printf("***********************************\n\n");

    printf("===== MAC Address =====\n");
    printf("src MAC  = %02X:%02X:%02X:%02X:%02X:%02X\n"
           , src_ether[0]
           , src_ether[1]
           , src_ether[2]
           , src_ether[3]
           , src_ether[4]
           , src_ether[5]);
    printf("dest MAC = %02X:%02X:%02X:%02X:%02X:%02X\n"
           , dest_ether[0]
           , dest_ether[1]
           , dest_ether[2]
           , dest_ether[3]
           , dest_ether[4]
           , dest_ether[5]);

    printf("===== IP  Address =====\n");
    // inet_ntoa() : 32bit address NBO -> HBO (+ dotted decimal notation)
    printf("src IP  = %s\n", inet_ntoa(*src_ip));
    printf("dest IP = %s\n", inet_ntoa(*dest_ip));

    printf("=== TCP Port Number ===\n");
    printf("src Port  = %u\n", *src_port);
    printf("dest Port = %u\n", *dest_port);

    for (u_int8_t i = 0; i < loop; i++) {
        printf("%02lX ", (u_int64_t) packet[i]);
    }
    printf("\n");
    printf("=======================\n");

    return;
}
