#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void usage()
{
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test eth0\n");
}

u_int32_t   print_mac_addr  (const u_char* packet);
u_int32_t   print_ip_addr   (const u_char* packet, u_int32_t* tot_l);
u_int32_t   print_tcp_port  (const u_char* packet);
void        print_packet    (const u_char* packet, const u_int32_t* payload_l);

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
        u_int32_t tot_l, ip_hl, tcp_hl, payload_l;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("***********************************\n\n");
        printf("%d bytes captured\n", header->caplen);

        /*
         * add code -----------
         * ethernet header (dest port, src port)
         * ip header (src ip , dest ip)
         * tcp header (src port, dest port)
         * payload (max 16 bytes)
         */

        u_int32_t pointer = 0;

        // ethernet
        pointer += print_mac_addr(packet);

        // ip
        ip_hl = print_ip_addr(packet+pointer, &tot_l);  // receive ip header length & total packet length (ip header + tcp header + payload)
        pointer += ip_hl;

        // tcp
        tcp_hl = print_tcp_port(packet+pointer);        // receive tcp header length
        pointer += tcp_hl;
        printf("=======================\n");

        // data
        payload_l = tot_l - ip_hl - tcp_hl;         // get payload length
        print_packet(packet+pointer, &payload_l);   // print packet (max length: 16 bytes)

        printf("\n");
    }

    return 0;
}

u_int32_t print_mac_addr(const u_char* packet)
{
    struct libnet_ethernet_hdr *ether_h;
    ether_h = (struct libnet_ethernet_hdr *) packet;

    printf("===== MAC Address =====\n");
    printf("src MAC  = %02X:%02X:%02X:%02X:%02X:%02X\n"
           , ether_h->ether_shost[0]
           , ether_h->ether_shost[1]
           , ether_h->ether_shost[2]
           , ether_h->ether_shost[3]
           , ether_h->ether_shost[4]
           , ether_h->ether_shost[5]);

    printf("dest MAC = %02X:%02X:%02X:%02X:%02X:%02X\n"
            , ether_h->ether_dhost[0]
            , ether_h->ether_dhost[1]
            , ether_h->ether_dhost[2]
            , ether_h->ether_dhost[3]
            , ether_h->ether_dhost[4]
            , ether_h->ether_dhost[5]);

    return 14; // ethernet header length
}

u_int32_t print_ip_addr(const u_char* packet, u_int32_t* tot_l)
{
    struct libnet_ipv4_hdr *ip4_h;
    ip4_h = (struct libnet_ipv4_hdr *) packet;

    printf("===== IP  Address =====\n");
    // inet_ntoa() : 32bit address NBO -> HBO (+ dotted decimal notation)
    printf("src IP  = %s\n", inet_ntoa(ip4_h->ip_src));
    printf("dest IP = %s\n", inet_ntoa(ip4_h->ip_dst));

    *tot_l = (u_int32_t) ntohs(ip4_h->ip_len);

    // compute ip header length (bytes)
    u_int32_t ip_hl = ip4_h->ip_hl * 4;

    return ip_hl;
}

u_int32_t print_tcp_port(const u_char* packet)
{
    struct libnet_tcp_hdr *tcp_h;
    tcp_h = (struct libnet_tcp_hdr *) packet;

    printf("=== TCP Port Number ===\n");
    printf("src Port  = %u\n", ntohs(tcp_h->th_sport));
    printf("dest Port = %u\n", ntohs(tcp_h->th_dport));

    // compute ip header length (bytes)
    u_int32_t tcp_hl = tcp_h->th_off * 4;

    return tcp_hl;
}

void print_packet(const u_char* packet, const u_int32_t* payload_l)
{
    u_int8_t loop = *payload_l < 16 ? *payload_l : 16;

    for (u_int8_t i = 0; i < loop; i++) {
        printf("%02lX ", (u_int64_t) packet[i]);
    }
    printf("\n");

    return;
}
