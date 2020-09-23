#include <pcap.h>

#include <stdlib.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <stdio.h>

 

struct eth_hdr {

    unsigned char dst_mac[6];

    unsigned char src_mac[6];

    unsigned short type;

};

 

struct IPv4_hdr {

    unsigned char unnecessary_1 : 4;

    unsigned char ip_hdr_len : 4;

    unsigned char unnecessary_2[8];

    unsigned char protocol;

    unsigned char unnecessary_3[2];

    struct in_addr src_add;

    struct in_addr dst_add;

};

 

struct TCP_hdr {

    unsigned short src_port;

    unsigned short dst_port;

    unsigned char unnecessary[8];

    unsigned char tcp_hdr_offset : 4;

};

 

struct http

{

    unsigned char data[16];

};

 

void usage() {

    printf("syntax: pcap-test <interface>\n");

    printf("sample: pcap-test wlan0\n");

}

 

int print_ethernet_header(const u_char* packet) {

    struct eth_hdr* eth;

    eth = (struct eth_hdr*)packet;

    printf("\n----------Ethernet Header----------\n");

    printf("destination mac %02x:%02x:%02x:%02x:%02x:%02x \n", eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2], eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

    printf("source mac %02x:%02x:%02x:%02x:%02x:%02x \n", eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);

    eth->type = ntohs(eth->type);

    if (eth->type != 0x0800) {

        printf("it doesn't use IPv4 \n");

        return -1;

    }

    return 0;

}

 

int print_IP_header(const u_char* packet) {

    struct IPv4_hdr* ip;

    ip = (struct IPv4_hdr*)packet;

    printf("----------IP Header----------\n");

    if (ip->protocol != 0x06) {

        printf("it doesn't use TCP\n");

        return -1;

    }

    printf("source IP  : %s\n", inet_ntoa(ip->src_add)); // inet_ntoa : dotted decimal로 변형

    printf("destination IP  : %s\n", inet_ntoa(ip->dst_add));

    return (ip->ip_hdr_len);

}

 

 

 

int print_TCP_header(const u_char* packet) {

    struct TCP_hdr* tcp;

    tcp = (struct TCP_hdr*)packet;

    printf("----------TCP Header----------\n");

    printf("source port : %d\n", ntohs(tcp->src_port)); // 보통 port num은 8000번 같은 10진수

    printf("destination port : %d\n", ntohs(tcp->dst_port));

    return (tcp->tcp_hdr_offset);

}

 

 

 

void print_http_data(const u_char* packet) {

    for (int i = 0; i < 16; i++) {

        printf("%02x ", *(packet + i));

    }

    printf("\n");

 

}

 

 

int main(int argc, char* argv[]) {

    if (argc != 2) {

        usage();

        return -1;

    }

 

    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {

        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);

        return -1;

    }

 

    while (true) {

        struct pcap_pkthdr* header;

        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;

        if (res == -1 || res == -2) {

            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));

            break;

        }

        

        int num = print_ethernet_header(packet);

        if (num == -1) {

            continue;

        }

 

        packet += 14;

 

        num = print_IP_header(packet);

        if (num == -1) {

            continue;

        }

 

        packet += num * 4;

 

        num = print_TCP_header(packet);

 

        packet += num * 4;

 

        print_http_data(packet);

    }

 

    pcap_close(handle);

    return 0;

}
