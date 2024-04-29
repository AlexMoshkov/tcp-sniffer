//
// Created by dtalexundeer on 4/10/24.
//

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../include/capture.h"
#include "../include/sniffer.h"
#include "../include/handlers.h"

#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/tcp.h"
#include <netinet/ip.h>


const char filter_delimiter[] = " || ";

void process_packets_by_filters(struct sniffer *sniff, const struct pcap_pkthdr *header, const u_char *packet) {
    for (size_t i = 0; i < sniff->filters_count; ++i) {
        if (pcap_offline_filter(&sniff->filters[i].fp, header, packet)) {
            process_handlers(&sniff->filters[i], header, packet);
        }
    }
}

void print_payload(const u_char *payload, int len);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct sniffer *sniff = (struct sniffer *) args;

    static int count = 1;

    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number: %d\n", count++);

    process_packets_by_filters(sniff, header, packet);

//    ethernet = (struct sniff_ethernet *) (packet);
//    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
//
//    size_ip = IP_HL(ip) * 4;
//    if (size_ip < 20) {
//        printf("    * Invalid IP header length: %u bytes", size_ip);
//        return;
//    }
//
//    printf("       From: %s\n", inet_ntoa(ip->ip_src));
//    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
//
//    switch (ip->ip_p) {
//        case IPPROTO_TCP:
//            printf("   Protocol: TCP\n");
//            break;
//        case IPPROTO_UDP:
//            printf("   Protocol: UDP\n");
//            return;
//        case IPPROTO_ICMP:
//            printf("   Protocol: ICMP\n");
//            return;
//        case IPPROTO_IP:
//            printf("   Protocol: IP\n");
//            return;
//        default:
//            printf("   Protocol: unknown\n");
//            return;
//    }
//
//    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
//    size_tcp = TH_OFF(tcp) * 4;
//    if (size_tcp < 20) {
//        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
//        return;
//    }
//
//    printf("   Src port: %d\n", ntohs(tcp->th_sport));
//    printf("   Dst port: %d\n", ntohs(tcp->th_dport));
//
//    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
//    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
//    if (size_payload > 0) {
//        printf("   Payload (%d bytes):\n", size_payload);
//        print_payload(payload, size_payload);
//    }
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
}

void print_payload(const u_char *payload, int len) {
    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

}


void sniff_interface(char *device, struct config *cfg) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle;
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(1);
    }

//    if (pcap_datalink(handle) != DLT_EN10MB) {
//        fprintf(stderr, "Device %s doesn't provide, Ethernet headers - not supported", device);
//        exit(1);
//    }

    struct sniffer *sniff;
    init_sniffer(handle, cfg, &sniff);

    // build full filter string from all filters
    size_t full_filter_size = 0;
    size_t delimiter_size = strlen(filter_delimiter);
    for (int i = 0; i < sniff->filters_count; ++i) {
        compile_filter(&sniff->filters[i], cfg->handlers[i], handle);
        full_filter_size += strlen(sniff->filters[i].filter_str) + delimiter_size;
    }
    char full_filter[full_filter_size];
    strcpy(full_filter, "");
    for (int i = 0; i < sniff->filters_count; ++i) {
        strcat(full_filter, sniff->filters[i].filter_str);
        if (i < sniff->filters_count - 1) {
            strcat(full_filter, filter_delimiter);
        }
    }

    // set full filter
    if (pcap_compile(handle, &sniff->full_fp, full_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't compile full filter %s: %s\n", full_filter, pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &sniff->full_fp) == -1) {
        fprintf(stderr, "Couldn't install full filter %s: %s", full_filter, pcap_geterr(handle));
    }


    pcap_loop(handle, -1, got_packet, (u_char *) sniff);

    free_sniffer(sniff);
    pcap_close(handle);
}
