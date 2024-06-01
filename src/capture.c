//
// Created by dtalexundeer on 4/10/24.
//

#include <stdlib.h>
#include <string.h>

#include "capture.h"
#include "sniffer.h"
#include "handlers/handlers.h"

static volatile int sigint = 0;

void sigint_handler(int sig) {
    sigint = 1;
}

const char filter_delimiter[] = " || ";

void process_packets_by_filters(struct sniffer *sniff, const struct pcap_pkthdr *header, const u_char *packet) {
    for (size_t i = 0; i < sniff->filters_count; ++i) {
        if (pcap_offline_filter(&sniff->filters[i].fp, header, packet)) {
            process_packages(sniff->filters[i].handlers, header, packet);
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct sniffer *sniff = (struct sniffer *) args;

    if (sigint) {
        pcap_breakloop(sniff->handle);
    }


    static int count = 1;

    printf("\nPacket number: %d\n", count++);

    process_packets_by_filters(sniff, header, packet);
}

void sniff_interface(char *device, struct config *cfg, int count) {
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
        compile_filter(&sniff->filters[i], handle);
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

    pcap_loop(handle, count, got_packet, (u_char *) sniff);

    free_sniffer(sniff);
    pcap_close(handle);
}
