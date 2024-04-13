//
// Created by dtalexundeer on 4/10/24.
//

#include "../include/capture.h"

void start(char *device, struct config *cfg) {
    char *errbuf = NULL;

    pcap_t *handle;
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(1);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide, Ethernet headers - not supported", device);
        exit(1);
    }

    struct sniffer *sniff;
    init_sniffer(cfg, &sniff);

    for (int i = 0; i < sniff->filters_count; ++i) {
        compile_filter(&sniff->filters[i], handle);
    }

    free_sniffer(sniff);
}