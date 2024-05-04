//
// Created by dtalexundeer on 3/10/24.
//
//
#include <sys/socket.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ethernet.h"
#include "sniffer.h"
#include "handlers/handlers.h"

const struct sniff_ethernet *ethernet;

void init_filter(pcap_t *handle, struct cfg_handler *handler, struct filter *filter);

void init_sniffer(pcap_t *handle, struct config *cfg, struct sniffer **sniff) {
    *sniff = (struct sniffer *) malloc(sizeof(struct sniffer));
    if (*sniff == NULL) {
        goto error;
    }

    (*sniff)->filters = malloc(cfg->handlers_count * sizeof(struct filter));
    if ((*sniff)->filters == NULL) {
        goto error;
    }

    (*sniff)->filters_count = cfg->handlers_count;
    for (int i = 0; i < (*sniff)->filters_count; ++i) {
        init_filter(handle, cfg->handlers[i], &(*sniff)->filters[i]);
    }
    return;
    error:
    perror("Couldn't init sniffer");
    exit(1);
}

void free_filter(struct filter *filter);

void free_sniffer(struct sniffer *sniff) {
    for (int i = 0; i < sniff->filters_count; ++i) {
        free_filter(&sniff->filters[i]);
    }
    free(sniff->filters);
    free(sniff);
}

void init_filter(pcap_t *handle, struct cfg_handler *handler, struct filter *filter) {
    filter->name = handler->name;
    filter->filter_str = handler->filter;

    init_handlers(handle, handler, filter);
}

void free_filter(struct filter *filter) {
    free_handlers(filter);
    pcap_freecode(&filter->fp);
}

void compile_filter(struct filter *filter, struct cfg_handler *handler, pcap_t *handle) {
    if (pcap_compile(handle, &filter->fp, filter->filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't compile filter %s: %s\n", filter->filter_str, pcap_geterr(handle));
        exit(1);
    }
}

//int start_capture(char *device, struct config *cfg) {
//    pcap_t *handle;
//    char *errbuf;
//
//    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
//    if (handle == NULL) {
//        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
//        exit(1);
//    }
//
//    if (pcap_datalink(handle) != DLT_EN10MB) {
//        fprintf(stderr, "Device %s doesn't provide, Ethernet headers - not supported", capture->interface);
//        exit(1);
//    }
//
//    struct sniffer *sniff;
//    init_sniffer(cfg, &sniff);
//
//}

//int init_filters(struct filter **filters) {
//
//}


//int sniff(const char *device, char *errbuf) {
//    pcap_t *handle;
//
//    struct pcap_pkthdr header;
//    const u_char *packet;
//
//    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
//    if (handle == NULL) {
//        sprintf(errbuf, "Couldn't open device %s: %s\n", device, errbuf);
//        return -1;
//    }
//
//    if (pcap_datalink(handle) != DLT_EN10MB) {
//        sprintf(errbuf, "Device %s doesn't provide Ethernet headers -not  supported\n", device);
//        return -1;
//    }
//
//    packet = pcap_next(handle, &header);
//
//    ethernet = (struct sniff_ethernet *) (packet);
//    printf("%s -> %s: %d\n", ethernet->ether_shost, ethernet->ether_dhost, ethernet->ether_type);
//
//    printf("%d\n", ethernet->ether_type);
//
//    return 0;
//}
