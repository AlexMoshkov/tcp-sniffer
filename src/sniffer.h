//
// Created by dtalexundeer on 3/18/24.
//

#ifndef PROJECT_SNIFFER_H
#define PROJECT_SNIFFER_H

#include <pcap.h>

#include "config.h"
#include "handlers/handlers.h"

struct filter {
    char *name;
    char *filter_str;

    struct bpf_program fp;

    struct handlers *handlers;
};

extern void compile_filter(struct filter *filter, pcap_t *handle);

struct sniffer {
    pcap_t *handle;
    struct filter *filters;
    unsigned filters_count;

    struct bpf_program full_fp;
};

extern void init_sniffer(pcap_t *handle, struct config *cfg, struct sniffer **sniff);

extern void free_sniffer(struct sniffer *sniff);

#endif //PROJECT_SNIFFER_H

