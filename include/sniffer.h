//
// Created by dtalexundeer on 3/18/24.
//

#ifndef PROJECT_SNIFFER_H
#define PROJECT_SNIFFER_H

#include <pcap.h>

#include "config.h"
#include "../src/handlers/save_pcap.h"

struct filter {
    char *name;
    char *filter_str;

    struct bpf_program fp;

    // pointers to handlers structs
    // if is not null => handling
    struct save_pcap_handler *save_pcap_handler;
};

extern void compile_filter(struct filter *filter, struct cfg_handler *handler, pcap_t *handle);


struct sniffer {
    struct filter *filters;
    unsigned filters_count;

    struct bpf_program full_fp;
};

extern void init_sniffer(pcap_t *handle, struct config *cfg, struct sniffer **sniff);

extern void free_sniffer(struct sniffer *sniff);

#endif //PROJECT_SNIFFER_H

