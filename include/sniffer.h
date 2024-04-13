//
// Created by dtalexundeer on 3/18/24.
//

#ifndef PROJECT_SNIFFER_H
#define PROJECT_SNIFFER_H

#include <pcap.h>

#include "config.h"

struct filter {
    char *name;
    char *filter_str;

    struct bpf_program *fp;

    // TODO: save handler in some way
};

extern void compile_filter(struct filter *filter, pcap_t *handle);


struct sniffer {
    struct filter *filters;
    unsigned filters_count;

    struct bpf_program *full_fp;
};

extern void init_sniffer(struct config *cfg, struct sniffer **sniff);

extern void free_sniffer(struct sniffer *sniff);

extern void compile_full_filter(struct sniffer *sniff);

#endif //PROJECT_SNIFFER_H

