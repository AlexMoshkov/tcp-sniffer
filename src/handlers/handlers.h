//
// Created by dtalexundeer on 4/16/24.
//

#ifndef TCP_SNIFFER_HANDLERS_H
#define TCP_SNIFFER_HANDLERS_H

#include "../sniffer.h"
#include "../config.h"
#include "save_pcap.h"

extern void init_handlers(pcap_t *handle, struct cfg_handler *handler, struct filter *filter);

extern void free_handlers(struct filter *filter);

extern void process_handlers(struct filter *filter, const struct pcap_pkthdr *header, const u_char *packet);

#endif //TCP_SNIFFER_HANDLERS_H
