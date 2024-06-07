//
// Created by dtalexundeer on 4/16/24.
//

#ifndef TCP_SNIFFER_HANDLERS_H
#define TCP_SNIFFER_HANDLERS_H

#include "../sniffer.h"
#include "../config.h"
#include "save_pcap.h"
#include "template_saving/handler.h"

struct handlers {
    struct save_pcap_handler *save_pcap_handler;
    struct save_in_template *save_in_template_handler;
};

extern void init_handlers(pcap_t *handle, struct cfg_handler *cfg_handler, struct handlers **handlers);

extern void free_handlers(struct handlers *handlers);

extern void process_packages(struct handlers *handlers, const struct pcap_pkthdr *header, const u_char *packet);

#endif //TCP_SNIFFER_HANDLERS_H
