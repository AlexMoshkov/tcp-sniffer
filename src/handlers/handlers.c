//
// Created by dtalexundeer on 4/28/24.
//

#include <malloc.h>
#include "handlers.h"

void init_by_cfg_handler(pcap_t *handle, struct cfg_handler *handler, struct filter *filter) {
    if (handler->save_capture != NULL) {
        init_save_pcap_handler(&filter->save_pcap_handler, handle, handler->save_capture->filepath);
    }
}

void init_handlers(pcap_t *handle, struct cfg_handler *handler, struct filter *filter) {
    if (handler->save_capture != NULL) {
        init_by_cfg_handler(handle, handler, filter);
    }
}

void free_handlers(struct filter *filter) {
    if (filter->save_pcap_handler != NULL) {
        free_save_pcap_handler(filter->save_pcap_handler);
    }
}

void process_handlers(struct filter *filter, const struct pcap_pkthdr *header, const u_char *packet) {
    if (filter->save_pcap_handler != NULL) {
        filter->save_pcap_handler->process(filter->save_pcap_handler, header, packet);
    }
}


