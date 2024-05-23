//
// Created by dtalexundeer on 4/28/24.
//

#include <malloc.h>
#include <stdlib.h>
#include "handlers.h"

void init_handlers(pcap_t *handle, struct cfg_handler *cfg_handler, struct handlers **handlers) {
    *handlers = (struct handlers *) malloc(sizeof(struct handlers));
    if (*handlers == NULL) {
        perror("Couldn't init handlers");
        exit(1);
    }
    // init new handlers
    if (cfg_handler->save_capture != NULL) {
        init_save_pcap_handler(&(*handlers)->save_pcap_handler, handle, cfg_handler->save_capture->filepath);
    }

}

void free_handlers(struct handlers *handlers) {
    // free new handlers
    if (handlers->save_pcap_handler != NULL) {
        free_save_pcap_handler(handlers->save_pcap_handler);
    }
    free(handlers);
}

void process_packages(struct handlers *handlers, const struct pcap_pkthdr *header, const u_char *packet) {
    if (handlers->save_pcap_handler != NULL) {
        handlers->save_pcap_handler->process(handlers->save_pcap_handler, header, packet);
    }
}


