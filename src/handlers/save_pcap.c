//
// Created by dtalexundeer on 4/28/24.
//

#include <malloc.h>
#include <stdlib.h>
#include "save_pcap.h"

void process(struct save_pcap_handler *handler, const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_dump((u_char *) handler->pcap_dump, header, packet);
}

void init_save_pcap_handler(struct save_pcap_handler **handler, pcap_t *handle, char *filepath) {
    *handler = (struct save_pcap_handler *) malloc(sizeof(struct save_pcap_handler));
    if (*handler == NULL) {
        perror("Couldn't init save pcap handler");
        exit(1);
    }
    (*handler)->pcap_dump = pcap_dump_open(handle, filepath);
    if ((*handler)->pcap_dump == NULL) {
        fprintf(stderr, "Couldn't open dump file: %s", pcap_geterr(handle));
        exit(1);
    }

    (*handler)->process = &process;
}

void free_save_pcap_handler(struct save_pcap_handler *handler) {
    pcap_dump_close(handler->pcap_dump);
}
