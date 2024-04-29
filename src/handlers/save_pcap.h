//
// Created by dtalexundeer on 4/28/24.
//

#ifndef TCP_SNIFFER_SAVE_PCAP_H
#define TCP_SNIFFER_SAVE_PCAP_H

#include <pcap/pcap.h>

struct save_pcap_handler {
    pcap_dumper_t *pcap_dump;

    void (*process)(struct save_pcap_handler *handler, const struct pcap_pkthdr *header, const u_char *packet);
};

extern void init_save_pcap_handler(struct save_pcap_handler **handler, pcap_t *handle, char *filepath);

extern void free_save_pcap_handler(struct save_pcap_handler *handler);

#endif //TCP_SNIFFER_SAVE_PCAP_H
