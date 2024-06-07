//
// Created by dtalexundeer on 6/1/24.
//

#ifndef TCP_SNIFFER_HANDLER_H
#define TCP_SNIFFER_HANDLER_H

#include <pcap.h>
#include <stdio.h>
#include "templater.h"

struct save_in_template {
    FILE *fptr;
    struct templater *templater;

    void (*process)(struct save_in_template *handler, const struct pcap_pkthdr *header, const u_char *packet);
};

extern void init_save_in_template_handler(struct save_in_template **handler, char *filepath, char *template_str);

extern void free_save_in_template_handler(struct save_in_template *handler);

#endif //TCP_SNIFFER_HANDLER_H
