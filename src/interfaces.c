//
// Created by dtalexundeer on 3/18/24.
//

#include <pcap/pcap.h>


int get_interfaces_names(char *ifs[], size_t size, char *err) {
    pcap_if_t *interfaces;

    if (pcap_findalldevs(&interfaces, err) == -1) {
        printf("error while get all interfaces: %s", err);
        return -1;
    }
    size_t i = 0;
    for (pcap_if_t *temp = interfaces; temp; temp = temp->next) {
        ifs[i++] = temp->name;
    }

    return 0;
}