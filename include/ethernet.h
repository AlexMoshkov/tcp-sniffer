//
// Created by dtalexundeer on 3/20/24.
//

#ifndef PROJECT_ETHERNET_H
#define PROJECT_ETHERNET_H

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

#endif //PROJECT_ETHERNET_H
