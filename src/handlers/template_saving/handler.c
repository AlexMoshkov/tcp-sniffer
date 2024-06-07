//
// Created by dtalexundeer on 6/1/24.
//

#include <malloc.h>
#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "handler.h"

void fill_arguments_from_ether(struct templater *templater, struct ether_header *ether_header) {
    templater_add_argument(templater, templater_argument_new("ether_dhost", ether_ntoa(
            (struct ether_addr *) ether_header->ether_dhost)));
    templater_add_argument(templater, templater_argument_new("ether_shost", ether_ntoa(
            (struct ether_addr *) ether_header->ether_shost)));
}

void fill_arguments_from_ip(struct templater *templater, struct ip *ip) {
    templater_add_argument(templater, templater_argument_new("ip_src", inet_ntoa(ip->ip_src)));
    templater_add_argument(templater, templater_argument_new("ip_dst", inet_ntoa(ip->ip_dst)));
}

void fill_arguments_from_tcp(struct templater *templater, struct tcphdr *tcp_header) {
    char *th_sport = g_strdup_printf("%i", ntohs(tcp_header->th_sport));
    templater_add_argument(templater, templater_argument_new("tcp_sport", th_sport));
    char *th_dport = g_strdup_printf("%i", ntohs(tcp_header->th_dport));
    templater_add_argument(templater, templater_argument_new("tcp_dport", th_dport));
}

void fill_arguments_from_udp(struct templater *templater, struct udphdr *udp_header) {
    char *uh_sport = g_strdup_printf("%i", ntohs(udp_header->uh_sport));
    templater_add_argument(templater, templater_argument_new("udp_sport", uh_sport));
    char *uh_dport = g_strdup_printf("%i", ntohs(udp_header->uh_dport));
    templater_add_argument(templater, templater_argument_new("udp_dport", uh_dport));
}

void fill_templater_arguments_from_package(struct templater *templater, const u_char *packet) {
    struct ether_header *ether_header = (struct ether_header *) (packet);
    fill_arguments_from_ether(templater, ether_header);

    size_t shift = ETHER_HDR_LEN;
    int contains_tcp = 0;
    int contains_udp = 0;

    if (ntohs(ether_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *) (packet + shift);
        fill_arguments_from_ip(templater, ip);
        shift += ip->ip_hl * 4;
        if (ip->ip_p == IPPROTO_TCP) {
            contains_tcp = 1;
        }
        if (ip->ip_p == IPPROTO_UDP) {
            contains_udp = 1;
        }
    }
    if (contains_tcp) {
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + shift);
        fill_arguments_from_tcp(templater, tcp_header);
    }
    if (contains_udp) {
        struct udphdr *udp_header = (struct udphdr *) (packet + shift);
        fill_arguments_from_udp(templater, udp_header);
    }
}

void
process_save_in_template(struct save_in_template *handler, const struct pcap_pkthdr *header, const u_char *packet) {
    fill_templater_arguments_from_package(handler->templater, packet);

    char *result = templater_render(handler->templater);
    fprintf(handler->fptr, "%s\n", result);
}


void init_save_in_template_handler(struct save_in_template **handler, char *filepath, char *template_str) {
    *handler = (struct save_in_template *) malloc(sizeof(struct save_in_template));
    if (*handler == NULL) {
        goto error;
    }

    (*handler)->fptr = fopen(filepath, "w");
    if ((*handler)->fptr == NULL) {
        goto error;
    }
    (*handler)->templater = templater_new(template_str);

    (*handler)->process = &process_save_in_template;
    return;

error:
    perror("Couldn't init save_in_template handler");
    exit(1);
}

void free_save_in_template_handler(struct save_in_template *handler) {
    fclose(handler->fptr);
    free(handler);
}
