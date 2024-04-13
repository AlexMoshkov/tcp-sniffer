#include "include/config.h"
#include "include/sniffer.h"

int main() {
    char *filename = "../example.yaml";

    struct config *cfg;

    parse_config_from_yaml(filename, &cfg);

    struct sniffer *sniff;
    init_sniffer(cfg, &sniff);


    free_sniffer(sniff);
    free_config(cfg);
    return 0;
}
