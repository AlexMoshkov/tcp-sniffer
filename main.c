#include "include/config.h"
#include "include/sniffer.h"
#include "include/capture.h"

int main() {
    char *filename = "../example.yaml";
    char *device = "wlp0s20f3";
    // TODO: parse from cli

    struct config *cfg;

    parse_config_from_yaml(filename, &cfg);

    start(device, cfg);

    free_config(cfg);
    return 0;

}
