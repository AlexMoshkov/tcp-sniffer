#include <getopt.h>
#include <stdlib.h>
#include <signal.h>

#include "src/config.h"
#include "src/sniffer.h"
#include "src/capture.h"

char *help_message = "tcp-sniffer --config <yaml_file>  [ --interface <device_name> ]\n\n"
                     "Flags:\n"
                     "\t--config / -c <yaml_file>\t Path to configuration file in yaml format\n"
                     "\t--interface / -i <device_name>\t Set device for capturing (default is any)\n";

void print_help_message(FILE *stream) {
    fprintf(stream, "%s\n", help_message);
}


int main(int argc, char **argv) {
    signal(SIGINT, sigint_handler);

    // arguments
    char *config_path;
    char *interface = "any";

    int c;
    while (1) {
        static struct option long_options[] = {
                {"help",      no_argument,       0, 'h'},
                {"config",    required_argument, 0, 'c'},
                {"interface", required_argument, 0, 'i'},
                {0, 0,                           0, 0},
        };

        int option_index = 0;
        c = getopt_long(argc, argv, "hc:i:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                print_help_message(stdout);
                exit(0);
            case 'c':
                config_path = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            default:
                abort();
        }
    }

    if (config_path == NULL) {
        print_help_message(stderr);
        exit(1);
    }

    struct config *cfg;
    parse_config_from_yaml(config_path, &cfg);

    sniff_interface(interface, cfg);

    free_config(cfg);
    return 0;

}
