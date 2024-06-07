//
// Created by dtalexundeer on 3/28/24.
//

#ifndef PROJECT_CONFIG_H
#define PROJECT_CONFIG_H

struct save_capture_handler {
    char *filepath;
};

struct save_in_template_handler {
    char *filepath;
    char *template_str;
};

struct cfg_handler {
    char *name;
    char *filter;

    // handlers
    struct save_capture_handler *save_capture;
    struct save_in_template_handler *save_in_template;
};

struct config {
    struct cfg_handler **handlers;
    unsigned handlers_count;
};

extern void parse_config_from_yaml(char *filepath, struct config **cfg_out);

extern void free_config(struct config *cfg);

#endif //PROJECT_CONFIG_H

