//
// Created by dtalexundeer on 6/1/24.
//

#ifndef TCP_SNIFFER_TEMPLATER_H
#define TCP_SNIFFER_TEMPLATER_H

#include<glib.h>

struct templater_argument {
    GRegex *name_regex;
    char *value;
};

extern struct templater_argument *templater_argument_new(char *argument, char *value);

struct templater {
    char *template_str;

    // array of templater arguments
    GArray *arguments;
};

extern struct templater *templater_new(char *templater_str);

extern void templater_add_argument(struct templater *templater, struct templater_argument *argument);

extern char *templater_render(struct templater *templater);

#endif //TCP_SNIFFER_TEMPLATER_H
