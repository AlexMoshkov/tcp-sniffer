//
// Created by dtalexundeer on 6/1/24.
//

#include <glib.h>
#include <stdio.h>

#include "templater.h"

const char *TOKEN_OPEN = "{%";
const char *TOKEN_CLOSE = "%}";

char *prepare_argument(char *argument) {
    GString *result = g_string_new("");
    g_string_printf(result, "%s\\s*%s\\s*%s", TOKEN_OPEN, argument, TOKEN_CLOSE);
    return result->str;
}

struct templater_argument *templater_argument_new(char *argument, char *value) {
    struct templater_argument *arg = g_new(struct templater_argument, 1);
    arg->name_regex = g_regex_new(prepare_argument(argument), G_REGEX_OPTIMIZE, 0, NULL);
    if (arg->name_regex == NULL) {
        fprintf(stderr, "Couldn't create templater argument %s", argument);
        exit(1);
    }
    arg->value = value;
    return arg;
}

void templater_argument_free(struct templater_argument *arg) {
    g_regex_unref(arg->name_regex);
    g_free(arg);
}

struct templater *templater_new(char *template_str) {
    struct templater *templater = g_new(struct templater, 1);
    templater->template_str = template_str;
    templater->arguments = g_array_new(FALSE, FALSE, sizeof(struct templater_argument));
    return templater;
}

void templater_add_argument(struct templater *templater, struct templater_argument *arg) {
    templater->arguments = g_array_append_val(templater->arguments, *arg);
}

char *templater_render(struct templater *templater) {
    char *result = templater->template_str;

    for (size_t i = 0; i < templater->arguments->len; ++i) {
        struct templater_argument arg = g_array_index(templater->arguments, struct templater_argument, i);
        result = g_regex_replace(arg.name_regex, result, -1, 0, arg.value, 0, NULL);
    }

    return result;
}
