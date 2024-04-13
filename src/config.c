//
// Created by dtalexundeer on 3/28/24.
//

#include <cyaml/cyaml.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../include/config.h"

static const cyaml_schema_field_t save_capture_fields_schema[] = {
        CYAML_FIELD_STRING_PTR("filepath", CYAML_FLAG_POINTER, struct save_capture_func, filepath, 0, CYAML_UNLIMITED),
        CYAML_FIELD_END
};

static const cyaml_schema_field_t handler_fields_schema[] = {
        CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct cfg_handler, name, 0, CYAML_UNLIMITED),
        CYAML_FIELD_STRING_PTR("filter", CYAML_FLAG_POINTER | CYAML_FLAG_DEFAULT, struct cfg_handler, filter, 0,
                               CYAML_UNLIMITED),

        CYAML_FIELD_MAPPING_PTR("save_capture", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct cfg_handler,
                                save_capture,
                                save_capture_fields_schema),
        CYAML_FIELD_END
};

static const cyaml_schema_value_t handlers_entry_schema = {
        CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct cfg_handler, handler_fields_schema),
};


static const cyaml_schema_field_t config_fields_schema[] = {
        CYAML_FIELD_SEQUENCE("handlers", CYAML_FLAG_POINTER, struct config, handlers, &handlers_entry_schema, 0,
                             CYAML_UNLIMITED),
        CYAML_FIELD_END
};

static const cyaml_schema_value_t config_entry_schema = {
        CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct config, config_fields_schema)
};


static const cyaml_config_t yaml_config = {
        .log_fn = cyaml_log,
        .mem_fn = cyaml_mem,
        .log_level = CYAML_LOG_WARNING,
};


void parse_config_from_yaml(char *filepath, struct config **cfg_out) {
    cyaml_err_t err = cyaml_load_file(filepath, &yaml_config, &config_entry_schema, (cyaml_data_t **) cfg_out, NULL);
    if (err != CYAML_OK) {
        fprintf(stderr, "error while parse config: %s\n", cyaml_strerror(err));
        exit(1);
    }
}

void free_config(struct config *cfg) {
    cyaml_err_t err = cyaml_free(&yaml_config, &config_entry_schema, cfg, 0);
    if (err != CYAML_OK) {
        fprintf(stderr, "error while free config: %s\n", cyaml_strerror(err));
        exit(1);
    }
}