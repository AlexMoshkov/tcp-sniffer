//
// Created by dtalexundeer on 4/10/24.
//

#ifndef PROJECT_CAPTURE_H
#define PROJECT_CAPTURE_H

#include "config.h"

extern void sigint_handler(int sig);

extern void sniff_interface(char *device, struct config *cfg, int count);

#endif //PROJECT_CAPTURE_H
