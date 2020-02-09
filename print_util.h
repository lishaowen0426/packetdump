//
// Created by lsw on 2020/02/05.
//

#ifndef PACKETDUMP_PRINT_UTIL_H
#define PACKETDUMP_PRINT_UTIL_H

#include "dissect.h"



extern void ts_print(disset_options*, const struct timeval*);
extern void set_function_pointers(disset_options*);

#endif //PACKETDUMP_PRINT_UTIL_H
