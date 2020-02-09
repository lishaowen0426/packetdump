//
// Created by lsw on 2020/02/05.
//

#include "print_util.h"
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

#define pd_istimevalset(ref)  ((ref)->tv_sec || (ref)->tv_usec)

static void ts_date_print(disset_options* opt, const struct timeval* ts){
    time_t time = ts->tv_sec;
    struct tm* tm;

    tm = localtime(&time);
    if(tm == NULL){
        PD_PRINT("Error converting time to data");
        return;
    }

    char timestr[32];

    strftime(timestr, sizeof(timestr), "%H:%M:%S",tm);
    PD_PRINT("%s", timestr);

    PD_PRINT(".%06u",(unsigned)ts->tv_usec);
}

static void ts_unix_print(disset_options* opt, const struct timeval* ts){

    PD_PRINT("%u.%06u", (unsigned)ts->tv_sec, (unsigned)ts->tv_usec);
}

void ts_print(disset_options* opt, const struct timeval* ts ){

    static struct timeval ts_ref;


    switch(opt->time_format_flag){
        case 0:
            ts_unix_print(opt,ts);
            break;
        case 1:
            ts_date_print(opt,ts);
            break;
        default:
            break;
    }


    if(!pd_istimevalset(&ts_ref)) ts_ref = *ts;

    PD_PRINT(" (%u.%09u): ",(unsigned)(ts->tv_sec-ts_ref.tv_sec), (unsigned)(ts->tv_usec-ts_ref.tv_usec));

    ts_ref = *ts;
}


static int pd_printf(disset_options* opt, const char* fmt, ...){

    va_list  args;
    int ret;

    va_start(args,fmt);
    ret = vfprintf(stdout, fmt, args);
    va_end(args);

    if(ret < 0){
        fprintf(stderr, "Couldn't output\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}


void set_function_pointers(disset_options* opt){

    opt->pd_printf = pd_printf;

}
