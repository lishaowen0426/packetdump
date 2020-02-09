//
// Created by lsw on 2020/02/05.
//

#ifndef PACKETDUMP_DISSECT_H
#define PACKETDUMP_DISSECT_H

#include "type.h"
#include <pcap.h>

#define TIME_FORMAT     1
#define SHOW_MAC_ADDR   1
#define SHOW_HOSTNAME   1
#define SHOW_IP_VERBOSE 1
#define SHOW_TCP_FLAGS  1



struct disset_options {
    link_layer_type_t link_layer_type;

    u_int8_t time_format_flag;
    u_int8_t show_mac_addr_flag;
    u_int8_t show_hostname;
    u_int8_t show_ip_verbose;
    u_int8_t show_tcp_flags;
    /*functioin pointers*/
    int (* pd_printf) (struct disset_options*, const char* fmt, ...);

};
typedef struct disset_options disset_options;





extern void ethernet_print(disset_options* , const struct pcap_pkthdr* ,const u_char*);
extern void ipv4_print(disset_options*, const u_char*, bpf_u_int32 caplen, bpf_u_int32 len);
extern void tcp_print(disset_options*, const u_char*, bpf_u_int32 caplen, bpf_u_int32 len);

#define PD_PRINT(...) (opt->pd_printf)(opt,__VA_ARGS__);


#endif //PACKETDUMP_DISSECT_H
