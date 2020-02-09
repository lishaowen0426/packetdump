//
// Created by lsw on 2020/02/05.
//


#include "dissect.h"
#include "ethertype.h"
#include "type.h"
#include "print_util.h"
#include <arpa/inet.h>

#define ETHERNET_HDRLEN 14
/*Extract big endian unsigned 6 bytes*/
#define EXTRACT_BE_U_6(p) (                          \
    (uint64_t)(                                      \
    ((uint64_t)(*((const uint8_t*)(p)+ 0)) << 40 ) | \
    ((uint64_t)(*((const uint8_t*)(p)+ 1)) << 32 ) | \
    ((uint64_t)(*((const uint8_t*)(p)+ 2)) << 24 ) | \
    ((uint64_t)(*((const uint8_t*)(p)+ 3)) << 16 ) | \
    ((uint64_t)(*((const uint8_t*)(p)+ 4)) << 8 ) | \
    ((uint64_t)(*((const uint8_t*)(p)+ 5)) << 0 )))



struct ethernet_header {
    mac_addr_t ether_dhost;       /*Etherent destination host*/
    mac_addr_t ether_shost;       /*Etherent sourc host*/
    pd_uint16_t   ether_type;         /*Ethertype defined in ethertype.h*/
};
typedef struct ethernet_header ethernet_header;


static const char hex[16] = {
        '0','1','2','3','4','5','6','7',
        '8','9','a','b','c','d','e','f'
};

static inline void macaddr_string(char* cp, uint64_t addr){

    uint8_t octet;
    for(int i = 5; i >=0; i--) {
        octet = (addr >> (i*8)) & 0xff;
        *cp++ = hex[(octet >> 4) & 0xf];
        *cp++ = hex[(octet >> 0) & 0xf];
        *cp++ = ':';
    }

    *cp = '\0';

}

void ethernet_print(disset_options* opt, const struct pcap_pkthdr* header,const u_char* packet){

    bpf_u_int32 caplen = header->caplen;

    if(caplen < ETHERNET_HDRLEN){
        PD_PRINT("Corrupted Ethernet frame\n");
        return;
    }

    bpf_u_int32 len = header->len;
    uint64_t dhost = EXTRACT_BE_U_6(packet);
    uint64_t shost = EXTRACT_BE_U_6(packet+MAC_ADDR_LEN);
    u_short ethertype = ntohs(*(uint16_t*)(packet+2*MAC_ADDR_LEN));

    /*First: print the time*/
    ts_print(opt,&header->ts);

    /*Second: print the mac address*/
    if(opt->show_mac_addr_flag){

        char dbuf[18], sbuf[18];
        macaddr_string(dbuf,dhost);
        macaddr_string(sbuf,shost);
        PD_PRINT("%s > %s ", sbuf,dbuf);
    }

    switch(ethertype) {
        case ETHERTYPE_IPV4:{
            ipv4_print(opt,packet+ETHERNET_HDRLEN,caplen - ETHERNET_HDRLEN,len - ETHERNET_HDRLEN);
            break;
        }
        default:{
            PD_PRINT("Unsupported Ethernet type\n");
            return;
        }
    }

    return;
}