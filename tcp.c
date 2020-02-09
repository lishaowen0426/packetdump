//
// Created by lsw on 2020/02/07.
//

#include "tcp.h"
#include <arpa/inet.h>
#include "dissect.h"

struct tcp_header{
    u_short sport;
    u_short dport;
    uint32_t  seq;
    uint32_t   ack;
    u_char offset;
#define TCP_DATAOFFSET(tcp)  ((tcp->offset & 0xf0) >> 4)
    u_char flags;
#define  FIN 0x01
#define SYN 0x02
#define  RST 0x04
#define  PSH 0x08
#define ACK 0x10
#define  URG 0x20
#define  ECE 0x40
#define  CWR 0x80
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;

};
typedef struct tcp_header tcp_header;

static void tcp_flags(disset_options* opt, tcp_header* header){

    char buf[512];

    char* current = buf;

    sprintf(current, "Flags [ ");
    current+= 8;

    u_char flags = header ->flags;

    if(flags & CWR){
        sprintf(current, "CWR. ");
        current += 5;
    }

    if(flags & ECE){
        sprintf(current, "ECE. ");
        current += 5;
    }

    if(flags & URG){
        sprintf(current, "URG. ");
        current += 5;
    }

    if(flags&ACK){
        sprintf(current, "ACK. ");
        current += 5;
    }

    if(flags& PSH){
        sprintf(current, "PSH. ");
        current += 5;
    }

    if(flags&RST){
        sprintf(current, "RST. ");
        current +=5;
    }

    if(flags& SYN){
        sprintf(current, "SYN. ");
        current += 5;
    }

    if(flags& FIN){
        sprintf(current, "FIN. ");
        current += 5;
    }

    sprintf(current,"]");

    PD_PRINT("%s", buf);
}

void tcp_print(disset_options* opt, const u_char* pkt, bpf_u_int32 caplen, bpf_u_int32 len){

    tcp_header* tcp = (tcp_header*)pkt;

    PD_PRINT("%d > %d ", ntohs(tcp->sport), ntohs(tcp->dport));

    PD_PRINT("seq %lu ", (uint32_t)ntohl(tcp->seq));

    PD_PRINT("ack %lu ", (uint32_t)ntohl(tcp->ack));

    tcp_flags(opt,tcp);

    PD_PRINT("\n");

}