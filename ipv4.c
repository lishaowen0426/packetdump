//
// Created by lsw on 2020/02/06.
//
#include "dissect.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "ipv4.h"


struct ip_header {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RES 0x8000
#define IP_DF  0x4000
#define IP_MF  0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_protocol;
    u_short ip_checksum;
    struct in_addr ip_src;
    struct in_addr ip_dest;
};

typedef struct ip_header ip_header;

#define IP_VERSION(ip) (((ip)->ip_vhl) >> 4)
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)

static void network_flag(disset_options* opt, ip_header* header, char* buf){
    //char buf[15];
    char* current = buf;
    sprintf(current, "Flags[");
    current += 6;

    u_short flags = ntohs(header -> ip_off);

    u_short df = (flags & IP_DF);
    u_short mf = (flags & IP_MF );

    if(df != 0){
        *current++ = 'D';
        *current++ = 'F';
    }

    if(mf != 0){
        *current++ = '+';
    }

    if(df == 0 && mf == 0){
        *current++ = '.';
    }

    *current++= ']';
    *current = '\0';

    //PD_PRINT("%s ", buf);



}


static void network_addr(disset_options* opt, ip_header* header){

    char dbuf[INET_ADDRSTRLEN];
    char sbuf[INET_ADDRSTRLEN];
    struct hostent* dhost;
    struct hostent* shost;

    inet_ntop(AF_INET,&header->ip_src,sbuf,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&header->ip_dest,dbuf,INET_ADDRSTRLEN);

    if(opt->show_hostname){
        shost = gethostbyaddr(&header->ip_src,sizeof(header->ip_src),AF_INET);
        dhost = gethostbyaddr(&header->ip_dest, sizeof(header->ip_dest),AF_INET);

        if(shost != NULL){
            PD_PRINT("%s > ", shost->h_name);
        }
        else{
            PD_PRINT("%s >", sbuf);
        }

        if(dhost != NULL){
            PD_PRINT("%s: ", dhost->h_name);
        } else{
            PD_PRINT("%s: ", dbuf);
        }
    }else{
        PD_PRINT("%s > %s: ", sbuf, dbuf);
    }


}

static void network_verbose(disset_options* opt, ip_header* header){

    char buf[1024];
    char flags[15];

    network_flag(opt,header, flags);

    sprintf(buf, "( tos 0x%x, ttl %d, id %d, offset %d, %s, protocol %d, length %d )",
            header->ip_tos, header->ip_ttl, ntohs(header->ip_id), ntohs(header->ip_off)&IP_OFFMASK, flags,header->ip_protocol
            , ntohs(header->ip_len));

    PD_PRINT("%s ", buf);

}

void ipv4_print(disset_options* opt, const u_char* pkt, bpf_u_int32 caplen, bpf_u_int32 len){
    ip_header* ip;
    ip = (ip_header*) pkt;

    u_int ip_size = IP_HL(ip) * 4;

    if(ip_size < 20){
        fprintf(stderr, "Corrupted IP datagram: header is %d bytes\n", ip_size);
        return;
    }

    if(opt->show_ip_verbose) {
        network_verbose(opt, ip);
    }

    network_addr(opt,ip);

    if(ip_size == ip->ip_len)
        return;

    pkt += ip_size;

    switch(ip->ip_protocol){
        case IPV4_TCP:{
            tcp_print(opt,pkt,caplen-ip_size, len - ip_size);
            break;
        }
        case IPV4_UDP:{
            break;
        }
        case IPV4_ICMP:{
            break;
        }
        default:{
            fprintf(stderr, "Unsupported IPv4 protocol: %d\n", ip->ip_protocol);
            break;
        }
    }

    return;



}
