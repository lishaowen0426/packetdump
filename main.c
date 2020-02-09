#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "dissect.h"
#include "print_util.h"

#define MAXBYTES2CAPTURE 65535

static void packet_handler(u_char* pcap_userdata, const struct pcap_pkthdr* header, const u_char* packet){

    disset_options* opt = (disset_options*) pcap_userdata;

    switch(opt->link_layer_type){
        case DLT_EN10MB:
            ethernet_print(opt,header,packet);
            break;
        default:
        {
            fprintf(stderr,"Couldn't recognize the link layer header type:%d\n", opt->link_layer_type);
            exit(EXIT_FAILURE);
        }


    }



};


/*
 * concatenate the BPF filter expression
 */
static char* concat_argv(char** argv){

    char** p;
    size_t len = 0;
    char* buf;
    char* src, *dst;

    p = argv;
    if(*p == NULL) return NULL;

    while(*p) len += strlen(*p++) + 1;

    buf = (char*) malloc(len);
    if(buf == NULL) {
        fprintf(stderr,"concat_argv:malloc:%d",__LINE__);
        exit(EXIT_FAILURE);
    }

    p = argv;
    dst = buf;

    while((src = *p++) != NULL){
        while( (*dst++ = *src++) != '\0');

        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    return buf;
};

static void init_opt(disset_options* opt){

    opt->time_format_flag = TIME_FORMAT;
    opt->show_mac_addr_flag = SHOW_MAC_ADDR;
    opt->show_hostname = SHOW_HOSTNAME;
    opt->show_ip_verbose = SHOW_IP_VERBOSE;
    opt->show_tcp_flags = SHOW_TCP_FLAGS;
}

int main(int argc, char** argv ) {



    char* dev = NULL;                /*capture device name*/
    char* filter_exp = NULL;         /*BPF filter expression*/
    char errbuf[PCAP_ERRBUF_SIZE];   /*error buffer*/
    pcap_t* handle;                  /*packet capture handle*/
    bpf_u_int32 mask;                /*subnet mask*/
    bpf_u_int32 net;                 /*ip*/
    struct bpf_program fp;           /*compiled filter program*/
    int packets_cnt = 0;             /*number of packets to capture*/
    //u_char* pcap_userdata;           /*user data passed to the callback*/
    disset_options Opt;
    disset_options* opt = &Opt;

    memset(opt,0,sizeof(*opt));

    set_function_pointers(opt);
    init_opt(opt);



    PD_PRINT("packetdump:\n");

    if(argc >= 3 && strcmp(argv[1],"-d") == 0){
        dev = argv[2];         /*use option d to specify device name*/
        if(argc > 3) filter_exp = concat_argv(argv + 3);
    }else if (argc > 1){
        filter_exp = concat_argv(argv + 1);
    }

    if( dev == NULL){
        /*find a capture device if not specified on command-line*/
        dev = pcap_lookupdev(errbuf);
        if( dev == NULL ){
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == PCAP_ERROR){
        fprintf(stderr, "Couldn't get net and mask for device: %s, %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, MAXBYTES2CAPTURE,1, 1000, errbuf);
    if( handle == NULL ){
        fprintf(stderr, "Couldn't open device: %s, %s\n",dev, errbuf);
        exit(EXIT_FAILURE);
    }

    opt->link_layer_type = pcap_datalink(handle);

    /*
    if(pcap_datalink(handle) != DLT_EN10MB ){
        fprintf(stderr, "Device: %s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    */

    if(filter_exp != NULL){
        if(pcap_compile(handle,&fp,filter_exp,1,mask) == PCAP_ERROR){
            fprintf(stderr,"Couldn't compile the filter program: %s, %s\n",filter_exp,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        if(pcap_setfilter(handle,&fp) == PCAP_ERROR){
            fprintf(stderr,"Couldn't set the filter program: %s, %s\n", filter_exp,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

    }

    int status;

    do{
        status = pcap_loop(handle, packets_cnt, packet_handler, (u_char*)opt);

        if(status == PCAP_ERROR_BREAK){
            /*We are interrupted*/
            putchar('\n');
            fflush(stdout);
        }
        else if (status == PCAP_ERROR){
            fprintf(stderr, "pcap_loop error: %s\n",pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }while(1);

    free(filter_exp);
    pcap_close(handle);
    pcap_freecode(&fp);

    return 0;
}