//
// Created by lsw on 2020/02/05.
//

#ifndef PACKETDUMP_TYPE_H
#define PACKETDUMP_TYPE_H

typedef unsigned char pd_uint8_t[1];
typedef unsigned char pd_uint16_t[2];
typedef unsigned char pd_uint24_t[3];
typedef unsigned char pd_uint32_t[4];
typedef unsigned char pd_uint40_t[5];
typedef unsigned char pd_uint48_t[6];
typedef unsigned char pd_uint56_t[7];
typedef unsigned char pd_uint64_t[8];

#define MAC_ADDR_LEN 6
typedef unsigned char mac_addr_t[MAC_ADDR_LEN];
typedef unsigned char byte;

typedef int link_layer_type_t;



#endif //PACKETDUMP_TYPE_H
