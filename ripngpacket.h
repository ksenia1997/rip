//ISA project
//Ksenia Bolshakova
#pragma once
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class RIPngPacket {
    public:
        int length;
        char *packet;
        RIPngPacket( struct in6_addr next_hop,  struct in6_addr prefix, char route_tag[2], char* prefix_len, char* metric);

};