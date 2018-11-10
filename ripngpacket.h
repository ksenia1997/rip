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
        RIPngPacket(char next_hop[INET6_ADDRSTRLEN], char prefix[INET6_ADDRSTRLEN], char route_tag[2], char* prefix_len, char* metric);

};