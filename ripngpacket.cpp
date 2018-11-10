//ISA project 
//Ksenia Bolshakova
#include "ripngpacket.h"
using namespace std;

RIPngPacket::RIPngPacket(unsigned char next_hop[sizeof(struct in6_addr)], unsigned char prefix[sizeof(struct in6_addr)], char route_tag[2], char* prefix_len, char* metric) {
    int nextHopCheck = 0;
    unsigned char next_hop_implicitly[3] = "\0";
    if (next_hop[0] == '\0') {
        this->length = 24;
        this->packet = (char*)malloc(4+20); //allocation of memory ripng header + ripng rt entry length
        memset(this->packet, '\0', 24); //sets 24 bytes of the block memory to the '\0'
    }
    else{
        nextHopCheck = 1;
        this->length = 44;
        this->packet = (char*) malloc(44); //allocation of memory (header length of ripng + rt entry of ripng + nh entry of ripng)
        memset(this->packet, '\0', 44); //sets 44 bytes of the block memory to the '\0'
    }

    //Create ripng header
    memset(&packet[0], 2 , 1); //Command 
    memset(&packet[1], 1, 1); //Version
    memset(&packet[2], 0, 1); //Must be 0
    memset(&packet[3], 0, 1); //Must be 0


    //Creation of Route Table Entry
    //IPv6
    memcpy(&packet[4], &prefix, sizeof(struct in6_addr));

    //Route Tag
    short routeTag = (short) atoi(route_tag);
    memcpy(&packet[20], &routeTag, 2);

    //Prefix length
    short prefixLen = (short) atoi(prefix_len);
    memcpy(&packet[22], &prefixLen, 1);

    //Metric
    short metricShort = (short) atoi(metric);
    memcpy(&packet[23], &metricShort, 1);

    //Next hop
    if (nextHopCheck == 1) {
        memcpy(&packet[24], &next_hop, sizeof(struct in6_addr));

        packet[44 - 1] = 0xff; //Metric field (ripng header + rt entry len of ripng + nh entry len of ripng)
    }

    return;
}