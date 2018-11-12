//ISA project 
//Ksenia Bolshakova
#include "ripngpacket.h"
using namespace std;

RIPngPacket::RIPngPacket( struct in6_addr next_hop,  struct in6_addr prefix, char route_tag[2], char* prefix_len, char* metric, int purpose) {
    int nextHopCheck = 0;
    char nexthop [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &next_hop, nexthop, INET6_ADDRSTRLEN);

    nextHopCheck = 1;
    this->length = 44;
    this->packet = (char*) malloc(44); //allocation of memory (header length of ripng + rt entry of ripng + nh entry of ripng)
    memset(this->packet, '\0', 44); //sets 44 bytes of the block memory to the '\0'
    

    //Create ripng header
    memset(&packet[0], purpose, 1); //Command 
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