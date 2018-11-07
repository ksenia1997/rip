//ISA project 
//Ksenia Bolshakova
#include "ripngpacket.h"
using namespace std;

RIPngPacket::RIPngPacket(char next_hop[32], char prefix[32], char route_tag[2], char* prefix_len, char* metric) {
    int nextHopCheck = 0;
    if (strcmp(next_hop, "::") == 0) {
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
    memset(&packet[2], 0, 1); //Reverzed MBZ 3-4 bytes
    memset(&packet[3], 0, 1); 


    //Creation of RTE
    int counter = 0;
    for (int i = 0; i < 32; i += 2) {
        char number[3];
        number[0] = packet[i];
        number[1] = packet[i+1];
        number[2] = '\0';
        int number_int = stoi(number, NULL, 16); //convert number char  to int with base 16
        unsigned short short_number = abs((unsigned short)number_int); 
        packet[4+counter] = short_number;
        counter++;
    }

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
        int count = 0;
        for (int i = 0; i < 32; i += 2) {
            char number[3];
            number[0] = packet[i];
            number[1] = packet[i+1];
            number[2] = '\0';
            int number_int = stoi(number, NULL, 16); //convert number char to int with base 16
            unsigned short short_number = abs((unsigned short)number_int); 
            packet[24+count] = short_number; //address   (ripng header + rt entry len of ripng)
            count ++;
        }

        packet[44 - 1] = 0xff; //Metric field (ripng header + rt entry len of ripng + nh entry len of ripng)
    }


    return;
}