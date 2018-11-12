//ISA projekt
//Ksenia Bolshakova

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <csignal>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "ripngpacket.h"
pcap_t *handle; // Session handle  


int main(int argc, char *argv[]) {
    char* interface = NULL;
    char* ip_addr_next_hop = (char*) "::";
    char* netmask = (char*)"0";
    char* prefix = (char*) "::";
    char* metric = (char*) "1";
    char* router_tag = (char*) "0";

    int converted_next_hop;
    int converted_addr;
    struct in6_addr ipv6_addr;
    struct in6_addr ipv6_nexthop_addr;

    converted_next_hop = inet_pton(AF_INET6, ip_addr_next_hop, &ipv6_nexthop_addr);
    converted_addr = inet_pton(AF_INET6, prefix, &ipv6_addr);

    if (argc < 2) {
        fprintf(stderr, "Bad number of arguments.\n Please enter: ./myriprequest -h to see a help.\n");
        return -1;
    }
    int option;
    while((option = getopt(argc, argv, "i:h")) != -1) {
        switch(option) {
            case 'i':
                interface = optarg;
                break;
            case 'h':
                fprintf(stderr, "Please enter: ./myriprequest -i <interface>\n where <interface> is interface for request.\n");
                return 0;
            case '?':
                fprintf(stderr, "Bad argument.\n");
                return -1;
            default:
                exit(-1);
        }
    }

    if (interface == NULL) {
        fprintf(stderr, "Missing an interface.\n");
        exit(-1);
    }
    struct sockaddr_in6 dest_addr;
    struct sockaddr_in6 source_addr;
    int socket_of_client;

    //Prepare source address
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin6_family = AF_INET6;
    source_addr.sin6_port = htons(521);
    source_addr.sin6_addr = in6addr_any;

    //Prepare destionation address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons(521);
    inet_pton(AF_INET6, "ff02::9", &dest_addr.sin6_addr);
    //Creation of a socket
    socket_of_client = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    //Failed to create a socket
    if (socket_of_client < 0) {
        fprintf(stderr, "Could not create a socket.\n");
        exit(-1);
    }
    //Binding of a socket to the port
    if (bind(socket_of_client, (struct sockaddr *) &source_addr, sizeof(source_addr)) < 0) {
        perror("error of binding");
        exit(-1);
    }

    //Set of a socket
    if (setsockopt(socket_of_client, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface))){
        perror("error of setsockopt"); 
        return -1;
    }

    //Build RIPng packet
    RIPngPacket *ripngPacket = new RIPngPacket(ipv6_nexthop_addr, ipv6_addr, router_tag, netmask, metric, 1);
   
    //Send packet
    if (sendto(socket_of_client, ripngPacket->packet, ripngPacket->length, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0){
        perror("Error to send message");
        return -1;
    }
  
    return (0);
}