//ISA project
//Ksenia Bolshakova
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "ripngpacket.h"
    
int main(int argc, char* argv[]){
    char* interface;
    char* ip_addr;
    char* ip_addr_next_hop = (char*) "::";
    char* netmask;
    char* prefix;
    char* metric = (char*) "1";
    char* router_tag = (char*) "0";
    unsigned char buf[sizeof(struct in6_addr)];
    unsigned char buf_next_hop[sizeof(struct in6_addr)];
    char ip6_addr[INET6_ADDRSTRLEN];
    char ip6_next_hop[INET6_ADDRSTRLEN];
    int converted_next_hop;
    int converted_addr;
    struct in_addr addr;
    int option;
    if (argc < 3) {
        fprintf(stderr, "Not all arguments.\n");
        return -1;
    }
    while((option = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
        switch(option) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                ip_addr = strtok(optarg, "/");
                prefix = strtok(NULL, "/");
                netmask = prefix; 
                converted_addr = inet_pton(AF_INET6, ip_addr, buf);
                if (converted_addr <= 0) {
                    if (converted_addr == 0) {
                        fprintf(stderr, "IPv6 is not in presentation format.\n");
                    }
                    else{
                        perror("inet_pton");
                    }
                    exit(-1);
                }
                if (inet_ntop(AF_INET6, buf, ip6_addr, INET6_ADDRSTRLEN) == NULL){
                    perror("inet_ntop");
                    exit(-1);
                }
                if (!((atoi(netmask) >= 16 ) && (atoi(netmask) <= 128))) {
                    fprintf(stderr, "Bad length of the prefix.\n");
                    exit(-1);
                }
                break;
            case 'n':
                ip_addr_next_hop = optarg;
                converted_next_hop = inet_pton(AF_INET6, ip_addr_next_hop, buf_next_hop);
                if (converted_next_hop <= 0) {
                    if (converted_next_hop == 0) {
                        fprintf(stderr, "IPv6 of next hope is not in presentation format.\n");
                    }
                    else{
                        perror("inet_pton");
                    }
                    exit(-1);
                }
                if (inet_ntop(AF_INET6, buf_next_hop, ip6_next_hop, INET6_ADDRSTRLEN) == NULL){
                    perror("inet_ntop");
                    exit(-1);
                }
                break;
            case 'm':
                metric = optarg;
                if (!((atoi(metric) >= 0)&& (atoi(metric) <= 16))) {
                    fprintf(stderr, "Metric is out of range.\n");
                    exit(-1);
                }
                break;
            case 't':
                router_tag = optarg;
                if (!((atoi(router_tag) >= 0) && (atoi(router_tag) <= 65535))) {
                    fprintf(stderr, "Router tag is out of range.\n");
                    exit(-1);
                }
                break;
            case '?':
                fprintf(stderr, "Missing value of argument.\n");
                return -1;
            default:
                exit(-1);

        }
    } 
    printf("Interface: %s\n", interface);
    printf("IP address: %s, netmask: %s\n", ip_addr, netmask);
    printf("IP address of next hop: %s\n", ip_addr_next_hop);
    printf("Metric: %s\n", metric);
    printf("Router tag: %s\n", router_tag);

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
    RIPngPacket *ripngPacket = new RIPngPacket(ip_addr_next_hop, ip_addr, router_tag, netmask, metric);
   
    //Send packet
    if (sendto(socket_of_client, ripngPacket->packet, ripngPacket->length, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0){
        perror("Error to send message");
        return -1;
    }
    return 0;
}