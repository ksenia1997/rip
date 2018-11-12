//ISA project
//Ksenia Bolshakova
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include "ripngpacket.h"
    
int main(int argc, char* argv[]){
    char* interface = NULL;
    char* ip_addr = NULL;
    char* ip_addr_next_hop = (char*) "::";
    char* netmask;
    char* prefix;
    char* metric = (char*) "1";
    char* router_tag = (char*) "0";
    int converted_next_hop;
    int converted_addr;
    unsigned int index;
    struct in6_addr ipv6_addr;
    struct in6_addr ipv6_nexthop_addr;
    int option;
    converted_next_hop = inet_pton(AF_INET6, ip_addr_next_hop, &ipv6_nexthop_addr);

   
    if (argc < 2) {
        fprintf(stderr, "Not all arguments.\nPlease enter: ./myripresponse -h to see a help.\n");
        return -1;
    }
    while((option = getopt(argc, argv, "i:r:n:m:t:h")) != -1) {
        switch(option) {
            case 'i':
                interface = optarg;
                index = if_nametoindex(optarg);
                break;
            case 'r':
                ip_addr = strtok(optarg, "/");
                prefix = strtok(NULL, "/");
                netmask = prefix; 
                converted_addr = inet_pton(AF_INET6, ip_addr, &ipv6_addr);
                if (converted_addr <= 0) {
                    if (converted_addr == 0) {
                        fprintf(stderr, "IPv6 is not in presentation format.\n");
                    }
                    else{
                        perror("inet_pton");
                    }
                    exit(-1);
                }

                if (!((atoi(netmask) >= 16 ) && (atoi(netmask) <= 128))) {
                    fprintf(stderr, "Bad length of the prefix.\n");
                    exit(-1);
                }
                break;
            case 'n':
                ip_addr_next_hop = optarg;
                converted_next_hop = inet_pton(AF_INET6, ip_addr_next_hop, &ipv6_nexthop_addr);
                if (converted_next_hop <= 0) {
                    if (converted_next_hop == 0) {
                        fprintf(stderr, "IPv6 of next hope is not in presentation format.\n");
                    }
                    else{
                        perror("inet_pton");
                    }
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
            case 'h':
                fprintf(stderr, "Please enter: -i <interface> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}\n<interface> is interface on which packet capture is to be performed.\n<IPv6> is IP address of capture network and behind the slash is numerical length of the network mask.\n-n <IPv6> is a next-hope address for capture route, implicitly \"::\"\n-m is a RIP Metric, the number of hopes, implicitly is 1(not necessary parameter).\n-t is a number of Router Tag, implicitly 0.\n");
                return 0;
            case '?':
                fprintf(stderr, "Missing value of argument.\n");
                return -1;
            default:
                exit(-1);

        }
    } 
 
    if ((interface == NULL) || (ip_addr == NULL)){
        fprintf(stderr, "Missing necessary arguments: interface and IPv6 address.\n");
        exit(-1);
    }
    printf("Interface: %s\n", interface);
    printf("IP address: %s, netmask: %s\n", prefix, netmask);
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

    //Set of a socket
    if (setsockopt(socket_of_client, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index))){
        perror("error of setsockopt"); 
        return -1;
    }
    //Binding of a socket to the port
    if (bind(socket_of_client, (struct sockaddr *) &source_addr, sizeof(source_addr)) < 0) {
        perror("error of binding");
        exit(-1);
    }

    int max_hop = 255;
    if (setsockopt(socket_of_client, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &max_hop, sizeof(max_hop))){
        perror("error of setsockopt"); 
        return -1;
    }
    
    //Build RIPng packet
    // 2 is purpose of the message (it is a pesponse)
    RIPngPacket *ripngPacket = new RIPngPacket(ipv6_nexthop_addr, ipv6_addr, router_tag, netmask, metric, 2);
   
    //Send packet
    if (sendto(socket_of_client, ripngPacket->packet, ripngPacket->length, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0){
        perror("Error to send message");
        return -1;
    }
    return 0;
}