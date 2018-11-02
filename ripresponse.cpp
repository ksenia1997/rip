//ISA projekt
//Ksenia Bolshakova
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "ripngheader.h"
    
int main(int argc, char* argv[]){
    char* interface;
    char* ip_addr;
    char* ip_addr_next_hop = (char*) "::";
    char* netmask;
    char* prefix;
    char* metric = (char*) "1";
    char* router_tag = (char*) "0";
    struct in_addr addr;
    int option;
    if (argc < 3) {
        fprintf(stderr, "Not all arguments.\n");
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
                if (!((atoi(netmask) >= 16 ) && (atoi(netmask) <= 128))) {
                    fprintf(stderr, "Bad length of the prefix.\n");
                    exit(-1);
                }
                break;
            case 'n':
                ip_addr_next_hop = optarg;
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

    return 0;
}