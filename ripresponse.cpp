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
    char ip_addr_next_hop[40] = "0000:0000:0000:0000:0000:0000:0000:0000";
    int netmask;
    char* prefix;
    int metric = 1;
    int router_tag = 0;
    struct in_addr addr;
    int option;
    while((option = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
        switch(option) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                ip_addr = strtok(optarg, "/");
                prefix = strtok(NULL, "/");
                printf("IP address: %s, prefix: %s\n", ip_addr, prefix);
                if (!inet_aton(ip_addr, &addr)) {
                    fprintf(stderr, "Invalid address of IPv6.\n");
                    exit(-1);
                };
                
                printf("Vypis: %s\n", inet_ntoa(addr));
                netmask = atoi(prefix); 
                if (!((netmask >= 16 ) && (netmask <= 128))) {
                    fprintf(stderr, "Bad length of the prefix.\n");
                    exit(-1);
                }
                break;
            case 'n':
                strcpy(ip_addr_next_hop, optarg);
                break;
            case 'm':
                metric = atoi(optarg);
                printf("metric: %d\n", metric);
                if (!((metric >= 0)&& (metric <= 16))) {
                    fprintf(stderr, "Metric is out of range.\n");
                    exit(-1);
                }
                break;
            case 't':
                router_tag = atoi(optarg);
                if (!((router_tag >= 0) && (router_tag <= 65535))) {
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
    return 0;
}