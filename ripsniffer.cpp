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
#define RIP_ENTRY 20
pcap_t *handle; // Session handle  
//Print information about RIPv1 and RIPv2 
void ripInfo(u_char *args,const struct pcap_pkthdr* header,const u_char* packet)
{    
    //unused parameters
    (void) args;
    (void) header;
   
    if (packet == NULL) {
        fprintf(stderr, "Empty packet.\n");
        return;
    }
    printf("RIPpacket\n");

    
    int ipVersion = packet[14]>>4;
    //RIPv1 RIPv2
    if (ipVersion == 4) {
        printf("Source IPv4 address: %d:%d:%d:%d\n",packet[26], packet[27], packet[28], packet[29]);
        printf("Destination IPv4 address: %d:%d:%d:%d\n", packet[30], packet[31], packet[32], packet[33]);
        
        short packetLen = (short)(((unsigned char)packet[38]) << 8 | ((unsigned char)packet[39]));
        packetLen = packetLen - 8;

        int ripCommand = packet[42];
        if (ripCommand == 2) {
            printf("Command: Response.\n");
        }
        else if (ripCommand == 1){
            printf("Command: Request.\n");
        }
        else {
            printf("Command: %d\n", ripCommand);
        }
        int ripVersion = packet[43];
        printf("Version: RIPv%x\n", ripVersion);
        if (ripVersion == 2) {
            if ((int(packet[46]) == 255) && (int(packet[47]) == 255)){
                //authentication Type is 2 byte
                int authenticationType1 = packet[48];
                int authenticationType2 = packet[49];

                if((authenticationType1 == 0)&&(authenticationType2 == 2)) {
                    printf("Authentication type: Simple password(2).\n");
                    printf("Authentication: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", packet[50], packet[51], packet[52], packet[53], 
                                                                                packet[54], packet[55], packet[56], packet[57], 
                                                                                packet[58], packet[59], packet[60], packet[61], 
                                                                                packet[62], packet[63], packet[64], packet[65]);
                    
                    printf("\n");
                    printf("Route Entry:\n");
                    int i = 66;
                    while((i+RIP_ENTRY) <= (42+packetLen)) {
                        printf("Address Family: %d\n", (short)(((unsigned char)packet[i]) << 8 | ((unsigned char)packet[i+1])));
                        printf("Route tag: %d\n", (short)(((unsigned char)packet[i+2]) << 8 | ((unsigned char)packet[i+3])));
                        printf("IP address: %d:%d:%d:%d\n", packet[i+4], packet[i+5], packet[i+6], packet[i+7]);
                        printf("Netmask: %d:%d:%d:%d\n", packet[i+8], packet[i+9], packet[i+10], packet[i+11]);
                        printf("Next hop: %d:%d:%d:%d\n", packet[i+12], packet[i+13], packet[i+14], packet[i+15]);
                        uint32_t metric = 0;
                        for (int k = 0; k < 4; k++) {
                            metric = (metric << 4) | packet[i+16+k];
                            
                        }
                        printf("Metric: %d\n", metric);
                        printf("\n");
                        i = i+RIP_ENTRY;                                    
                    }
                    
                }

                else if ((authenticationType1 == 0)&&(authenticationType2 == 3)) {
                    printf("Authentication: MD5");
                }
                else{
                    printf("Authentication: Other");
                }
            }
            
        }
      
        
 
        printf("\n");
    }
    else {
        short RTELen = (short)(((unsigned char)packet[58]) << 8 | ((unsigned char)packet[59]));
        RTELen = RTELen - 12; //len of RTE        
        printf("Version: RIPng\n");
        int command = packet[62];
        if (command == 2) {
            printf("Command: Response (%d)\n",command); 
        }
        else if (command == 1){
            printf("Command: Request (%d)\n", command); 
        }
        else{
            printf("Command: %d\n", command);
        }
        printf("\n");
        printf("Route Table Entry:\n");
        int i = 66;
        int k = 0;
        while (k <= RTELen) {
            printf("IPv6 Prefix: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet[i+k], packet[i+k+1], packet[i+k+2],packet[i+k+3], 
                                                                                                        packet[i+k+4], packet[i+k+5], packet[i+k+6], packet[i+k+7], 
                                                                                                        packet[i+k+8], packet[i+k+9], packet[i+k+10], packet[i+k+11], 
                                                                                                        packet[i+k+12], packet[i+k+13], packet[i+k+14], packet[i+k+15]);
            short routeTag = (short)(((unsigned char)packet[i+k+16]) << 8 | ((unsigned char)packet[i+k+17]));
            printf("Route Tag: %d\n", routeTag);
            printf("Prefix Length: %d\n", packet[i+k+18]);
            printf("Metric: %d\n", packet[i+k+19]);
            printf("\n");     
            k += 20;                                                                                       
        }
        printf("Source IPv6 address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",packet[22], packet[23], packet[24], packet[25], packet[26], packet[27], packet[28], packet[29],
                                                                            packet[30], packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        printf("Destination IPv6 address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet[38], packet[39], packet[40], packet[41], packet[42], packet[43], packet[44], packet[45],
                                                        packet[46], packet[47], packet[48], packet[49], packet[50], packet[51], packet[52], packet[53]);
    
        printf("\n");

       
    }
}


int main(int argc, char *argv[]) {
    char *dev = NULL;  //device to sniff on
    //pcap_t *handle; // Session handle  
    char errbuf[PCAP_ERRBUF_SIZE]; //Error string
    struct bpf_program fp; //The compiled filter expression
    char filter_expRIP[] = "port 520 or port 521"; //The filter expression RIP
    //char filter_expRIPng[] = "port 521"; //The filter expression for RIPng
    bpf_u_int32 mask; //The netmask of our sniffing device
    bpf_u_int32 net; //The IP of our sniffing device
    struct pcap_pkthdr header; //The header that pcap gives us
    const u_char *packet; //The actual packet

    if (argc < 2) {
        fprintf(stderr, "Bad number of arguments.\n");
        return -1;
    }
    int option;
    while((option = getopt(argc, argv, "i:h")) != -1) {
        switch(option) {
            case 'i':
                dev = optarg;
                break;
            case 'h':
                fprintf(stderr, "Please enter argument: -i <interface>\nwhere <interface> is interface on which packet capture is to be performed.\n");
                return 0;
            case '?':
                fprintf(stderr, "Bad argument.\n");
                return -1;
            default:
                exit(-1);
        }
    }

    if (dev == NULL) {
        fprintf(stderr, "Missing interface.\nPlease enter: -i <interface>\n");
        exit(-1);
    }
    //This part of program prepares the sniffer to sniff all traffic coming from or going to port NUMBER
    //Get IP and Mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Cannot get net mask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s, %s\n", dev, errbuf );
        return(-1);
    }
    if  (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers -not supported.\n", dev);
        return(-1);
    }

    //Set and Compile RIPv1, RIPv2 and RIPng filter
    if (pcap_compile(handle, &fp, filter_expRIP, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_expRIP, pcap_geterr(handle));
        return(-1);
    }
    

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_expRIP, pcap_geterr(handle));
        return(-1);
    }

  
    pcap_loop(handle, 0, ripInfo, NULL);
        
    //Close the session
    pcap_close(handle);

    return (0);
}