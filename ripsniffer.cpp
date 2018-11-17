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
        if (ripVersion == 1) {
            int ripv1_len = packetLen - 4;
            int l = 0;
            while (l < ripv1_len) {
                short addr_family_id = (short)(((unsigned char)packet[46+l]) << 8 | ((unsigned char)packet[47+l]));
                printf("Address family identifier: %d\n", addr_family_id);
                printf("IPv4 address: %d:%d:%d:%d\n", packet[50+l], packet[51+l], packet[52+l], packet[53+l]);
                uint32_t metric = 0;            
                metric = ((metric << 4) | packet[62+l] | (metric<<4)| packet[63+l] | (metric<<4)|packet[64+l]| (metric<<4)|packet[65+l]);
                printf("Metric: %d\n", metric);
                printf("\n");
                l += RIP_ENTRY;
            }
        }
        else if (ripVersion == 2) {
            //check if 0xFFFF 
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
                    printf("packet len: %d\n", packetLen);
                    while((i+RIP_ENTRY) <= (42+packetLen)) {
                        printf("Address Family: %d\n", (short)(((unsigned char)packet[i]) << 8 | ((unsigned char)packet[i+1])));
                        printf("Route tag: %d\n", (short)(((unsigned char)packet[i+2]) << 8 | ((unsigned char)packet[i+3])));
                        printf("IP address: %d:%d:%d:%d\n", packet[i+4], packet[i+5], packet[i+6], packet[i+7]);
                        printf("Netmask: %d:%d:%d:%d\n", packet[i+8], packet[i+9], packet[i+10], packet[i+11]);
                        printf("Next hop: %d:%d:%d:%d\n", packet[i+12], packet[i+13], packet[i+14], packet[i+15]);
                        uint32_t metric = 0;   
                        metric = ((metric << 4) | packet[i+16+0] | (metric<<4)| packet[i+17] | (metric<<4)|packet[i+18]| (metric<<4)|packet[i+19]);  
                        printf("Metric: %d\n", metric);
                        printf("\n");
                        i = i+RIP_ENTRY;                                    
                    }
                    
                }

                else if ((authenticationType1 == 0)&&(authenticationType2 == 3)) {
                    int lenRTE = packetLen - 24;
                    printf("Authentication: MD5");
                    short rip2_packetLen = (short)(((unsigned char)packet[50]) << 8 | ((unsigned char)packet[51]));
                    printf("RIP-2 packet length: %d\n", rip2_packetLen);
                    printf("Key ID: %d\n", packet[52]);
                    printf("Authentication data length: %d\n", packet[53]);
                    uint32_t seq_num = 0;
                    seq_num = ((seq_num << 4) | packet[54] | (seq_num<<4)| packet[55] | (seq_num<<4)|packet[56]| (seq_num<<4)|packet[57]);
                    printf("Sequence number: %d\n", seq_num);
                    int idx = 0;
                    printf("\n");
                    printf("Route Table Entry.\n");
                    while(idx < lenRTE) {
                        if ((int(packet[66+idx]) == 255) && (int(packet[67+idx]) == 255)) {
                            printf("Authentication Data: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", packet[70+idx], packet[71+idx],
                                    packet[72+idx], packet[73+idx], packet[74+idx], packet[75+idx], packet[76+idx], packet[77+idx], packet[78+idx], packet[79+idx],
                                    packet[80+idx], packet[81+idx], packet[82+idx], packet[83+idx], packet[84+idx], packet[85+idx]);
                            idx += RIP_ENTRY;
                        }
                        else{
                            printf("Address Family: %d\n", (short)(((unsigned char)packet[66+idx]) << 8 | ((unsigned char)packet[67+idx])));
                            printf("Route tag: %d\n", (short)(((unsigned char)packet[68 + idx]) << 8 | ((unsigned char)packet[69+idx])));
                            printf("IP address: %d:%d:%d:%d\n", packet[70+idx], packet[71+idx], packet[72+idx], packet[73+idx]);
                            printf("Netmask: %d:%d:%d:%d\n", packet[74+idx], packet[75+idx], packet[76+idx], packet[77+idx]);
                            printf("Next hop: %d:%d:%d:%d\n", packet[78+idx], packet[79+idx], packet[80+idx], packet[81+idx]);
                            uint32_t metric = 0;
                            metric = ((metric << 4) | packet[82+idx] | (metric<<4)| packet[83+idx] | (metric<<4)|packet[84+idx]| (metric<<4)|packet[85+idx]);
                            printf("Metric: %d\n", metric);
                            printf("\n");
                            idx += RIP_ENTRY;
                        }
                    }


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
        while (k <RTELen) {
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
        fprintf(stderr, "Missing arguments.\nPlease enter: \"./myripsniffer -h\" to see a help.\n");
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
                fprintf(stderr, "Bad argument. Please enter \"./myripsniffer -h \" to see a help.\n");
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

    printf("Start sniffing.\n");
    pcap_loop(handle, 0, ripInfo, NULL);
        
    //Close the session
    pcap_close(handle);

    return (0);
}