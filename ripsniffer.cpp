//ISA projekt
//Ksenia Bolshakova

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <csignal>
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

    int ipVersion = packet[14]>>4;
    if (ipVersion == 4) {
        int ripCommand = packet[42];

        int ripVersion = packet[43];
        printf("Version: RIPv%x\n", ripVersion);
        if (ripVersion == 2) {
            if (ripCommand == 2) {
                printf("Command: Responce.\n");
            }
            else {
                printf("Command: Request.\n");
            }
            //authentication Type is 2 byte
            int authenticationType1 = packet[48];
            int authenticationType2 = packet[49];
            if((authenticationType1 == 0)&&(authenticationType2 == 2)) {
                printf("Authentication: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", packet[50], packet[51], packet[52], packet[53], 
                                                                            packet[54], packet[55], packet[56], packet[57], 
                                                                            packet[58], packet[59], packet[60], packet[61], 
                                                                            packet[62], packet[63], packet[64], packet[65]);
            }
            else if ((authenticationType1 == 0)&&(authenticationType2 == 3)) {
                printf("Authentication: MD5");
            }
            else{
                printf("Authentication: Other");
            }
            
        }
      
        printf("Source IPv4 address: %d:%d:%d:%d\n",packet[26], packet[27], packet[28], packet[29]);
        printf("Destination IPv4 address: %d:%d:%d:%d\n", packet[30], packet[31], packet[32], packet[33]);
 
        printf("\n");
    }
    else {
        
        printf("Version: RIPng\n");
        int ipVersion = packet[14]>>4;     
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