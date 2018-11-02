#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <csignal>
pcap_t *handle; // Session handle  
//Print information about RIPv1 and RIPv2 
void ripInfo(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{    
    printf("RIP packet.\n");
    int ripVersion = packet[43];
    printf("Version: RIPv%x\n", ripVersion);
    if (ripVersion == 2) {
        printf("Authentication: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", packet[50], packet[51], packet[52], packet[53], 
                                                                     packet[54], packet[55], packet[56], packet[57], 
                                                                     packet[58], packet[59], packet[60], packet[61], 
                                                                     packet[62], packet[63], packet[64], packet[65]);
    }
    int ipVersion = packet[14]>>4;
  
       
    printf("Source IPv4 address: %d:%d:%d:%d\n",packet[26], packet[27], packet[28], packet[29]);
    printf("Destination IPv4 address: %d:%d:%d:%d\n", packet[30], packet[31], packet[32], packet[33]);
    //fflush(stdout);
    printf("\n");
}
//Print information about RIPng
void ripngInfo(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    printf("RIPng packet.\n");
    printf("Version: RIPng\n");
    int ipVersion = packet[14]>>4;     
    printf("Source IPv6 address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",packet[22], packet[23], packet[24], packet[25], packet[26], packet[27], packet[28], packet[29],
                                                                            packet[30], packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
    printf("Destination IPv6 address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet[38], packet[39], packet[40], packet[41], packet[42], packet[43], packet[44], packet[45],
                                                        packet[46], packet[47], packet[48], packet[49], packet[50], packet[51], packet[52], packet[53]);
    
    //fflush(stdout);
    printf("\n");
}
void alarmStopHandler(int signal) {
    printf("Time is over.\n");
    printf("\n");
    pcap_breakloop(handle);

}

int main(int argc, char *argv[]) {
    char *dev;  //device to sniff on
    //pcap_t *handle; // Session handle  
    char errbuf[PCAP_ERRBUF_SIZE]; //Error string
    struct bpf_program fp; //The compiled filter expression
    char filter_expRIP[] = "port 520"; //The filter expression RIP
    char filter_expRIPng[] = "port 521"; //The filter expression for RIPng
    bpf_u_int32 mask; //The netmask of our sniffing device
    bpf_u_int32 net; //The IP of our sniffing device
    struct pcap_pkthdr header; //The header that pcap gives us
    const u_char *packet; //The actual packet

    if (argc != 3) {
        fprintf(stderr, "Bad number of arguments.\n");
        return -1;
    }
    int option;
    while((option = getopt(argc, argv, "i:")) != -1) {
        switch(option) {
            case 'i':
                dev = optarg;
                break;
            case '?':
                fprintf(stderr, "Bad argument.\n");
                return -1;
            default:
                exit(-1);
        }
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
        return(2);
    }
    if  (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers -not supported.\n", dev);
        return(2);
    }

    //Set and Compile RIPv1 and RIPv2 filter
    if (pcap_compile(handle, &fp, filter_expRIP, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_expRIP, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_expRIP, pcap_geterr(handle));
        return(2);
    }

    printf("RIPv1 and RIPv2.\n");
    alarm(60);
    signal(SIGALRM, alarmStopHandler);
    //Grab a packet
    pcap_loop(handle, -1, ripInfo, NULL);

    //Set and Compile RIPng filter
    if (pcap_compile(handle, &fp, filter_expRIPng, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_expRIPng, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_expRIPng, pcap_geterr(handle));
        return(2);
    }

    printf("RIPng.\n");
    alarm(60);
    //Grab a packet
    pcap_loop(handle, -1, ripngInfo, NULL);
    //Close the session
    pcap_close(handle);
    //printf("Device: %s\n", dev);
    return (0);
}