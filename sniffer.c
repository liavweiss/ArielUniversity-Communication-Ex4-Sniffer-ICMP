#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[]= "icmp";
    bpf_u_int32 net;
    char enp[] = "enp0s3"; //Predictable Network Interface Names
    
    // Step 1: Open live pcap session on NIC with name enp0s3
    handle= pcap_open_live(enp, BUFSIZ, 1, 1000, errbuf);
    
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    
    pcap_setfilter(handle, &fp);
    
    // Step 3: Capture ICMP packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
    unsigned short iphdr_len = ip_hdr->ihl * 4;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + iphdr_len  + sizeof(struct ethhdr));
    
    struct sockaddr_in src,dest;
    
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = ip_hdr->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_hdr->daddr;
    
    printf("***********************************************************\n");
    printf("***********************ICMP Packet*************************\n");
    printf("***********************************************************\n");
    printf("IP Header\n");
    printf("  |-Source IP        : %s\n", inet_ntoa(src.sin_addr));
    printf("  |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
    printf("ICMP Header\n");
    printf("  |-Type Of Service  : %d\n", (unsigned int)(icmp_hdr->type));
    printf("  |-Code             : %d\n\n", (unsigned int)(icmp_hdr->code));
    }
