#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IFACE_LENGTH 64
#define MAX_CAPTURED_BYTES 65535



typedef struct{
    uint32_t timestamp;
    uint8_t ip_version;

    union{
        struct{
            struct in_addr src_ip;
            struct in_addr dst_ip;
        }v4;
        struct{
            struct in6_addr src_ip6;
            struct in6_addr dst_ip6;
        }v6;
    }ip;

    uint16_t src_port;
    uint16_t dst_port; 
    uint8_t protocol;

    uint8_t direction;
    uint32_t packet_size;
    uint32_t flow_id;

}core_metadata;

typedef struct{
    core_metadata core;

    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flag;
    uint16_t window_size;
    uint8_t tcp_state;
    uint8_t data_offset;
    uint16_t checksum;

}tcp_metadata;


int main(){

    pcap_t *session;
    char interface[IFACE_LENGTH];
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
   

    printf("Enter interface name:\n");
    if(!fgets(interface, IFACE_LENGTH, stdin)){
        fprintf(stderr, "Enter a valid interface name");
        return 1;
    }

    interface[strcspn(interface, "\n")] = '\0';
    printf("Using interface %s\n", interface);


    if(pcap_lookupnet(interface, &net, &mask, errbuff) == -1){
        fprintf(stderr, "Canr get mask for device %s\n", interface);
        net = 0;
        mask = 0;
    }

    session = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuff);

    if(session == NULL){
        fprintf(stderr, "Coldnt open decive %s: %s\n", interface , errbuff);
        return 2;
    }

    //Compatibility check
    if(pcap_datalink(session) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesnt provide ethernet headers, not supported\n", interface);
        return 2;
    }

    // Compile filter expression
    if(pcap_compile(session, &fp,filter_exp, 0, net)==-1){
        fprintf(stderr, "Couldnt parse filter %s:%s\n", filter_exp, pcap_geterr(session));
        return 2;
    }

    //Set compiled filter to session
    if(pcap_setfilter(session, &fp)==-1){
        fprintf(stderr, "Couldnt filter with filter %s:%s\n", filter_exp,pcap_geterr(session));
        return 2;
    }

    packet = pcap_next(session, &header);
    printf("Jacked a packet with length of [%d]:", header.len);
    pcap_freecode(&fp);
    pcap_close(session);
    return 0;
}