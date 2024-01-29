#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <linux/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <linux/tcp.h>


#define MAX_PACKET_SIZE 65536

void get_tls_record(unsigned char* buffer, int size);


typedef struct __attribute__((packed)) {
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

void get_tls_record(unsigned char* buffer, int size) {
    // Skip the Ethernet, IP and TCP headers
    struct ethhdr * eth = (struct ethhdr *)(buffer);
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr *)(buffer + ethhdrlen);
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + ethhdrlen);
    unsigned short tcphdrlen = tcph->doff*4;

    // Check if the packet is long enough to contain a TLS record
    if (size < iphdrlen + tcphdrlen + sizeof(TLSRecord) + ethhdrlen) {
        // printf("Packet is too short for a TLS record\n");
        return;
    }

    // Get the TLS record
    TLSRecord *tls = (TLSRecord*)(buffer + iphdrlen + tcphdrlen + ethhdrlen);
    if(tls->content_type == 0x16){
        //// print TLS record header
        // printf("TLS handshake\n");
        // printf("Content type: 0x%02x\n", tls->content_type);
        // printf("Version: 0x%04X\n", ntohs(tls->version));
        // printf("Length: %d\n", ntohs(tls->length));

        // for (int i = 0; i < ntohs(tls->length); i++){
        //     printf("%02X ", buffer[i]);
        // }
        //// Print buffer 
        // for (int i = 0; i < size; i++){
        //     printf("%02X ", buffer[i]);
        // }
        // printf("\n");

        // parse_client_hello(buffer + iphdrlen + tcphdrlen + sizeof(TLSRecord) + ethhdrlen, size - iphdrlen - tcphdrlen - sizeof(TLSRecord) - ethhdrlen);
        ClientHello *client_hello = (ClientHello*)(buffer + iphdrlen + tcphdrlen + sizeof(TLSRecord) + ethhdrlen);
        if (client_hello->handshake_type == 0x01){
            // // Print the ClientHello details
            // printf("\nHandshake type: 0x%02x\n", client_hello->handshake_type);
            // printf("Length: %d\n", (client_hello->length[0] << 16) | (client_hello->length[1] << 8) | client_hello->length[2]);
            // printf("Version: 0x%04X\n", ntohs(client_hello->version));
            // printf("Random: ");
            // for (int i = 0; i < 32; i++) {
            //     printf("%02X ", client_hello->random[i]);
            // }
            // printf("\n");
            // printf("Session ID length: %d\n", client_hello->session_id_length);
            // printf("Session ID: ");
            // for (int i = 0; i < client_hello->session_id_length; i++) {
            //     printf("%02x ", client_hello->session_id[i]);
            // }
            // printf("\nCipher suites length: %d\n", ntohs(client_hello->cipher_suites_length));
            // printf("Cipher suites: ");
            // for (int i = 0; i < ntohs(client_hello->cipher_suites_length)/2; i++) {
            //     printf("%04x ", ntohs(client_hello->cipher_suites[i]));
            // }
            // printf("\nCompression methods length: %d\n", client_hello->compression_methods_length);
            // printf("Compression methods: ");
            // for (int i = 0; i < client_hello->compression_methods_length; i++) {
            //     printf("%02x ", client_hello->compression_methods[i]);
            // }
            // printf("\nExtensions length: %d\n", ntohs(client_hello->extensions_length));
            // printf("Extensions: ");
            // for (int i = 0; i < ntohs(client_hello->extensions_length); i++) {
            //     printf("%02x ", client_hello->extensions[i]);
            // }
            // printf("\n");

            
            uint8_t *ptr = client_hello->extensions;
            uint8_t *end = client_hello->extensions + ntohs(client_hello->extensions_length);
            while (ptr < end){
                Extension *ext = (Extension*)ptr;
                // printf("Extension Type: 0x%04x\n", ntohs(ext->extension_type));
                // printf("Extension Length: %d\n", ntohs(ext->extension_length));

                if (ntohs(ext->extension_type) == 0x0000){
                    ServerName *server_name = (ServerName*)ext->extension_data;
                    // printf("Server Name List Length: %d\n", ntohs(server_name->server_name_list_length));
                    // printf("Server Name Type: 0x%02x\n", server_name->server_name_type);
                    // printf("Server Name Length: %d\n", ntohs(server_name->server_name_length));
                    printf("Server Name: ");
                    for (int i = 0; i < ntohs(server_name->server_name_length); i++){
                        printf("%c", server_name->server_name[i]);
                    }
                    printf("\n");
                }

                ptr += ntohs(ext->extension_length) + 4;                   
            }
            // // Print buffer hex
            // for (int i = 0; i < size; i++){
            //     printf("%02X ", buffer[i]);
            // }
            // printf("\n\n\n");
            
        }
    }
}



int main(){
    int sockfd;
    unsigned char buffer[MAX_PACKET_SIZE];

    // Create a raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {      //AF_INET - SOCK_RAW - IPPROTO_TCP
                                                                               // AF_PACKET - SOCK_RAW - htons(ETH_P_ALL)
        perror("Could not create socket");
        return 1;
    }

    while (1){
        socklen_t saddr_size = sizeof(struct sockaddr);
        struct sockaddr saddr;
        memset(&buffer, 0, MAX_PACKET_SIZE);

        // Receive a packet
        int data_size = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_size);

        if (data_size == -1){
            perror("Could not receive packet");
            return 1;
        }
        // printf("data_size: %d\n", data_size);
        // printf("Received packet\n");
        // for (int i = 0; i < data_size; i++){
        //     printf("%02X ", buffer[i]);
        // }
        // printf("\n\n\n\n");

        // Process the packet
        get_tls_record(buffer, data_size);
        // get_clienthello_packet(buffer, data_size);
    }

    return 0;
}