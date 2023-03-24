#include "network.h"

void block_common_bad_ports() {
    // List of common bad ports to block.
    int bad_ports[] = { 23, 135, 137, 138, 139, 445, 10000 };
    // Bind each bad port to the loopback address.
    for (size_t i = 0; i < sizeof(bad_ports) / sizeof(bad_ports[0]); i++) {
        if (block_port(bad_ports[i]) == -1) {
            fprintf(stderr, "Failed to bind port %d to loopback address.\n", bad_ports[i]);
        }
    }
}

int block_port(int port) 
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return -1;
    }

    printf("Socket is bound to loopback address.\n");
    return 0;
}

int block_ip(const char* ip_addr) {

    char command[100];
    
    // Block the IP address temporarily
    sprintf(command, "iptables -A INPUT -s %s -j DROP", ip_addr);
    if (system(command) == -1) {
        perror("Error blocking IP address");
        return 1;
    }
    
    // Save the iptables rules to a file
    if (system("iptables-save > /etc/iptables/rules.v4") == -1) {
        perror("Error saving iptables rules");
        return 1;
    }
    
    printf("IP address %s has been blocked and rule has been saved.\n", ip_addr);
    
    return 0;
}
