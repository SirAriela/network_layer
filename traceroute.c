#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>       // For struct iphdr
#include <netinet/icmp6.h>    // For ICMPv6
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <poll.h>
#include <float.h>
#include <netdb.h>            // For DNS resolution with getaddrinfo

#define MAX_HOPS 30
#define TIMEOUT 1 // seconds

// Function to calculate checksum
unsigned short checksum(void *data, int length) {
    unsigned short *ptr = data;
    unsigned long sum = 0;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(unsigned char *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Function to create raw socket based on protocol (IPv4/IPv6)
int create_raw_socket(int protocol) {
    int sock;

    if (protocol == 4) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }

    if (sock < 0) {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Function to send ICMP request
void send_icmp_request(int sock, void *dest, int protocol, int id, int sequence) {
    char buffer[64];
    memset(buffer, 0, sizeof(buffer));

    if (protocol == 4) {
        struct icmphdr *icmp = (struct icmphdr *)buffer;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(sequence);
        icmp->checksum = checksum(buffer, sizeof(buffer));
    } else {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(id);
        icmp6->icmp6_seq = htons(sequence);
    }

    if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)dest,
               (protocol == 4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) < 0) {
        perror("Failed to send ICMP request");
    }
}

// Function to receive ICMP reply
int receive_icmp_reply(int sock, int id, int protocol, double *rtt, char *sender_ip, int ttl) {
    char buffer[1024];
    struct sockaddr_storage sender;
    socklen_t sender_len = sizeof(sender);

    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    int timeout = 1000; // 1 second timeout

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = poll(&pfd, 1, timeout);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (ret == 0) {
        printf("%2d  *  Request timeout\n", ttl);
        return 0; // Timeout occurred
    } else if (ret < 0) {
        perror("Poll error");
        return -1; // Error occurred
    }

    ssize_t bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&sender, &sender_len);
    if (bytes_received < 0) {
        perror("Failed to receive ICMP reply");
        return -1;
    }

    *rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;

    if (protocol == 4) {
        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct icmphdr *icmp_header = (struct icmphdr *)(buffer + (ip_header->ihl * 4));

        if (icmp_header->type == ICMP_ECHOREPLY || icmp_header->type == ICMP_TIME_EXCEEDED) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&sender)->sin_addr, sender_ip, INET_ADDRSTRLEN);
            return (icmp_header->type == ICMP_ECHOREPLY) ? 2 : 1;
        }
    } else if (protocol == 6) {
        struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)buffer;

        if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY || icmp6_header->icmp6_type == ICMP6_TIME_EXCEEDED) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sender)->sin6_addr, sender_ip, INET6_ADDRSTRLEN);
            return (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) ? 2 : 1;
        }
    }

    return 0; // Unrecognized ICMP packet
}

int main(){
    
}
