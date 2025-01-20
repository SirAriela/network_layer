#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>

#define MAX_HOPS 30
#define PACKETS_PER_HOP 3
#define TIMEOUT 1000  // Timeout in milliseconds
#define BUFFER_SIZE 1024

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void traceroute(const char *destination_ip) {
    int sock;
    struct sockaddr_in dest_addr;
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    char send_buf[BUFFER_SIZE], recv_buf[BUFFER_SIZE];
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    struct timeval start, end;
    int seq = 0;

    // Create raw socket with IP protocol
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options to include IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        exit(EXIT_FAILURE);
    }

    // Create raw socket for receiving
    int recv_sock;
    if ((recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("receive socket");
        exit(EXIT_FAILURE);
    }

    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, destination_ip, &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", destination_ip, MAX_HOPS);

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        int packets_received = 0;
        float rtt[PACKETS_PER_HOP] = {0};
        char ip_address[INET_ADDRSTRLEN] = "";

        printf("%2d  ", ttl);

        for (int i = 0; i < PACKETS_PER_HOP; i++) {
            memset(send_buf, 0, sizeof(send_buf));

            // Construct IP header
            ip_header = (struct iphdr *)send_buf;
            ip_header->version = 4;
            ip_header->ihl = 5;
            ip_header->tos = 0;
            ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
            ip_header->id = htons(getpid());
            ip_header->frag_off = 0;
            ip_header->ttl = ttl;
            ip_header->protocol = IPPROTO_ICMP;
            ip_header->check = 0;
            ip_header->saddr = INADDR_ANY;
            ip_header->daddr = dest_addr.sin_addr.s_addr;
            ip_header->check = checksum(ip_header, sizeof(struct iphdr));

            // Create ICMP header
            icmp_header = (struct icmphdr *)(send_buf + sizeof(struct iphdr));
            icmp_header->type = ICMP_ECHO;
            icmp_header->code = 0;
            icmp_header->un.echo.id = htons(getpid());
            icmp_header->un.echo.sequence = htons(seq++);
            icmp_header->checksum = 0;
            icmp_header->checksum = checksum(icmp_header, sizeof(struct icmphdr));

            // Record start time
            gettimeofday(&start, NULL);

            if (sendto(sock, send_buf, ip_header->tot_len, 0, 
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                perror("sendto");
                continue;
            }

            struct pollfd fds = {
                .fd = recv_sock,
                .events = POLLIN
            };

            int ret = poll(&fds, 1, TIMEOUT);
            if (ret > 0) {
                ssize_t bytes_received = recvfrom(recv_sock, recv_buf, sizeof(recv_buf), 
                                                0, (struct sockaddr *)&recv_addr, &addr_len);
                if (bytes_received > 0) {
                    // Record end time
                    gettimeofday(&end, NULL);

                    ip_header = (struct iphdr *)recv_buf;
                    icmp_header = (struct icmphdr *)(recv_buf + ip_header->ihl * 4);

                    float time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + 
                                  (end.tv_usec - start.tv_usec) / 1000.0;
                    rtt[i] = time_ms;
                    inet_ntop(AF_INET, &(recv_addr.sin_addr), ip_address, INET_ADDRSTRLEN);

                    packets_received++;

                    // Check if we've reached the destination
                    if (recv_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {
                        printf("%s  %.3fms\n", ip_address, time_ms);
                        close(sock);
                        close(recv_sock);
                        return;
                    }
                }
            } else {
                rtt[i] = -1; // Mark timeout
            }
        }

        if (packets_received > 0) {
            printf("%s  ", ip_address);
            for (int i = 0; i < PACKETS_PER_HOP; i++) {
                if (rtt[i] >= 0) {
                    printf("%.3fms ", rtt[i]);
                } else {
                    printf("* ");
                }
            }
            printf("\n");
        } else {
            printf("* * *\n");
        }
    }

    printf("Destination unreachable\n");
    close(sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <destination_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    traceroute(argv[1]);
    return 0;
}