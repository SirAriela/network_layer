#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>    // For struct iphdr
#include <netinet/icmp6.h> // For ICMPv6
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <poll.h>
#include <float.h>

// Function prototypes
unsigned short checksum(void *data, int length);
int create_raw_socket(int protocol);
void send_icmp_request(int sock, void *dest, int protocol, int id, int sequence);
int receive_icmp_reply(int sock, int id, int protocol, double *rtt);

// check sum calculation
unsigned short checksum(void *data, int length)
{
    unsigned short *ptr = data;
    unsigned long sum = 0;

    while (length > 1)
    {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1)
    {
        sum += *(unsigned char *)ptr;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// create a raw socket
int create_raw_socket(int protocol)
{
    int sock;
    // Create a raw socket of the specified protocol
    if (protocol == 4)
    {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    else if (protocol == 6)
    {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    else
    {
        fprintf(stderr, "Error: Invalid protocol.\n");
        exit(EXIT_FAILURE);
    }

    if (sock < 0)
    {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    return sock;
}

// send the icmp request
void send_icmp_request(int sock, void *dest, int protocol, int id, int sequence)
{
    char buffer[64];
    memset(buffer, 0, sizeof(buffer));
    // Create ICMP header
    if (protocol == 4)
    {
        struct icmphdr *icmp = (struct icmphdr *)buffer;
        icmp->type = ICMP_ECHO; // Echo Request
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(sequence);
        icmp->checksum = checksum(buffer, sizeof(buffer));
    }
    else if (protocol == 6)
    {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(id);
        icmp6->icmp6_seq = htons(sequence);
    }
    else
    {
        fprintf(stderr, "Error: Invalid protocol.\n");
        exit(EXIT_FAILURE);
    }

    if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)dest,
               (protocol == 4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) < 0)
    {
        perror("Failed to send ICMP request");
    }
}

// receive the icmp reply
int receive_icmp_reply(int sock, int id, int protocol, double *rtt)
{
    char buffer[1024];
    struct sockaddr_storage sender;
    socklen_t sender_len = sizeof(sender);

    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int timeout = 10000; // 10 seconds timeout

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = poll(&pfd, 1, timeout);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (ret == 0)
    {
        printf("Timeout: No reply received within 10 seconds.\n");
        return 0; // Timeout occurred
    }
    else if (ret < 0)
    {
        perror("Poll error");
        return -1; // Error occurred
    }

    ssize_t bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&sender, &sender_len);
    if (bytes_received < 0)
    {
        perror("Failed to receive ICMP reply");
        return -1;
    }

    *rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;

    printf("Received ICMP reply, RTT=%.3f ms\n", *rtt);
    return 1;
}

int main(int argc, char *argv[])
{
    int opt;
    char *address = NULL;
    int count = -1;   // Default: no count specified
    int flood = 0;    // Default: no flood mode
    int protocol = 4; // Default: IPv4

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1)
    {
        switch (opt)
        {
        case 'a':
            // will get the ip address
            address = optarg;
            break;
        case 't':
            // will get the protocol
            protocol = atoi(optarg);
            if (protocol != 4 && protocol != 6)
            {
                fprintf(stderr, "Error: Protocol must be 4 (IPv4) or 6 (IPv6).\n");
                return EXIT_FAILURE;
            }
            break;
        case 'c':
            // how many times to send the icmp request
            count = atoi(optarg);
            if (count <= 0)
            {
                fprintf(stderr, "Error: Count must be a positive integer.\n");
                return EXIT_FAILURE;
            }
            break;
        case 'f':
            // flood mode
            flood = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -a <address> [-t <4|6>] [-c <count>] [-f]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Check if address is provided
    if (!address)
    {
        fprintf(stderr, "Error: Target address is required (-a <address>).\n");
        return EXIT_FAILURE;
    }

    // Set default count if not provided
    if (count == -1)
    {
        if (flood)
        {
            count = -1; // Infinite mode
            printf("Flood mode activated with infinite packets. Press Ctrl+C to stop.\n");
        }
        else
        {
            count = 4; // Default to 4 packets
        }
    }

    // Create raw socket
    int sock = create_raw_socket(protocol);

    // Setup destination address
    struct sockaddr_in dest4;
    struct sockaddr_in6 dest6;
    void *dest;

    if (protocol == 4)
    {
        memset(&dest4, 0, sizeof(dest4));
        dest4.sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &dest4.sin_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv4 address: %s\n", address);
            return EXIT_FAILURE;
        }
        dest = &dest4;
    }
    else if (protocol == 6)
    {
        memset(&dest6, 0, sizeof(dest6));
        dest6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &dest6.sin6_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv6 address: %s\n", address);
            return EXIT_FAILURE;
        }
        dest = &dest6;
    }
    else
    {
        fprintf(stderr, "Error: Invalid protocol.\n");
        return EXIT_FAILURE;
    }

    // Start ping loop
    printf("Pinging %s with 64 bytes of data:\n", address);

    int id = getpid() & 0xFFFF; // Use process ID as identifier
    // parameters for statistics
    int packets_sent = 0, packets_received = 0;
    double rtt_min = DBL_MAX, rtt_max = 0, rtt_sum = 0;

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    for (int i = 0; count == -1 || i < count; i++)
    {
        send_icmp_request(sock, dest, protocol, id, i);
        packets_sent++;

        double rtt;
        int reply = receive_icmp_reply(sock, id, protocol, &rtt);

        if (reply == 1)
        {
            packets_received++;
            // saves the total time of the rtt
            rtt_sum += rtt;
            // updates what is the new min\max
            if (rtt < rtt_min)
                rtt_min = rtt;
            if (rtt > rtt_max)
                rtt_max = rtt;

            if (!flood)
            {
                sleep(1); // Add a delay if not in flood mode
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &end_time);

        double total_time = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                            (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

        // Print statistics
        printf("\n--- %s ping statistics ---\n", address);
        printf("%d packets transmitted, %d received, %.1f%% packet loss, time %.2fms\n",
               packets_sent, packets_received,
               ((packets_sent - packets_received) / (double)packets_sent) * 100.0,
               total_time);
        if (packets_received > 0)
        {
            printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
                   rtt_min, rtt_sum / packets_received, rtt_max);
        }

        close(sock);
        return EXIT_SUCCESS;
    }
}
