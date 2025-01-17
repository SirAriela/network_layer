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
#include <netdb.h> // For DNS resolution with getaddrinfo

#define MAX_HOPS 30
#define TIMEOUT 1 // seconds

// Function to calculate checksum
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

// Function to create raw socket based on protocol (IPv4/IPv6)
int create_raw_socket(int protocol)
{
    int sock;

    if (protocol == 4)
    {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    }
    if (sock < 0)
    {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    return sock;
}
void debug_packet(char *buffer, int length) {
    printf("Packet (Hex): ");
    for (int i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
}

// Function to send ICMP request
void send_icmp_request(int sock, void *dest, int protocol, int id, int seq)
{
    char buffer[64];
    memset(buffer, 0, sizeof(buffer));

    struct iphdr *ip_header = (struct iphdr *)buffer;
    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + sizeof(struct iphdr));

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_header->id = htons(seq);
    ip_header->frag_off = 0;
    ip_header->ttl = seq;
    ip_header->check = 0;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = inet_addr("192.168.1.173");
    ip_header->daddr = ((struct sockaddr_in *)dest)->sin_addr.s_addr;
    ip_header->check = checksum(ip_header, sizeof(struct iphdr));

    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->checksum = 0;
    icmp_header->un.echo.id = htons(id);
    icmp_header->un.echo.sequence = seq;
    icmp_header->checksum = checksum(icmp_header, sizeof(struct icmphdr));
    printf("ID (Hex): %04x\n", id);

    if (sendto(sock, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
    {
        perror("Failed to send ICMP request");
    }
    debug_packet(buffer, sizeof(struct iphdr) + sizeof(struct icmphdr));
}

// Function to receive ICMP reply
int receive_icmp_reply(int sock, int id, int protocol, double *rtt, int index)
{
    char buffer[1024];
    char sender_ip[INET_ADDRSTRLEN];
    struct sockaddr_storage sender;
    socklen_t sender_len = sizeof(sender);

    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int timeout = 5000; // 1 second timeout

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // ממתינים לנתונים ב-socket, עד timeout מיליסקנד
    int ret = poll(&pfd, 1, timeout);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (ret == 0)
    {
        printf("%2d  *  Request timeout *\n", index);
        return 0; // Timeout occurred
    }
    else if (ret < 0)
    {
        perror("Poll error");
        return -1; // Error occurred
    }

    // יש נתונים להقرأ
    ssize_t bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&sender, &sender_len);
    if (bytes_received < 0)
    {
        perror("Failed to receive ICMP reply");
        return -1;
    }
     debug_packet(buffer, sizeof(struct iphdr) + sizeof(struct icmphdr));

    // מדידת הזמן שהמתנו מרגע השליחה
    *rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;

    // המעטפת: ה-IP Header הראשי של החבילה שהגיעה
    struct iphdr *ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl * 4;

    // מצביע ל-ICMP Header מאחורי ה-IP Header
    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + ip_header_len);

    // הופכים את כתובת השולח למחרוזת
    inet_ntop(AF_INET, 
              &((struct sockaddr_in *)&sender)->sin_addr,
              sender_ip, 
              INET_ADDRSTRLEN);

    // בדיקה איזה TYPE קיבלנו
    if (icmp_header->type == ICMP_TIME_EXCEEDED)
    {
        // Time Exceeded -> יכול להעיד שה-ttl אזל בצומת בדרך
        // מחזירים 1 כדי שהלוגיקה בחוץ תדע להמשיך ל-hop הבא
        printf("%2d  from %s  %.3f ms (Time Exceeded)\n", index, sender_ip, *rtt);
        return 1;
    }
    else if (icmp_header->type == ICMP_ECHOREPLY)
    {
        // Echo Reply -> כנראה הגענו ליעד הסופי
        printf("%2d  from %s  %.3f ms (Echo Reply)\n", index, sender_ip, *rtt);
        return 2;
    }
    else
    {
        // חבילה מסוג אחר – לא רלוונטית לנו
        // אפשר להדפיס debug, או פשוט להתעלם (לחזור ערך 0)
        return 0;
    }
}

int main(int argc, char *argv[])
{
    // check if arduments in correct format
    //  <address> <protocol (4 or 6)>
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <address> <protocol (4 or 6)>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // setting the varriables and the mood :)
    char *address = argv[1];
    int protocol = atoi(argv[2]);

    if (protocol != 4)
    {
        fprintf(stderr, "Protocol must be 4 (IPv4) \n");
        exit(EXIT_FAILURE);
    }

    // socket creation
    int sock = create_raw_socket(protocol);

    // Setup destination address
    struct sockaddr_in dest4;
    void *dest;

    if (protocol == 4)
    {
        memset(&dest4, 0, sizeof(dest4));
        dest4.sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &dest4.sin_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv4 address: %s\n", address);
            exit(EXIT_FAILURE);
        }
        dest = &dest4;
    }

    // remmber the id of the process
    int id = getpid() & 0xFFFF;

    printf("Tracing route to [%s] over a maximum of %d hops:\n\n", address, MAX_HOPS);

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i <= MAX_HOPS; i++)
    {
        // Set TTL value

        // check if the destination is reached
        send_icmp_request(sock, dest, protocol, id, i);

        // check answer
        double rtt;
        int result = receive_icmp_reply(sock, id, protocol, &rtt, i);

        if (result == 1)
        {
            printf("%2d  %.3f ms\n", i, rtt);
        }
        else if (result == 2)
        { // Echo Reply
            printf("%2d  %.3f ms (destination reached)\n", i, rtt);
            break;
        }
        else
        {
            // printf("%2d  *\n", ttl); // Timeout
        }
    }

    close(sock);
    return 0;
}
