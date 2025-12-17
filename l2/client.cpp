#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup失败\n");
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket失败: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(114);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

    RDT_Packet pkt;
    RDT_Packet recv_pkt;
    socklen_t servLen = sizeof(servaddr);

    srand((unsigned int)time(NULL));
    uint32_t client_seq = rand() % 10000;

    // ------------------------------
    // 伪首部设置
    // ------------------------------
    PseudoHeader ph;
    ph.src_ip = inet_addr("127.0.0.1");  // 本机IP
    ph.dst_ip = servaddr.sin_addr.s_addr; // 服务端 IP
    ph.zero = 0;
    ph.protocol = 17;                     // UDP
    ph.length = htons(sizeof(RDT_Packet)); // 包长度（首部+数据）

    // ------------------------------
    // 发送 SYN
    // ------------------------------
    pkt.seq_num = client_seq;
    pkt.ack_num = 0;
    pkt.flags = FLAG_SYN;
    pkt.length = 0;
    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, sizeof(pkt));

    sendto(sock, (char*)&pkt, sizeof(pkt), 0, (struct sockaddr*)&servaddr, servLen);
    printf("Sent SYN to server, seq=%u\n", pkt.seq_num);

    // ------------------------------
    // 等待 SYN+ACK
    // ------------------------------
    while (1) {
        int n = recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0, (struct sockaddr*)&servaddr, &servLen);
        if (n == SOCKET_ERROR) continue;

        // 验证校验和
        uint16_t recv_ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (recv_ck != checksum_with_pseudo(&ph, &recv_pkt, sizeof(recv_pkt))) {
            printf("Received corrupted packet, discard\n");
            continue; // 丢弃错误包
        }

        // 验证 SYN+ACK
        if ((recv_pkt.flags & FLAG_SYN) && (recv_pkt.flags & FLAG_ACK) && recv_pkt.ack_num == client_seq + 1) {
            printf("Received SYN+ACK from server, seq=%u, ack=%u\n", recv_pkt.seq_num, recv_pkt.ack_num);

            // ------------------------------
            // 发送 ACK 完成握手
            // ------------------------------
            pkt.seq_num = client_seq + 1;
            pkt.ack_num = recv_pkt.seq_num + 1;
            pkt.flags = FLAG_ACK;
            pkt.length = 0;
            pkt.checksum = 0;
            pkt.checksum = checksum_with_pseudo(&ph, &pkt, sizeof(pkt));

            sendto(sock, (char*)&pkt, sizeof(pkt), 0, (struct sockaddr*)&servaddr, servLen);
            printf("Sent ACK to server, connection established!\n");
            break;  // 握手完成
        }
    }

    // ------------------------------
    // 准备继续发送数据
    // ------------------------------

    closesocket(sock);
    WSACleanup();
    return 0;
}
