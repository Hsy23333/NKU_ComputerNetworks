#include "server.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

void server_run(int port) {//server端主体逻辑
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup失败\n");
        return;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket失败: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    struct sockaddr_in servaddr, cliaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR) {
        printf("bind失败: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return;
    }

    printf("Server running on port %d\n", port);

    RDT_Packet pkt;
    int cliLen = sizeof(cliaddr);

    while(1) {
        int n = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0, (struct sockaddr*)&cliaddr, &cliLen);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) continue;
            printf("recvfrom失败: %d\n", err);
            break;
        }

        further_run(sock,&cliaddr,&cliLen);
    }

    closesocket(sock);
    WSACleanup();
}

void further_run(SOCKET sock,struct sockaddr_in* cliaddr, int* cliLen){
    RDT_Packet pkt;
    RDT_Packet send_pkt;
    uint32_t server_seq = rand() % 10000; // 服务端初始序号

    //等待 SYN
    while (1) {
        int n = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0, (struct sockaddr*)cliaddr, cliLen);
        if (n == SOCKET_ERROR) continue;

        if (pkt.flags & FLAG_SYN) {
            printf("Received SYN from client, seq=%u\n", pkt.seq_num);

            //回复 SYN+ACK
            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = pkt.seq_num + 1;
            send_pkt.flags = FLAG_SYN | FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = 0;
            send_pkt.checksum = checksum(&send_pkt, sizeof(RDT_Packet));

            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0, (struct sockaddr*)cliaddr, *cliLen);
            printf("Sent SYN+ACK to client, seq=%u, ack=%u\n", send_pkt.seq_num, send_pkt.ack_num);

            //等待客户端 ACK
            while (1) {
                n = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0, (struct sockaddr*)cliaddr, cliLen);
                if (n == SOCKET_ERROR) continue;

                if ((pkt.flags & FLAG_ACK) && pkt.ack_num == server_seq + 1) {
                    printf("Received ACK from client, connection established!\n");
                    return;  //握手完成，返回后可以进入数据传输
                }
            }
        }
    }
}
