#include "server.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <direct.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

FILE* fopen_utf8(const char* filename, const char* mode) {
    int len = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    wchar_t* wfilename = new wchar_t[len];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, len);
    int mode_len = MultiByteToWideChar(CP_UTF8, 0, mode, -1, NULL, 0);
    wchar_t* wmode = new wchar_t[mode_len];
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, mode_len);
    FILE* fp = _wfopen(wfilename, wmode);
    delete[] wfilename;
    delete[] wmode;
    return fp;
}

#define SERVER_IP inet_addr("127.0.0.1")

void connection_loop(SOCKET sock, struct sockaddr_in* cliaddr, int* cliLen, uint32_t server_seq);

void server_run(int port) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SetConsoleOutputCP(CP_UTF8);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr, cliaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&servaddr, sizeof(servaddr));
    printf("Server running on port %d\n", port);

    int cliLen = sizeof(cliaddr);
    RDT_Packet pkt, send_pkt;

    uint32_t server_seq = rand() % 10000;

    while (1) {
        printf("等待连接\n");
        recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                 (struct sockaddr*)&cliaddr, &cliLen);
        printf("收到请求\n");

        // ---------- 校验 client -> server ----------
        PseudoHeader ph_recv;
        ph_recv.src_ip = cliaddr.sin_addr.s_addr;
        ph_recv.dst_ip = SERVER_IP;
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        uint16_t ck = pkt.checksum;
        pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length))
            continue;

        // ---------- SYN ----------
        if (pkt.flags & FLAG_SYN) {
            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = pkt.seq_num + 1;
            send_pkt.flags = FLAG_SYN | FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = 0;

            // ---------- server -> client ----------
            PseudoHeader ph_send;
            ph_send.src_ip = SERVER_IP;
            ph_send.dst_ip = cliaddr.sin_addr.s_addr;
            ph_send.zero = 0;
            ph_send.protocol = 17;
            ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)&cliaddr, cliLen);

            // ---------- 等 ACK ----------
            while (1) {
                recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                         (struct sockaddr*)&cliaddr, &cliLen);

                ck = pkt.checksum;
                pkt.checksum = 0;
                if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length))
                    continue;

                if ((pkt.flags & FLAG_ACK) && pkt.ack_num == server_seq + 1) {
                    printf("成功连接\n");
                    connection_loop(sock, &cliaddr, &cliLen, server_seq + 1);
                    return;
                }
            }
        }
    }
}

void connection_loop(SOCKET sock, struct sockaddr_in* cliaddr, int* cliLen, uint32_t server_seq) {
    RDT_Packet pkt, send_pkt;
    FILE* fp = NULL;
    uint32_t expected_seq = 0;
    int fileSize = 0;
    int total_received = 0;
    char filename[512] = {0};
    int stage = 0; // 0: 等文件名, 1: 等文件大小, 2: 数据传输

    _mkdir("./serverrecv");

    while (1) {
        //printf("**循环接收包\n");
        memset(&pkt, 0, sizeof(pkt));
        int recv_len = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                                (struct sockaddr*)cliaddr, cliLen);
        //printf("**收到包\n");
        if (recv_len <= 0) continue;

        // 校验伪头 + checksum
        PseudoHeader ph_recv;
        ph_recv.src_ip = cliaddr->sin_addr.s_addr;
        ph_recv.dst_ip = SERVER_IP;
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        uint16_t ck = pkt.checksum;
        pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length)) continue;

        // ---------- FIN ----------
        if (pkt.flags & FLAG_FIN) {
            PseudoHeader ph_send;
            ph_send.src_ip = SERVER_IP;
            ph_send.dst_ip = cliaddr->sin_addr.s_addr;
            ph_send.zero = 0;
            ph_send.protocol = 17;
            ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = pkt.seq_num + 1;
            send_pkt.flags = FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);

            send_pkt.flags = FLAG_FIN;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);

            if (fp) fclose(fp);
            printf("Connection closed\n");
            return;
        }

        // ---------- 文件名 ----------
        if (stage == 0) {
            memcpy(filename, pkt.truedata, pkt.length);
            filename[pkt.length] = 0; // 确保字符串结束
            printf("尝试接收文件: %s\n", filename);
            stage = 1;
            expected_seq = pkt.seq_num + pkt.length;

            // 发送 ACK
            PseudoHeader ph_send;
            ph_send.src_ip = SERVER_IP;
            ph_send.dst_ip = cliaddr->sin_addr.s_addr;
            ph_send.zero = 0;
            ph_send.protocol = 17;
            ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = expected_seq;
            send_pkt.flags = FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);
        }
        // ---------- 文件大小 ----------
        else if (stage == 1) {//printf("debug\n");
            char sizeStr[32] = {0};
            memcpy(sizeStr, pkt.truedata, pkt.length);
            sizeStr[pkt.length] = 0;
            fileSize = atoi(sizeStr);
            printf("文件大小: %d bytes\n", fileSize);

            char path[512];
            snprintf(path, sizeof(path), "./serverrecv/%s", filename);
            fp = fopen_utf8(path, "wb");
            if (!fp) {
                printf("Failed to open file %s\n", path);
                return;
            }
            stage = 2;
            expected_seq = pkt.seq_num + pkt.length;
            total_received = 0;

            // 发送 ACK
            PseudoHeader ph_send;
            ph_send.src_ip = SERVER_IP;
            ph_send.dst_ip = cliaddr->sin_addr.s_addr;
            ph_send.zero = 0;
            ph_send.protocol = 17;
            ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = expected_seq;
            send_pkt.flags = FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);
        }
        // ---------- 文件数据 ----------
        else if (stage == 2 && pkt.length > 0) {
            if (pkt.seq_num == expected_seq) {
                fwrite(pkt.truedata, 1, pkt.length, fp);
                total_received += pkt.length;
                expected_seq += pkt.length;
            } else {
                printf("Out-of-order or duplicate packet, seq = %u, expected = %u\n",
                       pkt.seq_num, expected_seq);
            }

            // 回复 ACK
            PseudoHeader ph_send;
            ph_send.src_ip = SERVER_IP;
            ph_send.dst_ip = cliaddr->sin_addr.s_addr;
            ph_send.zero = 0;
            ph_send.protocol = 17;
            ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

            send_pkt.seq_num = server_seq;
            send_pkt.ack_num = expected_seq;
            send_pkt.flags = FLAG_ACK;
            send_pkt.length = 0;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);

            // 检查是否接收完成
            if (total_received == fileSize) {
                printf("文件 %s 传输成功\n", filename);
                fclose(fp);
                fp = NULL;
                stage = 0;
            }
        }
    }
}



int main() {
    server_run(114);
    return 0;
}
