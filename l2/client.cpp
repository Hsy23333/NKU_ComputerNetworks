#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <time.h>
#include <conio.h>
#include <stdio.h>
#include <iostream>
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

#define CLIENT_IP inet_addr("127.0.0.1")

// ================== 关闭连接 ==================
void close_connection(SOCKET sock, struct sockaddr_in* servaddr, socklen_t servLen,
                      uint32_t* seq, uint32_t server_seq) {
    RDT_Packet pkt, recv_pkt;
    printf("正在关闭连接\n");

    // ---- FIN ----
    pkt.seq_num = *seq;
    pkt.ack_num = server_seq;
    pkt.flags = FLAG_FIN;
    pkt.length = 0;

    PseudoHeader ph;
    ph.src_ip = CLIENT_IP;
    ph.dst_ip = servaddr->sin_addr.s_addr;
    ph.zero = 0;
    ph.protocol = 17;
    ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

    memset(pkt.truedata + pkt.length, 0, MAX_DATA_SIZE - pkt.length);
    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, sizeof(pkt));
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)servaddr, servLen);

    // ---- 等 ACK ----
    while (1) {//std::cout<<"111";
        recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);

        memset(recv_pkt.truedata + recv_pkt.length, 0, MAX_DATA_SIZE - recv_pkt.length);
        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph, &recv_pkt, sizeof(recv_pkt)))
            continue;

        if ((recv_pkt.flags & FLAG_ACK) &&
            recv_pkt.ack_num == *seq + 1)
            break;
    }

    // ---- 等 server FIN ----
    while (1) {//std::cout<<"222";
        recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph, &recv_pkt, recv_pkt.length))
            continue;

        if (recv_pkt.flags & FLAG_FIN) {
            pkt.seq_num = *seq + 1;
            pkt.ack_num = recv_pkt.seq_num + 1;
            pkt.flags = FLAG_ACK;
            pkt.length = 0;
            pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);
            break;
        }
    }
}

void send_file(SOCKET sock, struct sockaddr_in* servaddr, socklen_t servLen,
               uint32_t* seq, uint32_t server_seq,
               const char* filename) {

    FILE* fp = fopen_utf8(filename, "rb");
    if (!fp) {
        printf("无法打开文件 %s\n", filename);
        return;
    }

    RDT_Packet pkt, recv_pkt;
    PseudoHeader ph;

    ph.src_ip = CLIENT_IP;
    ph.dst_ip = servaddr->sin_addr.s_addr;
    ph.zero = 0;
    ph.protocol = 17;

    PseudoHeader ph_recv;
    ph_recv.src_ip = servaddr->sin_addr.s_addr;
    ph_recv.dst_ip = CLIENT_IP;
    ph_recv.zero = 0;
    ph_recv.protocol = 17;

    printf("开始发送文件：%s\n", filename);
    // ---------- 发送文件名 ----------
    pkt.seq_num = *seq;
    pkt.ack_num = server_seq;
    pkt.flags = 0;
    pkt.length = (uint16_t)strlen(filename);
    memcpy(pkt.truedata, filename, pkt.length);

    ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)servaddr, servLen);

    // 等 ACK
    while (1) {
        printf("等待文件名ACK\n");
        recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);
        
        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)){
            printf("文件名ACK校验失败\n");
            continue;
        }
            

        if ((recv_pkt.flags & FLAG_ACK) &&
            recv_pkt.ack_num == *seq + pkt.length)
            break;
    }

    *seq += pkt.length;

    // ---------- 发送文件大小 ----------
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char sizeStr[32];
    snprintf(sizeStr, sizeof(sizeStr), "%ld", fileSize);

    pkt.seq_num = *seq;
    pkt.ack_num = server_seq;
    pkt.flags = 0;
    pkt.length = (uint16_t)strlen(sizeStr);
    memcpy(pkt.truedata, sizeStr, pkt.length);

    ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    printf("发送文件大小：%s 字节\n", sizeStr);
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)servaddr, servLen);

    // 等 ACK
    while (1) {
        recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length))
            continue;

        if ((recv_pkt.flags & FLAG_ACK) &&
            recv_pkt.ack_num == *seq + pkt.length)
            break;
    }

    *seq += pkt.length;

    // ---------- 发送文件数据 ----------
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        pkt.seq_num = *seq;
        pkt.ack_num = server_seq;
        pkt.flags = 0;
        pkt.length = (uint16_t)n;
        memcpy(pkt.truedata, buf, n);

        ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        pkt.checksum = 0;
        pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);

        int acked = 0;
        while (!acked) {
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);

            clock_t start = clock();
            while (clock() - start < 500 * CLOCKS_PER_SEC / 1000) {
                int rn = recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                                  (struct sockaddr*)servaddr, &servLen);
                if (rn <= 0) continue;

                uint16_t ck = recv_pkt.checksum;
                recv_pkt.checksum = 0;
                ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);
                if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length))
                    continue;

                if ((recv_pkt.flags & FLAG_ACK) &&
                    recv_pkt.ack_num == *seq + n) {
                    acked = 1;
                    break;
                }
            }
        }
        *seq += n;
    }

    fclose(fp);
    printf("文件 %s 传输成功\n", filename);
}



// ================== main ==================
int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(114);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    socklen_t servLen = sizeof(servaddr);

    srand((unsigned)time(NULL));
    uint32_t client_seq = rand() % 10000;
    uint32_t server_seq = 0;

    RDT_Packet pkt, recv_pkt;
    PseudoHeader ph;

    // ---------- SYN ----------
    ph.src_ip = CLIENT_IP;
    ph.dst_ip = servaddr.sin_addr.s_addr;
    ph.zero = 0;
    ph.protocol = 17;
    ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

    pkt.seq_num = client_seq;
    pkt.ack_num = 0;
    pkt.flags = FLAG_SYN;
    pkt.length = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)&servaddr, servLen);

    // ---------- SYN+ACK ----------
    while (1) {
        recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                (struct sockaddr*)&servaddr, &servLen);

        PseudoHeader ph_recv;
        ph_recv.src_ip = servaddr.sin_addr.s_addr; // server IP
        ph_recv.dst_ip = CLIENT_IP;                // client IP
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length))
            continue;

        if ((recv_pkt.flags & FLAG_SYN) && (recv_pkt.flags & FLAG_ACK)) {
            printf("Received SYN+ACK\n");
            server_seq = recv_pkt.seq_num;
            break;
        }
    }

    // ---------- ACK ----------
    pkt.seq_num = client_seq + 1;
    pkt.ack_num = server_seq + 1;
    pkt.flags = FLAG_ACK;
    pkt.length = 0;
    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)&servaddr, servLen);
    printf("连接成功\n");







    // ---------- 文件交互 ----------
    while (1) {
        char filename[256];
        printf("输入文件名（end 结束）：");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\r\n")] = 0;
        if (strcmp(filename, "end") == 0) break;
        printf("尝试传输文件...\n");
        send_file(sock, &servaddr, servLen, &client_seq, server_seq, filename);
    }

    close_connection(sock, &servaddr, servLen, &client_seq, server_seq);

    closesocket(sock);
    WSACleanup();
    return 0;
}
