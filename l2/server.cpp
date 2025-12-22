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



void sliding_window_recv(FILE *fp, SOCKET sock, sockaddr_in *cliaddr, socklen_t *cliLen, PseudoHeader ph, char *filename, int *stage, int fileSize, uint32_t base_seq){
    int total_received=0;
    
    u_long mode=1;
    ioctlsocket(sock, FIONBIO, &mode);//设置非阻塞模式，记得文件结束后改回来
    
    RecvWindow win;
    memset(&win, 0, sizeof(win));
    win.base_seq = base_seq;  // 初始期望 seq
    win.count = 0;

    while (1) {
        RDT_Packet pkt;
        int recvl = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                             (struct sockaddr*)cliaddr, cliLen);
        if (recvl==SOCKET_ERROR || recvl <= 0) {
            //printf("未收到包，等待\n");//Sleep(100000);
            //Sleep(100);
            continue;
        } // 没收到包

        // 更新伪首部长度
        ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        PseudoHeader ph_recv;
        ph_recv.src_ip = cliaddr->sin_addr.s_addr;
        ph_recv.dst_ip = inet_addr("192.168.56.1");
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        uint16_t ck = pkt.checksum;
        pkt.checksum = 0;
        uint16_t calc_ck = checksum_with_pseudo(&ph_recv, &pkt, pkt.length);
        if (ck != calc_ck) {
            //printf("Debug: ph.src_ip=%u, ph.dst_ip=%u, ph.zero=%u, ph.protocol=%u, ph.length=%u\n", ph.src_ip, ph.dst_ip, ph.zero, ph.protocol, ntohs(ph.length));
            //printf("Debug: pkt.seq_num=%u, pkt.ack_num=%u, pkt.flags=%u, pkt.length=%u\n", pkt.seq_num, pkt.ack_num, pkt.flags, pkt.length);
            printf("校验和错误(计算得%d，应为%d)，跳过该包，seq=%u\n", calc_ck, ck, pkt.seq_num);
            continue;
        }

        // 计算 pkt 在窗口中的 slot 下标
        int offset = (pkt.seq_num - win.base_seq) / 1; // 注意这里单位：以字节还是包？通常用包长度计算
        if (offset < 0 || offset >= WINDOW_SIZE) {
            // 超出窗口范围，丢弃
            printf("[SERVER] 超出窗口范围，seq=%u\n", pkt.seq_num);
            continue;
        }

        RecvSlot *slot = &win.slots[offset];
        if (!slot->received) {
            slot->pkt = pkt;
            slot->received = 1;
            win.count++;
            //printf("[SERVER] 收到包 seq=%u\n", pkt.seq_num);
        } else {
            //printf("[SERVER] 重复包 seq=%u\n", pkt.seq_num);
        }

        // 发送选择确认 ACK
        RDT_Packet ack_pkt;
        memset(&ack_pkt, 0, sizeof(ack_pkt));
        ack_pkt.seq_num = 0; // server seq，似乎这里没什么用
        ack_pkt.ack_num = pkt.seq_num; // ack 对应收到的 seq
        ack_pkt.flags = FLAG_ACK;
        ack_pkt.length = 0;
        PseudoHeader ph_send;
        ph_send.src_ip = SERVER_IP;
        ph_send.dst_ip = cliaddr->sin_addr.s_addr;
        ph_send.zero = 0;
        ph_send.protocol = 17;
        ph_send.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);
        ack_pkt.checksum = checksum_with_pseudo(&ph_send, &ack_pkt, ack_pkt.length);
        sendto(sock, (char*)&ack_pkt, sizeof(ack_pkt), 0, (struct sockaddr*)cliaddr, *cliLen);

        // 检查窗口头是否已收到，如果收到就写入文件并滑动窗口
        while (win.slots[0].received) {
            fwrite(win.slots[0].pkt.truedata, 1, win.slots[0].pkt.length, fp);
            win.base_seq = win.slots[0].pkt.seq_num + win.slots[0].pkt.length;
            total_received += pkt.length;

            // 窗口滑动
            for (int i = 0; i < WINDOW_SIZE - 1; i++)    win.slots[i] = win.slots[i + 1];
            win.slots[WINDOW_SIZE - 1].received = 0;
            win.count--;
        }

        if (total_received == fileSize) {//传输完毕
            printf("文件 %s 传输成功\n", filename);
            fclose(fp);
            fp = NULL;
            stage = 0;
            break;
        }
    }

    mode=0;
    ioctlsocket(sock, FIONBIO, &mode);//改回阻塞模式便于挥手
}




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
        ph_recv.dst_ip = inet_addr("192.168.56.1");
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        uint16_t ck = pkt.checksum;
        pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length)){
            printf("校验和错误(%d)，应为(%d)，跳过该包\n",checksum_with_pseudo(&ph_recv, &pkt, pkt.length),ck);
            continue;
        }
            

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
    uint32_t client_data_base = 0;

    _mkdir("./serverrecv");

    while (1) {
        //printf("**循环接收包\n");
        memset(&pkt, 0, sizeof(pkt));
        int recv_len = recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                                (struct sockaddr*)cliaddr, cliLen);
        //printf("**收到包\n");
        //printf("[SERVER] recv_len = %d\n", recv_len);
        //printf("[SERVER] checksum offset = %zu\n",
        //    offsetof(RDT_Packet, checksum));
        if (recv_len <= 0) continue;

        // 校验伪头 + checksum
        PseudoHeader ph_recv;
        ph_recv.src_ip = cliaddr->sin_addr.s_addr;
        ph_recv.dst_ip = inet_addr("192.168.56.1");
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

        //printf("pkt.length=%d\n",pkt.length);
        uint16_t ck = pkt.checksum;
        pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length)){
            //printf("length=%d",pkt.length);
            printf("校验和错误(%d)，应为(%d)，跳过该包\n",checksum_with_pseudo(&ph_recv, &pkt, pkt.length),ck);
            continue;
        }

        // ---------- FIN ----------
        if (pkt.flags & FLAG_FIN) {
            printf("收到 FIN，准备回传挥手ACK\n");
            Sleep(500);
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

            printf("回传后，等待发送第三次挥手\n");
            Sleep(500);

            send_pkt.flags = FLAG_FIN;
            send_pkt.checksum = checksum_with_pseudo(&ph_send, &send_pkt, send_pkt.length);
            sendto(sock, (char*)&send_pkt, sizeof(send_pkt), 0,
                   (struct sockaddr*)cliaddr, *cliLen);

            if (fp) fclose(fp);
            printf("发送了第三次，等待客户端回应第四次ACK\n");
            Sleep(500);
            while(1){
                memset(&pkt, 0, sizeof(pkt));
                recv_len=recvfrom(sock, (char*)&pkt, sizeof(pkt), 0,
                                (struct sockaddr*)cliaddr, cliLen);
                if (recv_len <= 0) continue;


                PseudoHeader ph_recv;
                ph_recv.src_ip = CLIENT_IP;  // client 真正 IP
                ph_recv.dst_ip = SERVER_IP;                 // server 自己 IP
                ph_recv.zero = 0;
                ph_recv.protocol = 17;
                // 注意：checksum 长度 = sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length
                ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

                // 不要 memset pkt.truedata，保持接收到的原样
                uint16_t ck = pkt.checksum;
                pkt.checksum = 0;
                //printf("len=%d???/n", (sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length));
                if (ck != checksum_with_pseudo(&ph_recv, &pkt, pkt.length)){
                    printf("校验和错误(%d)，应为(%d)，跳过该包\n",
                        checksum_with_pseudo(&ph_recv, &pkt, pkt.length), ck);
                    //printf("包信息: seq_num=%u, ack_num=%u, flags=%u, length=%u, checksum=%u\n", pkt.seq_num, pkt.ack_num, pkt.flags, pkt.length, pkt.checksum);
                    continue;
                }

                printf("收到ACK，准备关闭\n");
                break;
            }
            printf("连接成功关闭,5000ms后回退\n");
            Sleep(5000);
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
            client_data_base = pkt.seq_num + pkt.length;
            expected_seq = client_data_base;
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
            printf("准备进入文件传输\n");

            //在这里就开始滑动窗口接收
            sliding_window_recv(fp, sock, cliaddr, cliLen, ph_recv, filename, &stage, fileSize, client_data_base);
            stage=0;
        }
        // ---------- 文件数据 ----------
        else if (stage == 2 && pkt.length > 0) {
        printf("ERROR:不应该出现在这里\n");


        }
    }
}



int main() {
    server_run(115);
    return 0;
}
