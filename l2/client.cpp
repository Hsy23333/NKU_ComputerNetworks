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



void sliding_window_send(int window_size,uint32_t *seq,FILE *fp,PseudoHeader ph,SOCKET sock,sockaddr_in *servaddr,socklen_t servLen){//滑动窗口发送端
    
    SendWindow win;
    memset(&win, 0, sizeof(win));
    win.base = *seq;  // 初始 seq
    win.next_seq = *seq;
    win.count = 0;
    //初始化窗口

    // ================== [Reno] 新增变量 ==================
    int cwnd = 1;                 // 拥塞窗口（以包为单位）
    int ssthresh = WINDOW_SIZE;   // 慢启动阈值
    uint32_t last_ack = win.base;
    int dup_ack_cnt = 0;
    // =====================================================

    char buf[512];
    size_t n;
    while((n = fread(buf, 1, sizeof(buf), fp))>0){//只要没发完就一直这么做

        // ================== [Reno] 限制发送窗口 ==================
        int send_limit = cwnd < WINDOW_SIZE ? cwnd : WINDOW_SIZE;
        if (win.count < send_limit) {
        // =========================================================
            SendSlot *slot = &win.slots[win.count];
            slot->pkt.seq_num = win.next_seq;
            slot->pkt.length = (uint16_t)n;
            memcpy(slot->pkt.truedata, buf, n);
            ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + slot->pkt.length);
            slot->pkt.checksum = 0;
            slot->pkt.checksum = checksum_with_pseudo(&ph, &slot->pkt, slot->pkt.length);
            //printf("length=%d",slot->pkt.length);
            slot->send_time = GetTickCount();
            slot->acked = -1;

            win.next_seq += n;
            win.count++;
        }

        //这一部分是滑动窗口固定时的逻辑
        RDT_Packet pkt;//暂存的server返回包
        while(1){
            if(!win.count)  break;//没有数据包

            //先传包
            for (int i = 0; i < win.count; i++) {
                SendSlot *slot = &win.slots[i];
                if (!slot->acked || slot->acked == -1) {//没被确认
                    if (GetTickCount() - slot->send_time > 500 || slot->acked == -1) {//超时重传，或第一次传输
                        if(slot->acked==0){
                            //printf("重传包，seq = %d\n", slot->pkt.seq_num);
                        }
                        else{
                            //printf("第一次传输包，seq = %d\n", slot->pkt.seq_num);
                        }

                        // ================== [Reno] 超时处理 ==================
                        if (GetTickCount() - slot->send_time > 500) {
                            ssthresh = cwnd / 2;
                            if (ssthresh < 1) ssthresh = 1;
                            cwnd = 1;
                            dup_ack_cnt = 0;
                        }
                        // =====================================================

                        slot->acked=0;//标记为传输过但未被确认

                        sendto(sock, (char*)&slot->pkt, sizeof(slot->pkt), 0,
                            (struct sockaddr*)servaddr, servLen);
                        slot->send_time = GetTickCount();
                    }
                }
            }

            //然后看看有没有server返回包
            memset(&pkt, 0, sizeof(pkt));
            int recvl=recvfrom(sock,(char*)&pkt,sizeof(pkt),0,(struct sockaddr*)servaddr,&servLen);
            //非阻塞地接收server返回包
            PseudoHeader ph_recv;
            ph_recv.src_ip = SERVER_IP;
            ph_recv.dst_ip = CLIENT_IP;
            ph_recv.zero = 0;
            ph_recv.protocol = 17;
            ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);
            int ck=checksum_with_pseudo(&ph_recv,&pkt,pkt.length);
            if(recvl==SOCKET_ERROR || ck!=pkt.checksum){//没收到包或包损坏，休息一小会继续检测即可
                if (recvl != SOCKET_ERROR) {
                    printf("校验和错误(计算得%d，应为%d)，跳过该包\n", ck, pkt.checksum);
                }
                continue;
            }
            else{//接收到返回包，更新slot确认情况

                // ================== [Reno] ACK 处理 ==================
                if (pkt.ack_num == last_ack) {
                    dup_ack_cnt++;
                    if (dup_ack_cnt == 3) {
                        // 快速重传
                        ssthresh = cwnd / 2;
                        if (ssthresh < 1) ssthresh = 1;
                        cwnd = ssthresh + 3;

                        SendSlot *slot = &win.slots[0];
                        sendto(sock, (char*)&slot->pkt, sizeof(slot->pkt), 0,
                               (struct sockaddr*)servaddr, servLen);
                        slot->send_time = GetTickCount();
                    }
                }
                else if (pkt.ack_num > last_ack) {
                    last_ack = pkt.ack_num;
                    dup_ack_cnt = 0;

                    if (cwnd < ssthresh) {
                        cwnd++;          // 慢启动
                    } else {
                        cwnd += 1 / cwnd; // 拥塞避免（近似）
                    }
                }
                // =====================================================

                for(int i=0;i<win.count;++i){
                    SendSlot *slot=&win.slots[i];
                    if(slot->pkt.seq_num==pkt.ack_num){
                        slot->acked=1;
                        break;
                    }
                }
            }

            if(win.slots[0].acked==1){
                //如果窗口头被确认，滑动窗口
                win.base+=win.slots[0].pkt.length;
                for(int i=0;i<win.count-1;i++){
                    win.slots[i]=win.slots[i+1];
                }
                --win.count;
                break;//出去继续读取下一包准备发送
            }
        }
    }
}



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

// ================== 关闭连接 ==================
void close_connection(SOCKET sock, struct sockaddr_in* servaddr, socklen_t servLen,
                      uint32_t* seq, uint32_t server_seq) {
    RDT_Packet pkt, recv_pkt;
    printf("正在关闭连接\n");

    // ---- FIN ----
    pkt.seq_num = *seq;
    pkt.ack_num = server_seq;
    pkt.flags   = FLAG_FIN;
    pkt.length  = 0;

    //计算校验和使用的长度（照文件发送逻辑）
    int pkt_len = sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length;

    //构造伪头部（与文件发送保持一致）
    PseudoHeader ph;
    ph.src_ip   = CLIENT_IP;
    ph.dst_ip   = servaddr->sin_addr.s_addr;
    ph.zero     = 0;
    ph.protocol = 17; // UDP
    ph.length   = htons(pkt_len);

    //清空数据区（防止未初始化导致 checksum 不一致）
    memset(pkt.truedata, 0, MAX_DATA_SIZE);

    // 计算 checksum（与文件发送一致）
    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    //printf("pkt.length = %d\n", pkt_len);

    printf("发送FIN，校验和(%d)\n", pkt.checksum);

    sendto(sock, (char*)&pkt, pkt_len, 0,
        (struct sockaddr*)servaddr, servLen);



    // ---- 等 ACK ----
    while (1) {
        printf("等待ACK\n");
        Sleep(1200);
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){
            printf("未收到ACK包，重发FIN\n");
            sendto(sock, (char*)&pkt, pkt_len, 0,
                (struct sockaddr*)servaddr, servLen);
            continue;
        }
        
        printf("收到包\n");


        PseudoHeader ph_recv;
        ph_recv.src_ip = SERVER_IP;        // server 真正 IP
        ph_recv.dst_ip = CLIENT_IP;        // client IP
        ph_recv.zero   = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)) {
            printf("校验和错误(%d)，应为(%d)，重发FIN\n", checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length), ck);
            sendto(sock, (char*)&pkt, pkt_len, 0,
                (struct sockaddr*)servaddr, servLen);
            continue;
        }
  

        if ((recv_pkt.flags & FLAG_ACK) &&
            recv_pkt.ack_num == *seq + 1)
            break;
    }

    // ---- 等 server FIN ----
    while (1) {//事实上在现在的框架里，由于server->client不会丢包，所以这一部分不会重传
        printf("等待server FIN\n");
        //Sleep(1200);
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){
            printf("未收到server FIN包，重发FIN\n");
            // ---- FIN ----
            pkt.seq_num = *seq;
            pkt.ack_num = server_seq;
            pkt.flags   = FLAG_FIN;
            pkt.length  = 0;
            int pkt_len = sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length;
            PseudoHeader ph;
            ph.src_ip   = CLIENT_IP;
            ph.dst_ip   = servaddr->sin_addr.s_addr;
            ph.zero     = 0;
            ph.protocol = 17; // UDP
            ph.length   = htons(pkt_len);
            memset(pkt.truedata, 0, MAX_DATA_SIZE);
            pkt.checksum = 0;
            pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);

            sendto(sock, (char*)&pkt, pkt_len, 0,
                (struct sockaddr*)servaddr, servLen);
            continue;
        }
        
        

        PseudoHeader ph_recv;
        ph_recv.src_ip = SERVER_IP;        // server 真正 IP
        ph_recv.dst_ip = CLIENT_IP;        // client IP
        ph_recv.zero   = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)) {
                // ---- FIN ----
            pkt.seq_num = *seq;
            pkt.ack_num = server_seq;
            pkt.flags   = FLAG_FIN;
            pkt.length  = 0;
            int pkt_len = sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length;
            PseudoHeader ph;
            ph.src_ip   = CLIENT_IP;
            ph.dst_ip   = servaddr->sin_addr.s_addr;
            ph.zero     = 0;
            ph.protocol = 17; // UDP
            ph.length   = htons(pkt_len);
            memset(pkt.truedata, 0, MAX_DATA_SIZE);
            pkt.checksum = 0;
            pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);

            sendto(sock, (char*)&pkt, pkt_len, 0,
                (struct sockaddr*)servaddr, servLen);
            printf("校验和错误(%d)，应为(%d)，重发FIN\n", checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length), ck);
            continue;
        }

        printf("收到包，继续发送最后一次挥手\n");

        if (recv_pkt.flags & FLAG_FIN) {//printf("???");
            while(1){
                pkt.seq_num = *seq + 1;
                pkt.ack_num = recv_pkt.seq_num + 1;
                pkt.flags = FLAG_ACK;
                pkt.length = 0;

                // 构造新的伪首部
                PseudoHeader ph;
                ph.src_ip   = CLIENT_IP;
                ph.dst_ip   = SERVER_IP;
                ph.zero     = 0;
                ph.protocol = 17; // UDP
                ph.length   = htons(pkt_len);

                pkt.checksum = 0;
                pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);

                sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                    (struct sockaddr*)servaddr, servLen);
                Sleep(1200);

                memset(&recv_pkt, 0, sizeof(recv_pkt));
                int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                         (struct sockaddr*)servaddr, &servLen);
                if(recl<=0 || recl==SOCKET_ERROR){//没收到，可以断开
                    break;
                }//否则重发ACK
            }
            
            //printf("发送包信息: seq_num=%u, ack_num=%u, flags=%u, length=%u, checksum=%u\n", pkt.seq_num, pkt.ack_num, pkt.flags, pkt.length, pkt.checksum);
            break;
        }
    }
    printf("连接已关闭,5000ms后回退\n");
    Sleep(5000);
}

void send_file(SOCKET sock, struct sockaddr_in* servaddr, socklen_t servLen,
               uint32_t* seq, uint32_t server_seq,
               const char* filename) {

    FILE* fp = fopen_utf8(filename, "rb");
    if (!fp) {
        printf("无法打开文件 %s\n", filename);
        return;
    }

    DWORD start_time = GetTickCount();//开始计时

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

    printf("尝试开始发送文件：%s\n", filename);
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
        Sleep(1200);
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){
            printf("未收到文件名ACK包，重发文件名\n");
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);
            continue;
        }


        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;

        ph_recv.src_ip = SERVER_IP;
        ph_recv.dst_ip = CLIENT_IP;
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)){
            printf("校验和错误(%d)，应为(%d)，重发文件名\n", checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length), ck);
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);
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

    ph_recv.src_ip = SERVER_IP;
    ph_recv.dst_ip = CLIENT_IP;
    ph_recv.zero = 0;
    ph_recv.protocol = 17;
    ph.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + pkt.length);

    pkt.checksum = 0;
    pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
    printf("发送文件大小：%s 字节\n", sizeStr);
    sendto(sock, (char*)&pkt, sizeof(pkt), 0,
           (struct sockaddr*)servaddr, servLen);

    // 等 ACK
    while (1) {
        Sleep(1200);
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                 (struct sockaddr*)servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){
            printf("未收到文件大小ACK包，重发文件大小\n");
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);
            continue;
        }

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE + recv_pkt.length);
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)){
            printf("校验和错误(%d)，应为(%d)，重发文件大小\n", checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length), ck);
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                   (struct sockaddr*)servaddr, servLen);
            continue;
        }
            

        if ((recv_pkt.flags & FLAG_ACK) &&
            recv_pkt.ack_num == *seq + pkt.length)
            break;
    }

    *seq += pkt.length;

    // ---------- 发送文件数据 ----------
    sliding_window_send(WINDOW_SIZE, seq, fp, ph, sock, servaddr, servLen);

    fclose(fp);



    DWORD end_time = GetTickCount();
    double elapsed_sec = (end_time - start_time) / 1000.0;
    double throughput = fileSize / elapsed_sec / 1024.0; // KB/s
    printf("文件 %s 传输成功\n", filename);
    printf("客户端传输总时间: %.2f 秒\n", elapsed_sec);
    printf("平均吞吐率: %.2f KB/s\n", throughput);
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
    servaddr.sin_addr.s_addr = inet_addr("192.168.56.1");//router，not server
    socklen_t servLen = sizeof(servaddr);

    srand((unsigned)time(NULL));
    uint32_t client_seq = rand() % 10000;
    uint32_t server_seq = 0;


    u_long mode=1;
    ioctlsocket(sock, FIONBIO, &mode);//设置非阻塞模式

    RDT_Packet pkt, recv_pkt;
    PseudoHeader ph;

    // ---------- SYN ----------
    ph.src_ip = CLIENT_IP;
    ph.dst_ip = inet_addr("192.168.56.1");
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
        printf("等待SYN+ACK\n");
        Sleep(1200);
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                (struct sockaddr*)&servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){
            printf("未收到SYN+ACK包，重发SYN\n");
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,(struct sockaddr*)&servaddr, servLen);
            continue;
        }
        printf("Received packet, checksum: %d\n", recv_pkt.checksum);

        PseudoHeader ph_recv;
        ph_recv.src_ip = SERVER_IP; // server IP
        ph_recv.dst_ip = CLIENT_IP;                // client IP
        ph_recv.zero = 0;
        ph_recv.protocol = 17;
        ph_recv.length = htons(sizeof(RDT_Packet) - MAX_DATA_SIZE);

        uint16_t ck = recv_pkt.checksum;
        recv_pkt.checksum = 0;
        if (ck != checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length)){
            printf("校验和错误(%d)应为(%d)，重发SYN\n", checksum_with_pseudo(&ph_recv, &recv_pkt, recv_pkt.length), ck);
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,(struct sockaddr*)&servaddr, servLen);
            continue;
        }
            

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

    while(1){//根据是否接到到SYN+ACK包来判断ACK是否丢失
        Sleep(1200);
        memset(&recv_pkt, 0, sizeof(recv_pkt));
        int recl=recvfrom(sock, (char*)&recv_pkt, sizeof(recv_pkt), 0,
                (struct sockaddr*)&servaddr, &servLen);
        if(recl<=0 || recl==SOCKET_ERROR){//未收到，连接成功
            break;
        }
        else{
            printf("收到SYN+ACK包，需要重发ACK\n");
            pkt.seq_num = client_seq + 1;
            pkt.ack_num = server_seq + 1;
            pkt.flags = FLAG_ACK;
            pkt.length = 0;
            pkt.checksum = 0;
            pkt.checksum = checksum_with_pseudo(&ph, &pkt, pkt.length);
            sendto(sock, (char*)&pkt, sizeof(pkt), 0,
                (struct sockaddr*)&servaddr, servLen);
        }
    }
    




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