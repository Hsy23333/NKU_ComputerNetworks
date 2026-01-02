#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_DATA_SIZE 1024
#define WINDOW_SIZE 10

#define CLIENT_IP inet_addr("127.0.0.1")
#define SERVER_IP inet_addr("127.0.0.1")






// 控制位
#define FLAG_SYN 1
#define FLAG_ACK 2
#define FLAG_FIN 4

// -------------------------------
// 数据包
// -------------------------------
typedef struct {
    uint32_t seq_num;             // 序号
    uint32_t ack_num;             // 确认号
    uint16_t flags;               // SYN/ACK/FIN
    uint16_t length;              // 数据长度
    uint16_t checksum;            // 校验和
    char truedata[MAX_DATA_SIZE];     // 数据
} RDT_Packet;

// -------------------------------
// header
// -------------------------------
typedef struct {
    uint32_t src_ip;     // 源 IP
    uint32_t dst_ip;     // 目的 IP
    uint8_t zero;        // 保留 0
    uint8_t protocol;    // 协议号
    uint16_t length;     // 包长度（首部+数据）
} PseudoHeader;


// -------------------------------
// 发送 滑动窗口相关槽位
// -------------------------------
struct SendSlot {
    RDT_Packet pkt;      // 原始包
    uint64_t send_time;  // 最近一次发送时间
    int acked=-1;            // 是否被确认
};
// -------------------------------
// 发送 滑动窗口结构体
// -------------------------------
typedef struct {
    SendSlot slots[WINDOW_SIZE]; // 窗口格子
    int base;                    // 窗口头对应的 seq
    int next_seq;                // 下一个可发送 seq
    int count;                   // 当前窗口内包的数量
} SendWindow;//滑动窗口结构体



// -------------------------------
// 接收 滑动窗口相关槽位
// -------------------------------
typedef struct {
    RDT_Packet pkt;
    int received;  // 是否收到
} RecvSlot;
// -------------------------------
// 接收 滑动窗口结构体
// -------------------------------
typedef struct {
    RecvSlot slots[WINDOW_SIZE]; // 窗口格子
    uint32_t base_seq;                // 窗口头对应的 seq
    int count;                        // 当前窗口中有效包数量
} RecvWindow;



// -------------------------------
// 校验和函数
// -------------------------------
static inline uint16_t checksum_with_pseudo(PseudoHeader* ph, void* truedata, size_t len) {
    uint32_t retsum = 0;
    uint16_t* ph_ptr = (uint16_t*)ph;
    for (size_t i = 0; i < sizeof(PseudoHeader)>>1; ++i) retsum += ph_ptr[i];
    if (sizeof(PseudoHeader) % 2) retsum += ((uint8_t*)ph)[sizeof(PseudoHeader)-1];

    uint16_t* dataptr = (uint16_t*)truedata;
    for (size_t i = 0; i < len>>1; ++i) retsum += dataptr[i];
    if (len % 2) retsum += ((uint8_t*)truedata)[len-1];

    // 折叠进位
    while (retsum >> 16) retsum = (retsum & 0xFFFF) + (retsum >> 16);

    return ~retsum;
}

#endif // COMMON_H
