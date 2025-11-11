#include<iostream>
#include<vector>
#include<mutex>
#include<string>
#include<thread>
#include<WinSock2.h> 
#define _WIN32_WINNT 0x0600
#include<ws2tcpip.h>
#include<chrono>
#include<iomanip>
#include<sstream>
#include<windows.h>
#include <io.h>
#include <fcntl.h>
#include <codecvt>
#include <locale>
#pragma comment(lib, "ws2_32.lib") 

using namespace std;

SOCKET clientsocket;
sockaddr_in clientaddr;
bool server_running = true;

// UTF-16 <-> UTF-8 转换工具
wstring utf8_to_wstring(const string& str) {
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(str);
}
string wstring_to_utf8(const wstring& wstr) {
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

void Sendmessage(){//发送信息给服务器
    wcout<<L"输入消息发送给服务器，输入QUIT退出"<<endl;
    wstring wmsg;
    while(server_running){
        getline(wcin, wmsg);
        if(wmsg == L"QUIT") break; //QUIT退出
        string msg = wstring_to_utf8(wmsg);
        send(clientsocket, msg.c_str(), msg.size(), 0);
    }
}

void Receivemessage(){//接收服务器消息
    char buffer[1024];
    while(true){
        int ret = recv(clientsocket, buffer, sizeof(buffer)-1, 0);
        if(ret > 0){
            buffer[ret] = '\0';
            wstring wmsg = utf8_to_wstring(buffer);
            wcout << wmsg << endl;
        } else if(ret == 0){
            server_running = false;
            wcout<<L"服务器断开连接"<<endl;
            break;
        } else {
            server_running = false;
            wcout<<L"接收消息失败"<<endl;
            break;
        }
    }
}

bool Initsocket(){//初始化socket
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData)){
        wcout << L"启动失败" << endl;
        return false;
    }
    wcout<<L"启动成功" << endl;
    return true;
}
void Cleansocket(){//释放socket
    WSACleanup();
    closesocket(clientsocket);
    wcout<<L"关闭成功" << endl;
    return;
}
bool Createsocket(){//创建socket
    clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(clientsocket == INVALID_SOCKET){
        wcout << L"创建socket失败" << endl;
        Cleansocket();
        return false;
    }
    wcout << L"创建socket成功" << endl;
    return true;
}

bool Connectserver(){//连接服务器
    sockaddr_in serveraddr;
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(8080);
    inet_pton(AF_INET,"127.0.0.1",&serveraddr.sin_addr);

    if(connect(clientsocket, (SOCKADDR*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR){
        wcout<<L"连接失败"<<endl;
        Cleansocket();
        return false;
    }
    wcout<<L"成功连接"<<endl;
    thread t(Receivemessage);//启动接收消息线程
    t.detach();
    return true;
}

int main(){
    // 设置控制台输出为 UTF-16
    _setmode(_fileno(stdout), _O_U16TEXT);
    // 设置控制台输入为 UTF-16
    _setmode(_fileno(stdin), _O_U16TEXT);

    if(!Initsocket()) return 1;
    if(!Createsocket()) return 2;
    if(!Connectserver()) return 3;

    Sendmessage();

    Cleansocket();
    return 0;
}
