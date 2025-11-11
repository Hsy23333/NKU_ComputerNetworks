#include<iostream>
#include<vector>
#include<mutex>
#include<algorithm>
#include<string>
#include<thread>
#define _WIN32_WINNT 0x0600
#include<WinSock2.h> 
#include<ws2tcpip.h>
#include<chrono>
#include<iomanip>
#include<sstream>
#include<windows.h>
#include <io.h>
#include <fcntl.h>
#pragma comment(lib, "ws2_32.lib") 
//#define WIN32_LEAN_AND_MEAN

using namespace std;


SOCKET serversocket;
sockaddr_in serveraddr;
vector<SOCKET> clientsockets;//多个客户端连接
mutex clientsmutex;//保护clientsockets的互斥锁

void Boardcastmessage(const string& msg){//广播消息给所有客户端
    lock_guard<mutex> lock(clientsmutex);


    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    stringstream timeStream;
    timeStream << "[" << put_time(localtime(&t), "%Y-%m-%d %H:%M:%S") << "] ";
    string fullmsg = timeStream.str()+msg;
    //获取时间戳并转换

    
    for(auto clientsocket : clientsockets){
        send(clientsocket, fullmsg.c_str(), fullmsg.size(), 0);
    }
}


void Handleclient(SOCKET clientsocket){//分配线程处理每个客户端
    char buffer[1024];
    while(true){
        int ret = recv(clientsocket, buffer, sizeof(buffer)-1, 0);
        if(ret > 0){
            buffer[ret] = '\0';
            string msg(buffer);


            auto now = chrono::system_clock::now();
            time_t t = chrono::system_clock::to_time_t(now);
            stringstream timeStream;
            timeStream << "[" << put_time(localtime(&t), "%Y-%m-%d %H:%M:%S") << "] ";
            //同样是时间戳

            wcout << L"收到消息: " << msg.c_str() << endl;
            Boardcastmessage(msg);
        } else if(ret == 0){
            wcout << L"客户端断开连接" << endl;
            break;
        } else {
            wcout << L"接收消息失败" << endl;
            break;
        }
    }
    closesocket(clientsocket);
    lock_guard<mutex> lock(clientsmutex);
    clientsockets.erase(std::remove(clientsockets.begin(), clientsockets.end(), clientsocket), clientsockets.end());
    //收尾
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
    closesocket(serversocket);
    wcout<<L"关闭成功" << endl;
    return;
}

bool Createsocket(){//创建socket
    serversocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(serversocket == INVALID_SOCKET){
        wcout << L"创建socket失败" << endl;
        Cleansocket();
        return false;
    }
    wcout << L"创建socket成功" << endl;
    return true;
}
bool Bindsocket(){//绑定socket
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serveraddr.sin_addr);//转换IP地址为可用格式后准备绑定
    if(bind(serversocket, (SOCKADDR*)&serveraddr, sizeof(serveraddr))==SOCKET_ERROR){
        wcout<<L"绑定socket失败" << endl;
        Cleansocket();
        return false;
    }
    wcout<<L"绑定socket成功" << endl;
    return true;
}
void Startlisten(){//监听socket
    listen(serversocket, SOMAXCONN);
    wcout<<L"监听socket中（ESC退出）" << endl;
    sockaddr_in clientaddr;//局部变量，每次连接完扔掉就行
    int tmp=sizeof(clientaddr);//accept需要
    u_long mode = 1;
    ioctlsocket(serversocket, FIONBIO, &mode);//将accept改为非阻塞，持续检测esc

    while(true){//循环接受客户端连接
        if (GetAsyncKeyState(VK_ESCAPE)) {
            wcout<<L"退出监听"<< endl;
            Boardcastmessage("服务器即将关闭。");

            {
                lock_guard<mutex> lock(clientsmutex);
                for (auto client : clientsockets) {
                    closesocket(client);//关闭客户端socket
                }
                clientsockets.clear(); // 清空列表
            }

            Sleep(1000);
            break;
        }


        SOCKET clientsocket = accept(serversocket, (SOCKADDR*)&clientaddr, &tmp);
        if(clientsocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if(err != WSAEWOULDBLOCK) {
                wcout << L"accept 出错: " << err << endl;
            }
            this_thread::sleep_for(chrono::milliseconds(100));//非阻塞空轮询休眠
            continue;
        }
        

        u_long mode = 0;
        ioctlsocket(clientsocket, FIONBIO, &mode);//将客户端socket改回阻塞模式
        lock_guard<mutex> lock(clientsmutex);
        clientsockets.push_back(clientsocket);
        wcout<<L"有新的客户端连接"<<endl;
        thread t(Handleclient,clientsocket); //分配新线程处理该客户端
        t.detach();//分离线程使其后台运行
    }
    
}

int main(){
    // 设置控制台输出为 UTF-16
    _setmode(_fileno(stdout), _O_U16TEXT);
    // 设置控制台输入为 UTF-16
    _setmode(_fileno(stdin), _O_U16TEXT);

    if(!Initsocket())   return 1;
    if(!Createsocket()) return 2;
    if(!Bindsocket()) return 3;
    Startlisten();

    Cleansocket();
    return 0;
}
