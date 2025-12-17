#ifndef SERVER_H
#define SERVER_H

#include "common.h"

void server_run(int port);//用于启动端口并监听
void further_run(SOCKET sock,struct sockaddr_in* cliaddr, int* cliLen);//用于三次握手建立连接

#endif
