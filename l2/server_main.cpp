#include "server.h"
#include <stdio.h>

//用于执行
int main() {
    int port = 114;//default
    printf("Starting server on port %d...\n", port);
    server_run(port);

    printf("Server stopped.\n");
    return 0;
}
