#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib,"ws2_32.lib")

#define NULL_FLAG 0
#define MAX_BUFFER_LENGTH 512

#define IFACE INADDR_ANY
#define PORT 16000

typedef struct _server_config_t {
    USHORT port;
    USHORT max_connections;
} ServerConfig;

int32_t read_socket(SOCKET socket, char *buffer, uint16_t count) {
    int32_t totalRecv = 0;
    int32_t r = 0;

    while (totalRecv < count) {
        r = recv(socket, buffer + totalRecv, count - totalRecv, NULL_FLAG);
    
        if (r == SOCKET_ERROR) {
            printf("[x] Error: recv failed, error code %i.\n", WSAGetLastError());
            return -1;
        } else if (r == 0) {
            break;
        }
    
        totalRecv += r;
    }

    return totalRecv;
}

int32_t write_socket(SOCKET socket, char *buffer, uint16_t count) {
    int32_t totalSent = 0;
    int32_t s = 0;

    while (totalSent < count) {
        s = send(socket, buffer + totalSent, count - totalSent, NULL_FLAG);

        if (s == SOCKET_ERROR) {
            printf("[x] Error: write failed, error code %i.\n", WSAGetLastError());
            return -1;
        } else if (s == 0) {
            break;
        }
    
        totalSent += s;
    }
  
  return totalSent;
}

void Echo(SOCKET clientSocket) {
    uint8_t buffer[MAX_BUFFER_LENGTH];

    uint16_t len = 0;

    // Read text length to len and text itself to buffer.
    printf("[*] Reading text length.\n");
    read_socket(clientSocket, (char*)&len, sizeof(uint16_t));
  
    printf("[*] Reading 0x%x bytes from socket.\n", len);
    read_socket(clientSocket, (char*)buffer, len);

    // Echo len bytes from text and finish connection with client.
    printf("[*] Sending 0x%x bytes through socket.\n", len);
    write_socket(clientSocket, (uint8_t*)buffer, len);
}

SOCKET InitializeServer(WSADATA *wsaData, ServerConfig *config) {
    SOCKET returned;
    
    if (WSAStartup(MAKEWORD(2,2), wsaData) != 0) {
        return INVALID_SOCKET;
    }
    
    struct sockaddr_in server_address;
    ZeroMemory(&server_address, sizeof(server_address));
    
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(IFACE);
    server_address.sin_port = htons(config->port);
    
    SOCKET listener;

    if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        returned = INVALID_SOCKET;
        goto initialize_listener_cleanup_exit;
    };
    
    if (bind(listener, (struct sockaddr *)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
        returned = INVALID_SOCKET;
        goto initialize_listener_close_socket_exit;
    };
    
    if(listen(listener, config->max_connections) == SOCKET_ERROR) {
        returned = INVALID_SOCKET;
        goto initialize_listener_close_socket_exit;
    }
    
    returned = listener;
    goto initialize_listener_clean_exit;
    
    initialize_listener_close_socket_exit:
    closesocket(listener);
    
    initialize_listener_cleanup_exit:
    WSACleanup();
    
    initialize_listener_clean_exit:
    return returned;
}

int main(int argc, char **argv) {
    ServerConfig config;
    config.port = PORT;
    config.max_connections = 10;
    
    WSADATA wsaData;
  
    SOCKET serverSocket;
    SOCKET clientSocket;
    
    if ((serverSocket = InitializeServer(&wsaData, &config)) == INVALID_SOCKET) {
        return 1;
    } else {
        for (;;) {            
            if ((clientSocket = accept(serverSocket, NULL, NULL)) == INVALID_SOCKET) {
                break;
            }
            
            printf("[*] Connection accepted.\n");
            Echo(clientSocket);
            
            printf("[*] Closing socket.\n");
            closesocket(clientSocket);
            
        }
        closesocket(serverSocket);
        WSACleanup();
    }
}
