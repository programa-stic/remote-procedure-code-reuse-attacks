/*
 * Remote Procedure Code Reuse Attacks
 * 
 * @author: Adrián Barreal
 *
 */

/* This file connection.c, along with connection.h, define plain networking boilerplate. 
 * There is nothing particularly interesting in here.
 *
 */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdbool.h>

#pragma comment(lib,"ws2_32.lib")

#include "connection.h"

#define NULL_FLAG 0

static SOCKET open_socket = INVALID_SOCKET;

static struct sockaddr_in server_address;

static WSADATA wsa_data;

static bool networking_up = false;

int32_t initialize_networking() {
    if (WSAStartup(MAKEWORD(2,2), &wsa_data) != 0) {
        return -WSAGetLastError();
    } else {
        networking_up = true;
        return 0;
    }
}

void shutdown_networking() {
    closesocket(open_socket);
    WSACleanup();
    networking_up = false;
}

void configure_target_address(char *ip_address, USHORT port) {
    ZeroMemory(&server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &server_address.sin_addr);
}

int32_t establish_connection() {
    if (!networking_up && initialize_networking() < 0) {
        return -WSAGetLastError();
    }
    
    if ((open_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        return -WSAGetLastError();
    }
    if (connect(open_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
        return -WSAGetLastError();
    }
    
    return 0;
}

int32_t close_connection() {
    int32_t r_value = 0;
    if (closesocket(open_socket) == SOCKET_ERROR) {
        r_value = -WSAGetLastError();
    }
    open_socket = INVALID_SOCKET;
    return r_value;
}

int32_t read_response(uint8_t *buffer, uint16_t count) {
    int32_t totalRecv = 0;
    int32_t r = 0;
    while (totalRecv < count) {
        r = recv(open_socket, buffer + totalRecv, count - totalRecv, NULL_FLAG);
        if (r == SOCKET_ERROR) {
            return -WSAGetLastError();
        } else if (r == 0) {
            break;
        }
        totalRecv += r;
    }

    return totalRecv;
}

int32_t send_message(uint8_t *buffer, uint16_t count) {
    int32_t totalSent = 0;
    int32_t s = 0;
    while (totalSent < count) {
        s = send(open_socket, buffer + totalSent, count - totalSent, NULL_FLAG);
        if (s == SOCKET_ERROR) {
            return -WSAGetLastError();
        } else if (s == 0) {
            break;
        }
        totalSent += s;
    }
  return totalSent;
}

int32_t shutdown_write() {
    if (shutdown(open_socket, SD_SEND) == SOCKET_ERROR) {
        return -WSAGetLastError();
    } else {
        return 0;
    }
}
