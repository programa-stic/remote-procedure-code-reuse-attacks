#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <windows.h>
#include <stdint.h>

// Call this function to define target's address before connecting.
void configure_target_address(char *ip_address, USHORT port);

int32_t establish_connection();

int32_t send_message(uint8_t *buffer, uint16_t count);

int32_t shutdown_write();

int32_t read_response(uint8_t *buffer, uint16_t count);

int32_t close_connection();

#endif