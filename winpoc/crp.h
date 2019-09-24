#ifndef CRP_H_
#define CRP_H_

#include <stdint.h>
#include <wchar.h>

int32_t remote_memset(uint64_t address, uint8_t value, uint64_t size);

int32_t remote_malloc(uint64_t size, uint64_t *out_ptr);

int32_t copy_to_target(uint64_t dest_addr, uint8_t *source, uint64_t size);

int32_t remote_GetUserNameW(wchar_t *out_buffer, uint32_t *buff_size);

#endif