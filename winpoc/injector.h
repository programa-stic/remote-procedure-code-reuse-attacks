#ifndef INJECTOR_H_
#define INJECTOR_H_

#include <stdint.h>

/* This injector defines a label replacement mechanism to make handling references 
 * from code section to data easier.
 *
 * To see how offsets are resolved once the CRP has been built, check procedure 
 * resolve_internal_offsets in injector.c. To see usage examples, check CRP 
 * implementations in crp.c and rsched.c.
 *
 */
#define LABEL_REFERENCE 0x64646464
#define MAKE_REFERENCE(ID) (0x6464646400000000) + (ID & 0xffffffff)

#define LABEL_TARGET 0x65656565
#define MAKE_TARGET(ID) (0x6565656500000000) + (ID & 0xffffffff)

/* initialize_injector
 *
 * This function initializes the CRP injection subsystem. Call this function before
 * attempting to perform any remote CRP call.
 *
 */
int32_t initialize_injector();

/* remote_LoadLibrary
 *
 * Loads the dynamic library of name given by C string lib_name in the remote
 * host. When remote_LoadLibrary returns, if execution was successful,
 * r_lib_handle will contain the remote library handle for subsequent calls to
 * remote_GetProcAddress.
 *
 * Note that handles are cached internally, so library handles may be
 * retrieved several times without additional communication overhead.
 *
 */
int32_t remote_LoadLibrary(char *lib_name, uint64_t *r_lib_handle);

/* remote_GetProcAddress
 *
 * Finds address for procedure of name given by C string proc_name in the
 * remote host in module identified by handle h_lib. When remote_GetProcAddress 
 * returns, if execution was successful, r_proc_addr will contain the address 
 * of the requested procedure in the remote host. This address may be used in 
 * subsequent calls to remote_call.
 *
 * Note that, as module handles, procedure addresses are cached internally,
 * so repeated calls to remote_GetProcAddress with the same library name
 * should result in no additional CRPs injected into the target.
 *
 */
int32_t remote_GetProcAddress(uint64_t h_lib, char *proc_name, uint64_t *r_proc_addr);

/* remote_call
 *
 * Calls procedure at address r_proc_addr in the target process. To build the
 * static data section for the CRP, data_length bytes will be copied from the
 * address where given pointer data points to. After the CRP has been built,
 * the label replacement mechanism will be used to resolve internal offsets.
 * Variadic arguments are the arguments for the remote procedure being called.
 *
 * When remote_call returns, if the execution went successfully, *data_out
 * will point to a local buffer that has a copy of the remote output data
 * buffer; CRP output values may be read from there.
 *
 * To see how this function may be used, check CRP implementations in crp.c.
 *
 */
int32_t remote_call(
    int64_t r_proc_addr,
    uint8_t *data,
    uint64_t data_len,
    uint8_t **out,
    uint8_t arg_count,
    ...);

/* remote_find_and_call
 *
 * Equivalent to remote_call, except that that the remote procedure is
 * identified by library name and procedure name rather than remote address.
 * Internally, remote_find_and_call will first call remote_LoadLibrary and
 * remote_GetProcAddress to find the specified procedure, and then it will
 * inject a CRP to execute the procedure with given arguments.
 *
 * Notice that this function also benefits from the internal remote procedure
 * caching system, so repeated calls should not result in additional
 * communication overhead.
 *
 */
int32_t remote_find_and_call(
    char *lib_name,
    char *proc_name,
    uint8_t *data,
    uint64_t data_len,
    uint8_t **out,
    uint8_t arg_count,
    ...);

/* make_single_string_data / make_single_wstring_data
 *
 * Convenience procedures to create a code section large enough to hold a
 * single target label with number 1 and the string in question. Returns
 * the pointer to the data buffer that must be provided to remote_call,
 * and after execution out_data_size will hold the size in bytes. 
 * Remember to call free after done with the data buffer.
 *
 * For usage examples, check CRP implementations in crp.c and rsched.c.
 *
 */
uint8_t *make_single_string_data(char *string, uint64_t *out_data_size);

uint8_t *make_single_wstring_data(wchar_t *string, uint64_t *out_data_size);

/* get_out_storage_base
 *
 * Since the one in charge of injecting and getting CRPs executed is the injector,
 * it would make sense to have the injector tell CRP implementation procedures where
 * is it that output data should be written to in target process' address space,
 * as to decouple CRP implementation from CRP injection.
 *
 * This function returns the address where the region in the target process that
 * the injector promises to treat as the output data section begins. Hence
 * CRPs may write output values obtained from function calls to fixed
 * offsets from this address. Output values may be later retrieved using
 * the out pointer provided by remote_call (check definition above).
 *
 * For usage examples, check CRP implementations in crp.c and rsched.c.
 *
 */
uint64_t get_out_storage_base();

/* get_out_storage_size
 *
 * This injector limits the amount of storage size that can be used for a single
 * CRP. For handling large data, however, several calls may possibly be chained.
 *
 */
uint64_t get_out_storage_size();

/* get_max_input_data_size
 *
 * This function returns the maximum amount of data, in bytes, that may be
 * provided for a single CRP call. CRP implementations like copy_to_target may
 * make use of get_max_input_data_size to know how to split input data
 * into chunks to be sequentially copied to the target process' memory.
 *
 */
uint64_t get_max_input_data_size();

#endif
