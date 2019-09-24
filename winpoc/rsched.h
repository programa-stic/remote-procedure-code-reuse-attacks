#ifndef REMOTE_TASK_SCHED_H_
#define REMOTE_TASK_SCHED_H_

#include <stdint.h>

/* This file exposes the remote scheduler's CRP module interface.
 * It allows to obtain a remote binding handle for the task scheduler's RPC interface,
 * and to register a remote task.
 *
 * In fact, the remote_GetSchedBindingHandle does not actually need to be exposed, 
 * as it could be very well hidden inside the remote_RegisterTask call. As we can see,
 * RPCRA exploits can be very modular, component based software.
 *
 */

int32_t remote_GetSchedBindingHandle(uint64_t *out_handle);

int32_t remote_RegisterTask(uint64_t binding_handle, wchar_t *task_path, wchar_t *task_xml);

#endif