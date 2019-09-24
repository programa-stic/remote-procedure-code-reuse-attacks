#
# Remote Procedure Code Reuse Attacks: Proof of Concept
#
# @author: Adrián Barreal (STIC, Fundación Sadosky, Argentina)
#

Both exploit and target were built and tested in the following conditions:

    * Windows 10 Home 10.0.17134

    * Programs were compiled with cl 19.16.27030.1

Things to keep in mind:

* The exploit is not bulletproof, sometimes the initial information leak fails.
  In any case, this is detected by the client and an error message
  is displayed. In those cases, just restart the server. This should be infrequent, however.

* Notice that the interface exposed by injector the is fairly rough, especially 
  the label replacement system. This can most certainly be improved. For a nicer interface,
  check the Linux exploit.

Target:

    The target is an echo server that consists of a single file,
    server.c, which may be compiled with the following command:
    
    cl server.c /Fe:server.exe
    

Exploit:

    The exploit consists of the files listed below. To compile
    the exploit to an executable rpcra.exe, run
    
    cl rpcra.c injector.c crp.c rsched.c connection.c /Fe:rpcra.exe
    

    = rpcra.c
    *
    * This is the main file; the payload is defined here.
    * Target address and port are also defined here.
    *
    
    = injector.c / injector.h
    *
    * These files implement the injector component. Everything
    * exploitation and gadget related is defined here.
    *
    
    = crp.c / crp.h
    *
    * These files implement utility CRPs like remote_malloc
    * and remote_memset, and copy_to_target. In addition,
    * remote_GetUserNameW is also defined here.
    *
    
    = rsched.c / rsched.h
    *
    * These files define an additional CRP implementation
    * module for the remote task scheduler.
    *
    
    = connection.c / connection.h
    *
    * This files just implement networking related boilerplate.
    * There is nothing particularly interesting here.
    *
    
    Each one of these files contain additional information on the
    inner workings of the exploit. A high level overview of the
    architecture is available in the PDF report.
    
