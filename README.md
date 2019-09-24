# Remote Procedure Code Reuse Attacks

Adrián Barreal (STIC, Fundación Sadosky, Argentina).



**Directory Contents**:

* `winpoc`: Windows proof of concept exploit against an echo server vulnerable to stack overflow/overread attacks. The server may be protected by ACG, CIG and Child Process Policy, theoretically blocking arbitrary code. The payload registers a task in the task scheduler that launches an instance of notepad, only using ROP. Notice that registering a task should not be possible in the case of a properly isolated process; the PoC, however, still displays the potential of the technique to be used to implement complex payloads efficiently, which may include second stage privilege escalation exploits.
* `linux-nginx-poc`: Proof of concept exploit for Linux, against nginx 1.4.0. The exploit is provided as a Metasploit module based on the original chunked size exploit available by default in the framework. A Vagrantfile is also provided to launch the web server in a virtual machine.