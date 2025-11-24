/****************************************************************************************************
*                                                                                                   *
*  File:         Spoofer.c                                                                          *
*  Purpose:      Spoofs a new child process commandline.                                            *
*                                                                                                   *
*****************************************************************************************************/
#include "Spoofer.h"
#include <string.h>
#include <winternl.h>
#include <winnt.h>

/****************************************************************************************************
*                                                                                                   *
*  Constant:     MAX_COMMANDLINE_CHARS                                                              *
*  Purpose:      The maximum commandline length in characters.                                      *
*                                                                                                   *
*****************************************************************************************************/
#define MAX_COMMANDLINE_CHARS (32767)

/****************************************************************************************************
*                                                                                                   *
*  Prototype:    PFN_NTQUERYINFORMATIONPROCESS                                                      *
*  Purpose:      Function pointer prototype for ntdll!NtQueryInformationProcess.                    *
*  Parameters:   - hProcess - the process.                                                          *
*				 - eProcessInformationClass - the informatrion class.                               *
*                - pvProcessInformation - gets the process information.                             *
*                - cbProcessInformation - specifies the process information buffer size in bytes.   *
*                - pcbReturnLength - optionally gets the return length in bytes.                    *
*  Returns:      The corresponding NTSTATUS.                                                        *
*  Remarks:      - Done because statically linking with ntdll is not a great practice.              *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
typedef
NTSTATUS(NTAPI* PFN_NTQUERYINFORMATIONPROCESS)(
	__in __notnull HANDLE hProcess,
	__in PROCESSINFOCLASS eProcessInformationClass,
	__out_bcount(cbProcessInformation) __notnull PVOID pvProcessInformation,
	__in ULONG cbProcessInformation,
	__out_opt PULONG pcbReturnLength
);

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_CreateDebuggedChild                                                        *
*  Purpose:      Spawns a newly debugged child process.                                             *
*  Parameters:   - pwszCommandline - the commandline.                                               *
*                - bHideWindow - whether to hide the child process window or not.                   *
*                - bHideConsole - whether to hide the child process console or not.                 *
*                - phProcess - gets the process handle.                                             *
*			     - phThread - gets the main thread handle.                                          *
*  Returns:      A return status.                                                                   *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_CreateDebuggedChild(
	__in __notnull PCWSTR pwszCommandline,
	__in BOOL bHideWindow,
	__in BOOL bHideConsole,
	__out __notnull PHANDLE phProcess,
	__out __notnull PHANDLE phThread
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	STARTUPINFOW tStartupInfo = { 0 };
	PROCESS_INFORMATION tProcInfo = { 0 };
	DWORD dwCreationFlags = 0;
	PWSTR pwszDuplicatedCommandline = NULL;
	SIZE_T cchCommandlineLength = 0;
	SIZE_T cbCommandlineLength = 0;

	// Validations
	DEBUG_ASSERT(NULL != pwszCommandline);
	DEBUG_ASSERT(NULL != phProcess);
	DEBUG_ASSERT(NULL != phThread);

	// Prepare startup information and prepare to hide the window
	tStartupInfo.cb = sizeof(tStartupInfo);
	if (bHideWindow)
	{
		tStartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
		tStartupInfo.wShowWindow = SW_HIDE;
	}

	// Prepare creation flags
	dwCreationFlags = DEBUG_ONLY_THIS_PROCESS;
	if (bHideConsole)
	{
		dwCreationFlags |= CREATE_NO_WINDOW;
	}

	// Duplicate the commandline (since CreateProcessW requires the buffer to be writable)
	cchCommandlineLength = wcslen(pwszCommandline);
	cbCommandlineLength = (cchCommandlineLength + 1) * sizeof(*pwszCommandline);
	pwszDuplicatedCommandline = HEAPALLOCZ(cbCommandlineLength);
	if (NULL == pwszDuplicatedCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Commandline allocation failed (cbCommandlineLength=%Iu)", cbCommandlineLength);
		goto lblCleanup;
	}
	CopyMemory(pwszDuplicatedCommandline, pwszCommandline, cbCommandlineLength);

	// Spawn the process
	if (!CreateProcessW(NULL, pwszDuplicatedCommandline, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &tStartupInfo, &tProcInfo))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"CreateProcessW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Success
	*phProcess = tProcInfo.hProcess;
	tProcInfo.hProcess = NULL;
	*phThread = tProcInfo.hThread;
	tProcInfo.hThread = NULL;
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Free resources
	CLOSE_HANDLE(tProcInfo.hProcess);
	CLOSE_HANDLE(tProcInfo.hThread);
	HEAPFREE(pwszDuplicatedCommandline);

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_DrainDebugEvents                                                           *
*  Purpose:      Drains all debug events from the process and detaches it.                          *
*  Parameters:   - hThread - the main thread.                                                       *
*				 - ptDebugEvent - the previous debug event that needs to be drained.                *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Suspends the main thread to avoid a race.										*
*				 - Detaches from the process and resumes the thread.								*
*                - Failure might leave the thread in a suspended state.                             *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_DrainDebugEvents(
	__in __notnull HANDLE hThread,
	__in __notnull DEBUG_EVENT* ptDebugEvent
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	DEBUG_EVENT tDebugEvent = { 0 };

	// Validations
	DEBUG_ASSERT(NULL != hThread);
	DEBUG_ASSERT(NULL != ptDebugEvent);

	// Suspend the thread
	if ((DWORD)-1 == SuspendThread(hThread))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"SuspendThread() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Clean up the debug event
	if (!ContinueDebugEvent(ptDebugEvent->dwProcessId, ptDebugEvent->dwThreadId, DBG_CONTINUE))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Drain everything
	while (WaitForDebugEvent(&tDebugEvent, 0))
	{
		// Handle the various event types
		switch (tDebugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(tDebugEvent.u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(tDebugEvent.u.LoadDll.hFile);
			break;
		}

		// Continue debugging
		if (!ContinueDebugEvent(tDebugEvent.dwProcessId, tDebugEvent.dwThreadId, DBG_CONTINUE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
	}

	// Detach from the process
	if (!DebugActiveProcessStop(ptDebugEvent->dwProcessId))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"DebugActiveProcessStop() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}
	
	// Resume the process
	if ((DWORD)-1 == ResumeThread(hThread))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"ResumeThread() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_WaitForKernel32                                                            *
*  Purpose:      Waits for kernel32 to be loaded to the given process.                              *
*  Parameters:   - ptDebugEvent - upon success, gets a debug event which needs to be handled later. *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Relies on ASLR weakness - kernel32 has the same address for all processes.       *
*                - Only clean up the debug event upon success.                                      *
*                - Clean up event by invoking ContinueDebugEvent and then DebugActiveProcessStop.	*
*                - Note the debug event might be written even upon failure.                         *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_WaitForKernel32(
	__out __notnull DEBUG_EVENT* ptDebugEvent
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	HMODULE hKernel32 = NULL;
	BOOL bFoundKernel32 = FALSE;

	// Validations
	DEBUG_ASSERT(NULL != ptDebugEvent);

	// Get kernel32 address
	hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (NULL == hKernel32)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetModuleHandleW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Continue until kernel32 is loaded
	for (;;)
	{
		// Get the next debug event
		if (!WaitForDebugEvent(ptDebugEvent, INFINITE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"WaitForDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}

		// Handle the various event types
		switch (ptDebugEvent->dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CLOSE_FILE_HANDLE(ptDebugEvent->u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			bFoundKernel32 = (PVOID)hKernel32 == ptDebugEvent->u.LoadDll.lpBaseOfDll;
			CLOSE_FILE_HANDLE(ptDebugEvent->u.LoadDll.hFile);
			break;
		}

		// Bail-out if found
		if (bFoundKernel32)
		{
			break;
		}

		// Continue to the next debug event
		if (!ContinueDebugEvent(ptDebugEvent->dwProcessId, ptDebugEvent->dwThreadId, DBG_CONTINUE))
		{
			eStatus = RETSTATUS_FAILURE_MSG(L"ContinueDebugEvent() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_ReadProcMemory                                                             *
*  Purpose:      Reads a remote process memory.                                                     *
*  Parameters:   - hProcess - the process.                                                          *
*				 - pvAddr - the remote virtual memory address.										*
*                - cbSize - the amount of bytes to read.                                            *
*                - pvBuffer - gets the read memory upon success.                                    *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Output buffer might be partially written upon failure.                           *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_ReadProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize,
	__out_bcount(cbSize) __notnull PVOID pvBuffer
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcAddr = (PBYTE)pvAddr;
	PBYTE pcBuffer = (PBYTE)pvBuffer;
	SIZE_T cbOffset = 0;
	SIZE_T cbBytesRead = 0;

	// Validations
	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);
	DEBUG_ASSERT(NULL != pvBuffer);

	// Read the process memory
	while (cbOffset < cbSize)
	{
		// Read the chunk
		if (!ReadProcessMemory(hProcess, pcAddr + cbOffset, pcBuffer + cbOffset, cbSize - cbOffset, &cbBytesRead))
		{
			DEBUG_MSG(L"ReadProcessMemory() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}

		// Update offset
		cbOffset += cbBytesRead;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_WriteProcMemory                                                            *
*  Purpose:      Writes a remote process memory.                                                    *
*  Parameters:   - hProcess - the process.                                                          *
*				 - pvAddr - the remote virtual memory address.										*
*                - cbSize - the amount of bytes to write.                                           *
*                - pvBuffer - the buffer to write.                                                  *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Buffer might be partially written to remote memory upon failure.                 *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_WriteProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize,
	__in_bcount(cbSize) __notnull PVOID pvBuffer
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcAddr = (PBYTE)pvAddr;
	PBYTE pcBuffer = (PBYTE)pvBuffer;
	SIZE_T cbOffset = 0;
	SIZE_T cbBytesWritten = 0;

	// Validations
	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);
	DEBUG_ASSERT(NULL != pvBuffer);

	// Write the process memory
	while (cbOffset < cbSize)
	{
		// Write the chunk
		if (!WriteProcessMemory(hProcess, pcAddr + cbOffset, pcBuffer + cbOffset, cbSize - cbOffset, &cbBytesWritten))
		{
			DEBUG_MSG(L"WriteProcessMemory() failed (LastError=%lu)", GetLastError());
			goto lblCleanup;
		}

		// Update offset
		cbOffset += cbBytesWritten;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_ZeroProcMemory                                                             *
*  Purpose:      Writes zeros at a remote process memory.                                           *
*  Parameters:   - hProcess - the process.                                                          *
*				 - pvAddr - the remote virtual memory address.										*
*                - cbSize - the amount of bytes to write.                                           *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Zeros might be partially written to remote memory upon failure.                  *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_ZeroProcMemory(
	__in __notnull HANDLE hProcess,
	__in __notnull PVOID pvAddr,
	__in SIZE_T cbSize
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PBYTE pcZeros = NULL;

	// Validations
	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pvAddr);

	// Allocate a buffer full of zeros
	pcZeros = HEAPALLOCZ(cbSize);
	if (NULL == pcZeros)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Zeros buffer allocation failed (cbSize=%Iu)", cbSize);
		goto lblCleanup;
	}

	// Write the process memory
	eStatus = spoofer_WriteProcMemory(hProcess, pvAddr, cbSize, pcZeros);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Free resources
	HEAPFREE(pcZeros);

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     spoofer_SpoofCommandline                                                           *
*  Purpose:      Spoofs the remote process commandline.                                             *
*  Parameters:   - hProcess - the process.                                                          *
*                - pwszNewCommandline - the new commandline.                                        *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Some new memory might be allocated in the remote process upon failure.           *
*                - The remote process might be in an unrecoverable state upon failure.              *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
spoofer_SpoofCommandline(
	__in __notnull HANDLE hProcess,
	__in __notnull PCWSTR pwszNewCommandline
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	HMODULE hNtdll = NULL;
	PFN_NTQUERYINFORMATIONPROCESS pfnNtQueryInformationProcess = NULL;
	NTSTATUS eNtStatus = STATUS_INVALID_PARAMETER;
	PROCESS_BASIC_INFORMATION tProcInfo = { 0 };
	PEB tPeb = { 0 };
	RTL_USER_PROCESS_PARAMETERS tProcParams = { 0 };
	SIZE_T cchNewCommandline = 0;
	SIZE_T cbNewCommandline = 0;
	PVOID pvRemoteAllocatedAddress = NULL;
	PBYTE pcUnicodeStringRemoteAddress = NULL;

	// Validations
	DEBUG_ASSERT(NULL != hProcess);
	DEBUG_ASSERT(NULL != pwszNewCommandline);

	// Resolve ntdll!NtQueryInformationProcess
	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (NULL == hNtdll)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetModuleHandleW() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}
	pfnNtQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NULL == pfnNtQueryInformationProcess)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"GetProcAddress() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Get the remote process PEB address
	eNtStatus = pfnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &tProcInfo, sizeof(tProcInfo), NULL);
	if (!NT_SUCCESS(eNtStatus))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"NtQueryInformationProcess() failed (eNtStatus=%.8x)", eNtStatus);
		goto lblCleanup;
	}

	// Read the remote PEB
	__pragma(warning(suppress: 6387))
	eStatus = spoofer_ReadProcMemory(hProcess, tProcInfo.PebBaseAddress, sizeof(tPeb), &tPeb);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ReadProcMemory() failed for remote PEB (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Read the remote process parameters
	eStatus = spoofer_ReadProcMemory(hProcess, tPeb.ProcessParameters, sizeof(tProcParams), &tProcParams);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ReadProcMemory() failed for remote process parameters (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Override old commandline with zeros
	eStatus = spoofer_ZeroProcMemory(hProcess, tProcParams.CommandLine.Buffer, tProcParams.CommandLine.MaximumLength);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_ZeroProcMemory() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Allocate memory for the new commandline
	cchNewCommandline = wcslen(pwszNewCommandline);
	cbNewCommandline = (cchNewCommandline + 1) * sizeof(*pwszNewCommandline);
	pvRemoteAllocatedAddress = VirtualAllocEx(hProcess, NULL, cbNewCommandline, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pvRemoteAllocatedAddress)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"VirtualAllocEx() failed (LastError=%lu)", GetLastError());
		goto lblCleanup;
	}

	// Copy the new commandline
	eStatus = spoofer_WriteProcMemory(hProcess, pvRemoteAllocatedAddress, cbNewCommandline, (PVOID)pwszNewCommandline);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed for new commandline buffer (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Fix the UNICODE_STRING members and commit them
	tProcParams.CommandLine.Length = (USHORT)(cbNewCommandline - sizeof(*pwszNewCommandline));
	tProcParams.CommandLine.MaximumLength = (USHORT)cbNewCommandline;
	tProcParams.CommandLine.Buffer = pvRemoteAllocatedAddress;
	pcUnicodeStringRemoteAddress = (PBYTE)tPeb.ProcessParameters + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine);
	eStatus = spoofer_WriteProcMemory(hProcess, pcUnicodeStringRemoteAddress, sizeof(tProcParams.CommandLine), &(tProcParams.CommandLine));
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WriteProcMemory() failed for the new commandline string (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     SPOOFER_Spawn                                                                      *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
SPOOFER_Spawn(
	__in __notnull PCWSTR pwszFakeCommandline,
	__in __notnull PCWSTR pwszRealCommandline,
	__in DWORD dwSleepTimeSeconds,
	__in BOOL bHideWindow,
	__in BOOL bHideConsole,
	__out_opt PHANDLE phProcess
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	SIZE_T cchFakeCommandline = 0;
	SIZE_T cchRealCommandline = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	BOOL bTerminateProcess = FALSE;
	DEBUG_EVENT tDebugEvent = { 0 };

	// Validations
	if ((NULL == pwszFakeCommandline) || (NULL == pwszRealCommandline))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Invalid argument(s) (pwszFakeCommandline=%p, pwszRealCommandline=%p)", pwszFakeCommandline, pwszRealCommandline);
		goto lblCleanup;
	}

	// Validate lengths
	cchFakeCommandline = wcslen(pwszFakeCommandline);
	if (MAX_COMMANDLINE_CHARS < cchFakeCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Fake commandline is too long (cchFakeCommandline=%Iu)", cchFakeCommandline);
		goto lblCleanup;
	}
	cchRealCommandline = wcslen(pwszRealCommandline);
	if (MAX_COMMANDLINE_CHARS < cchRealCommandline)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Real commandline is too long (cchRealCommandline=%Iu)", cchRealCommandline);
		goto lblCleanup;
	}

	// Create the debugged child
	eStatus = spoofer_CreateDebuggedChild(pwszFakeCommandline, bHideWindow, bHideConsole, &hProcess, &hThread);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_CreateDebuggedChild() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}
	bTerminateProcess = TRUE;

	// Sleep for a while
	Sleep(dwSleepTimeSeconds * MILLISECONDS_IN_SECOND);

	// Wait for the child to load kernel32
	eStatus = spoofer_WaitForKernel32(&tDebugEvent);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_WaitForKernel32() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Spoof the remote commandline
	eStatus = spoofer_SpoofCommandline(hProcess, pwszRealCommandline);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_SpoofCommandline() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Drain and detach
	eStatus = spoofer_DrainDebugEvents(hThread, &tDebugEvent);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"spoofer_DrainDebugEvents() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Success
	bTerminateProcess = FALSE;
	if (NULL != phProcess)
	{
		*phProcess = hProcess;
		hProcess = NULL;
	}
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Optionally terminate the process
	if (bTerminateProcess)
	{
		(VOID)TerminateProcess(hProcess, 0);
	}

	// Free resources
	CLOSE_HANDLE(hProcess);
	CLOSE_HANDLE(hThread);

	// Return status
	return eStatus;
}

