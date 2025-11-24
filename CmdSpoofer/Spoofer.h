/****************************************************************************************************
*                                                                                                   *
*  File:         Spoofer.h                                                                          *
*  Purpose:      Spoofs a new child process commandline.                                            *
*                                                                                                   *
*****************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/****************************************************************************************************
*                                                                                                   *
*  Function:     SPOOFER_Spawn                                                                      *
*  Purpose:      Spawns a new child process with an initial commandline and then spoofs it.         *
*  Parameters:   - pwszFakeCommandline - the initial fake commandline.                              *
*                - pwszRealCommandline - the final real commandline.                                *
*                - dwSleepTimeSeconds - the time to sleep beforte changing the commandline.         *
*                - bHideWindow - whether to hide the child process window or not.                   *
*                - bHideConsole - whether to hide the child process console or not.                 *
*                - phProcess - optionally gets the process handle.                                  *
*  Returns:      A return status.                                                                   *
*  Remarks:      - Please enquote commandline arguments, just like when calling CreateProcessW.     *
*                - Note both given commandlines must contain the executable path.                   *
*                - Main executable image path is derived by the fake commandline.                   *
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
);
