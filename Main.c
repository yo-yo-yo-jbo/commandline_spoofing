/****************************************************************************************************
*                                                                                                   *
*  File:         Main.c                                                                             *
*  Purpose:      Main function for the commandline spoofer.                                         *
*                                                                                                   *
*****************************************************************************************************/
#include "Spoofer.h"

/****************************************************************************************************
*                                                                                                   *
*  Enum:         ARG_INDEX                                                                          *
*  Purpose:      Commandline argument index meanings.                                               *
*                                                                                                   *
*****************************************************************************************************/
typedef enum
{
	ARG_INDEX_SELF = 0,
	ARG_INDEX_FAKE_COMMANDLINE,
	ARG_INDEX_REAL_COMMANDLINE,
	ARG_INDEX_SLEEP_TIME_SECONDS,
	ARG_INDEX_MAX
} ARG_INDEX;

/****************************************************************************************************
*                                                                                                   *
*  Function:     main_ParseU32                                                                      *
*  Purpose:      Parses a DWORD out of the given string.                                            *
*  Parameters:   - pwszString - the string to parse.                                                *
*                - pdwValue - gets the value upon success.                                          *
*  Returns:      A return status.                                                                   *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
main_ParseU32(
	__in __notnull PCWSTR pwszString,
	__out __notnull PDWORD pdwValue
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	PCWSTR pwszEnd = NULL;
	DWORD dwValue = 0;

	// Validations
	DEBUG_ASSERT(NULL != pwszString);
	DEBUG_ASSERT(NULL != pdwValue);

	// Decimal parsing
	dwValue = wcstoul(pwszString, &pwszEnd, 10);
	if ((pwszEnd == pwszString) || (L'\0' !=  *pwszEnd))
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Input string is not a valid decimal number");
		goto lblCleanup;
	}

	// Success
	*pdwValue = dwValue;
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
*  Function:     wmain                                                                              *
*  Purpose:      Main routine.                                                                      *
*  Parameters:   - nArgs - the number of commandline argument.                                      *
*                - ppwszArgs - the arguments in accordance to the ARG_INDEX type.                   *
*  Returns:      A return status as an INT.                                                         *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
INT
wmain(
	__in INT nArgs,
	__in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
	RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
	DWORD dwSleepTimeSeconds = 0;

	// Validations
	if (ARG_INDEX_MAX > nArgs)
	{
		eStatus = RETSTATUS_FAILURE_MSG(L"Insufficient arguments (nArgs=%d)", nArgs);
		goto lblCleanup;
	}

	// Parse sleep time
	eStatus = main_ParseU32(ppwszArgs[ARG_INDEX_SLEEP_TIME_SECONDS], &dwSleepTimeSeconds);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"main_ParseU32() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Spawn and spoof
	eStatus = SPOOFER_Spawn(ppwszArgs[ARG_INDEX_FAKE_COMMANDLINE], ppwszArgs[ARG_INDEX_REAL_COMMANDLINE], dwSleepTimeSeconds, FALSE, FALSE, NULL);
	if (RETSTATUS_FAILED(eStatus))
	{
		DEBUG_MSG(L"SPOOFER_Spawn() failed (eStatus=%.8x)", eStatus);
		goto lblCleanup;
	}

	// Success
	eStatus = RETSTATUS_SUCCESS;

lblCleanup:

	// Return status
	return (INT)eStatus;
}
