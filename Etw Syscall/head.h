#pragma once
#include <Windows.h>
#include <iostream>
#include <crtdbg.h>

#define INITGUID  // Causes definition of SystemTraceControlGuid in evntrace.h. Has to be done once per executable/library.

#include <Evntrace.h>
#include <Evntcons.h>

#include <crtdbg.h>
#include <tlhelp32.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

#include "dbghelp.h"
#pragma comment(lib, "Dbghelp.lib")

#include "psapi.h"
#pragma comment(lib, "Psapi.lib")

#include  <direct.h>  
#pragma comment(lib,"URlmon")

struct CSwitch
{
	UINT32 NewThreadId;						// + 0x00
	UINT32 OldThreadId;						// + 0x04
	INT8 NewThreadPriority;					// + 0x08
	INT8 OldThreadPriority;					// + 0x09
	UINT8 PreviousCState;					// + 0x0A
	INT8 SpareByte;							// + 0x0B
	INT8 OldThreadWaitReason;				// + 0x0C
	INT8 OldThreadWaitMode;					// + 0x0D
	INT8 OldThreadState;					// + 0x0E
	INT8 OldThreadWaitIdealProcessor;		// + 0x0F
	UINT32 NewThreadWaitTime;				// + 0x10
	UINT32 Reserved;						// + 0x14
};
C_ASSERT(sizeof(CSwitch) == 0x18);
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair_Reusable = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,   // Obsolete
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    ThreadSwitchLegacyState = 19,
    ThreadIsTerminated = 20,
    ThreadLastSystemCall = 21,
    ThreadIoPriority = 22,
    ThreadCycleTime = 23,
    ThreadPagePriority = 24,
    ThreadActualBasePriority = 25,
    ThreadTebInformation = 26,
    ThreadCSwitchMon = 27,   // Obsolete
    ThreadCSwitchPmu = 28,
    ThreadWow64Context = 29,
    ThreadGroupInformation = 30,
    ThreadUmsInformation = 31,   // UMS
    ThreadCounterProfiling = 32,
    ThreadIdealProcessorEx = 33,
    ThreadCpuAccountingInformation = 34,
    ThreadSuspendCount = 35,
    ThreadActualGroupAffinity = 41,
    ThreadDynamicCodePolicyInfo = 42,
    MaxThreadInfoClass = 45,
} THREADINFOCLASS;
typedef NTSTATUS(WINAPI* ZWQUERYINFORMATIONTHREAD)(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _In_      PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
    );