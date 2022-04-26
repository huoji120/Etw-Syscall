// Etw Syscall.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "head.h"
#include <map>
#include <vector>
int g_iNumOfThreads = 0;
DWORD* g_lpdwThreadsIdArray = NULL;
/*
* 维护两个个状态表
* thread id <-> 处理器id[0],切换状态[1]
*/
//std::map<int, std::vector<int>> g_dwThreadsWithProcesserMap;
/*
* 处理器id <-> threadid[0]
*/
std::map<int, int> g_dwProcesserWithThreadsMap;
/*
* 线程id <-> 进程id
*/
std::map<int, DWORD> g_dwProcessWithThreadidsMap;
/*
* 进程pid <-> 进程名字
*/
std::map<DWORD, std::wstring> g_dwProcessNameWithProcessIdMap;
BOOLEAN
WINAPI
Initialize(
	VOID
);
BOOL
WINAPI
GetSystemFunctionName(
	IN ULONG64 pAddress,
	OUT CHAR* pName
);
enum SwitchState
{
	_SwitchState_Initialized = 0,
	_SwitchState_Ready = 1,
	_SwitchState_Running = 2,
	_SwitchState_Standby = 3,
	_SwitchState_Terminated = 4,
	_SwitchState_Waiting = 5,
	_SwitchState_Transition = 6,
	_SwitchState_DeferredReady = 6,
};

std::wstring GetProcessNameByPid(DWORD pPid) {
	HANDLE hProceesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProceesSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);
		BOOL hProcess = Process32First(hProceesSnap, &pe32);
		while (hProcess)
		{
			//printf("%ws %d\n", pe32.szExeFile, pe32.th32ProcessID);
			if (pe32.th32ProcessID == pPid) {
				CloseHandle(hProceesSnap);
				return std::wstring(pe32.szExeFile);
			}
			hProcess = Process32Next(hProceesSnap, &pe32);
		}
		CloseHandle(hProceesSnap);
	}
	return std::wstring(L"unknown");
}
/*
* 这个没用,因为只有在线程为等待状态并且是阻塞的情况下才有效
*/
/*
* VOID initFunctions()
{
	HMODULE hModule = LoadLibrary(L"ntdll.dll");
	ZwQueryInformationThread = (ZWQUERYINFORMATIONTHREAD)GetProcAddress(hModule, "ZwQueryInformationThread");
}
DWORD GetThreadSysCallNumByHandle(DWORD pThreadId) {
	typedef struct _THREAD_LAST_SYSCALL_INFORMATION
	{
		PVOID FirstArgument;
		USHORT SystemCallNumber;
	} THREAD_LAST_SYSCALL_INFORMATION, * PTHREAD_LAST_SYSCALL_INFORMATION;
	THREAD_LAST_SYSCALL_INFORMATION lastSystemCall = {0};

	HANDLE ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, pThreadId);
	if (ThreadHandle != INVALID_HANDLE_VALUE && ThreadHandle != NULL) {
		ZwQueryInformationThread(
			ThreadHandle,
			ThreadLastSystemCall,
			&lastSystemCall,
			sizeof(THREAD_LAST_SYSCALL_INFORMATION),
			NULL
		);
		CloseHandle(ThreadHandle);
		printf("lastSystemCall.SystemCallNumber: %d thread id %d \n", lastSystemCall.SystemCallNumber, pThreadId);
		return lastSystemCall.SystemCallNumber;
	}
	return NULL;
}
*/

std::map<std::wstring, bool> g_StopDetectList;
std::map<DWORD, std::map<std::string, bool>> g_injectList;
VOID WINAPI NewProcessAdd(DWORD pThreadId) {
	HANDLE ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, pThreadId);
	if (ThreadHandle != INVALID_HANDLE_VALUE && ThreadHandle != NULL) {
		DWORD ProcessId = GetProcessIdOfThread(ThreadHandle);
		if (ProcessId != NULL) {
			std::wstring TempStr = GetProcessNameByPid(ProcessId);
			if (TempStr.find(L"unknown") == std::wstring::npos) {
				g_dwProcessWithThreadidsMap[pThreadId] = ProcessId;
				g_dwProcessNameWithProcessIdMap[ProcessId] = TempStr;
				g_StopDetectList[TempStr] = false;
			}
		}
		CloseHandle(ThreadHandle);
	}
}

VOID WINAPI EtwEventCallback(PEVENT_RECORD EventRecord) {
	EVENT_HEADER& hdr = EventRecord->EventHeader;
	std::string lpOldThrState = std::string();

	UCHAR cpuId = EventRecord->BufferContext.ProcessorNumber;
	ULONG dwOldThrId = 0, dwNewThrId = 0;
	INT64 CycleTime = hdr.TimeStamp.QuadPart;
	if (EventRecord->EventHeader.EventDescriptor.Opcode == 36) {
		if (EventRecord->UserData) {
			CSwitch* pThrSwitch = (CSwitch*)EventRecord->UserData;
			_ASSERT(EventRecord->UserDataLength == sizeof(CSwitch));
			dwNewThrId = pThrSwitch->NewThreadId;
			dwOldThrId = pThrSwitch->OldThreadId;

			g_dwProcesserWithThreadsMap[cpuId] = dwNewThrId;
			if (g_dwProcessWithThreadidsMap.count(dwNewThrId) == 0) {
				NewProcessAdd(dwNewThrId);
			}
			if (g_dwProcessWithThreadidsMap.count(dwOldThrId) == 0) {
				NewProcessAdd(dwOldThrId);
			}
			if (g_dwProcessWithThreadidsMap.count(dwOldThrId) != 0 && pThrSwitch->OldThreadState == _SwitchState_Terminated) {
				if (g_dwProcessNameWithProcessIdMap.count(g_dwProcessWithThreadidsMap[dwOldThrId]) != 0) {
					g_dwProcessNameWithProcessIdMap.erase(g_dwProcessWithThreadidsMap[dwOldThrId]);
				}
				g_dwProcessWithThreadidsMap.erase(dwOldThrId);
			}
			/*
			switch (pThrSwitch->OldThreadState)
			{
				case 0: lpOldThrState = std::string("Initialized"); break;
				case 1: lpOldThrState = std::string("Ready"); break;
				case 2: lpOldThrState = std::string("Running"); break;
				case 3: lpOldThrState = std::string("Standby"); break;
				case 4: lpOldThrState = std::string("Terminated"); break;
				case 5: lpOldThrState = std::string("Waiting"); break;
				case 6: lpOldThrState = std::string("Transition"); break;
				case 7: lpOldThrState = std::string("DeferredReady"); break;
				default:
					return;
			}
			
			//这边维护一个容器状态
			if (g_dwThreadsWithProcesserMap.count(dwNewThrId) == 0) {
				//没有被记录的,创建新线程
				g_dwThreadsWithProcesserMap[dwNewThrId].push_back(cpuId);
				g_dwThreadsWithProcesserMap[dwNewThrId].push_back(_SwitchState_Running);
			}
			else if (g_dwThreadsWithProcesserMap.count(dwOldThrId) == 0 && pThrSwitch->OldThreadState != _SwitchState_Terminated) {
				//老的没有被记录
				g_dwThreadsWithProcesserMap[dwOldThrId].push_back(cpuId);
				g_dwThreadsWithProcesserMap[dwOldThrId].push_back(pThrSwitch->OldThreadState);
			}
			else if (g_dwThreadsWithProcesserMap.count(dwOldThrId) != 0 && pThrSwitch->OldThreadState != _SwitchState_Terminated) {
				//更新老的状态
				g_dwThreadsWithProcesserMap[dwOldThrId][0] = -1;
				g_dwThreadsWithProcesserMap[dwOldThrId][1] = pThrSwitch->OldThreadState;
			}
			else if (g_dwThreadsWithProcesserMap.count(dwOldThrId) != 0 && pThrSwitch->OldThreadState == _SwitchState_Terminated) {
				//老的线程结束了,删除这个hashmap
				g_dwThreadsWithProcesserMap.erase(dwOldThrId);
			}
			*/
			/*
			for (int i = 0; i < g_iNumOfThreads; i++) {
				if (g_lpdwThreadsIdArray[i] == dwNewThrId || g_lpdwThreadsIdArray[i] == dwOldThrId) {
					printf("[EtwContextSwitch] Processor: %i, New thread ID: %i, Old thread ID: %i (state: %s).\r\n", cpuId, dwNewThrId, dwOldThrId, lpOldThrState.c_str());
					//DebugBreak();
				}
			}
			*/
		}
	}
	else if (EventRecord->EventHeader.EventDescriptor.Opcode == 51) {
		//syscall enter
		if (g_dwProcesserWithThreadsMap.count(cpuId) == 0 || 
			g_dwProcessWithThreadidsMap.count(g_dwProcesserWithThreadsMap[cpuId]) == 0 || 
			g_dwProcessNameWithProcessIdMap.count(g_dwProcessWithThreadidsMap[g_dwProcesserWithThreadsMap[cpuId]]) == 0)
			return;
		DWORD ThreadId = g_dwProcesserWithThreadsMap[cpuId];
		std::wstring ProcessName = g_dwProcessNameWithProcessIdMap[g_dwProcessWithThreadidsMap[ThreadId]];
		PVOID* SsdtFucntionName = (PVOID*)EventRecord->UserData;

		if (g_StopDetectList[ProcessName])
			return;

		if (ProcessName.find(L"Toy") == std::wstring::npos)
			return;
		//printf("SsdtFucntionName: %p \n", SsdtFucntionName[0]);
		//DWORD SysCallNum = GetThreadSysCallNumByHandle(ThreadId);
		char NameStack[100];
		memset(NameStack, 0x0, sizeof(NameStack));
		if (GetSystemFunctionName((ULONG64)SsdtFucntionName[0], NameStack)) {
			std::string StringNameStack = std::string(NameStack);
			if (strcmp("NtCreateFile", NameStack) == 0 ||
				strcmp("NtCreateThreadEx", NameStack) == 0 ||
				strcmp("NtAllocateVirtualMemory", NameStack) == 0 ||
				strcmp("NtWriteVirtualMemory", NameStack) == 0 ||
				strcmp("NtOpenProcess", NameStack) == 0 ||
				strcmp("NtOpenProcessToken", NameStack) == 0 ||
				strcmp("NtCreateThread", NameStack) == 0) {
				int iter_num = 0;
				for (auto& value : g_injectList[g_dwProcessWithThreadidsMap[ThreadId]]) {
					if (StringNameStack == value.first) {
						g_injectList[g_dwProcessWithThreadidsMap[ThreadId]][value.first] = true;
					}
				//	if(g_injectList[g_dwProcessWithThreadidsMap[ThreadId]][value.first])
				//		iter_num += 1;
				}
				//if (iter_num == g_injectList[g_dwProcessWithThreadidsMap[ThreadId]].size())
				//	g_StopDetectList[ProcessName] = true,
				//	printf("检测到注入 进程名字: %ws \n", ProcessName.c_str());
				printf("cpuid: %d Process: %ws ThreadId: %d syscall: %s \n", cpuId, ProcessName.c_str(), ThreadId, NameStack);
			}
		}
	}
}


DWORD WINAPI TraceThread(LPVOID lpParam) {
	TRACEHANDLE hConsumer = (TRACEHANDLE)lpParam;
	BOOL bRetVal = FALSE;
	DWORD dwCurProcId = GetCurrentProcessId();
	if (!hConsumer) return -1;
	
	// Enumerate all the threads of this process and add it to the global list
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te = { 0 };
		int count = 0;
		te.dwSize = sizeof(te);
		bRetVal = Thread32First(h, &te);

		while (bRetVal) {
			te.dwSize = sizeof(te);
			bRetVal = Thread32Next(h, &te);
		}

		// Allocate enough memory
		//g_lpdwThreadsIdArray = new DWORD[dwNumOfThreads];
		//g_iNumOfThreads = dwNumOfThreads;

		bRetVal = Thread32First(h, &te);
		while (bRetVal) {
			//if (te.th32OwnerProcessID == dwCurProcId)
			//	g_lpdwThreadsIdArray[count++] = te.th32ThreadID;
			if (te.th32OwnerProcessID != NULL) {
				if (g_dwProcessWithThreadidsMap.count(te.th32ThreadID) == 0) {
					std::wstring TempStr = GetProcessNameByPid(te.th32OwnerProcessID);
					if (TempStr.find(L"unknown") == std::wstring::npos) {
						g_dwProcessWithThreadidsMap[te.th32ThreadID] = te.th32OwnerProcessID;
						g_dwProcessNameWithProcessIdMap[te.th32OwnerProcessID] = TempStr;
						g_StopDetectList[TempStr] = false;

						g_injectList[te.th32OwnerProcessID]["NtOpenProcessToken"] = 0;
						g_injectList[te.th32OwnerProcessID]["NtCreateFile"] = 0;
						g_injectList[te.th32OwnerProcessID]["NtOpenProcess"] = 0;
						g_injectList[te.th32OwnerProcessID]["NtAllocateVirtualMemory"] = 0;
						g_injectList[te.th32OwnerProcessID]["NtWriteVirtualMemory"] = 0;
						g_injectList[te.th32OwnerProcessID]["NtCreateThreadEx"] = 0;
					}
				}
			}
			te.dwSize = sizeof(te);
			bRetVal = Thread32Next(h, &te);
		}
		CloseHandle(h);
	}
	
	printf("开始trace");
	ProcessTrace(&hConsumer, 1, NULL, NULL);
	return 0;
}
DWORD WINAPI TestThread1(LPVOID lpParam) {
	LARGE_INTEGER curTime = { 0 };
	while (TRUE) {
		DWORD dwKey = 0;
		QueryPerformanceCounter(&curTime);
		dwKey = _rotr(curTime.LowPart, curTime.HighPart) * 56 / 11;
		Sleep(1);
	}
}

bool StartEtwTrace() {
	PEVENT_TRACE_PROPERTIES pEtwProp = NULL;
	EVENT_TRACE_LOGFILE etwLogFile = { 0 };
	wchar_t providerName[] = KERNEL_LOGGER_NAME;
	DWORD dwCbProvName = 0,
		dwEtwPropSize = 0;
	TRACEHANDLE hTrace = NULL;
	TRACEHANDLE hConsumerTrace = NULL;
	BOOL bRetVal = FALSE;
	DWORD dwLastErr = 0;

	dwCbProvName = (DWORD)(wcslen(providerName) + 1) * sizeof(TCHAR);

	// Allocate the memory for the ETW data structure
	dwEtwPropSize = sizeof(EVENT_TRACE_PROPERTIES) + dwCbProvName;
	pEtwProp = (PEVENT_TRACE_PROPERTIES)new BYTE[dwEtwPropSize];
	RtlZeroMemory(pEtwProp, dwEtwPropSize);

	pEtwProp->Wnode.ClientContext = 1;
	pEtwProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pEtwProp->Wnode.Guid = SystemTraceControlGuid;
	pEtwProp->Wnode.BufferSize = dwEtwPropSize;
	RtlCopyMemory(((LPBYTE)pEtwProp + sizeof(EVENT_TRACE_PROPERTIES)), providerName, dwCbProvName);

	bRetVal = ControlTrace(NULL, providerName, pEtwProp, EVENT_TRACE_CONTROL_STOP);
	if (bRetVal != ERROR_WMI_INSTANCE_NOT_FOUND) {
		DWORD dwOffset = FIELD_OFFSET(EVENT_TRACE_PROPERTIES, BufferSize);
		RtlZeroMemory((LPBYTE)pEtwProp + dwOffset, dwEtwPropSize - dwOffset);
	}
	pEtwProp->EnableFlags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_SYSTEMCALL;
	pEtwProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pEtwProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);


	wprintf(L"Initializing the ETW Consumer... ");
	bRetVal = StartTrace(&hTrace, providerName, pEtwProp);

	if (bRetVal == ERROR_SUCCESS) {
		RtlZeroMemory(&etwLogFile, sizeof(EVENT_TRACE_LOGFILE));
		etwLogFile.LoggerName = (LPWSTR)providerName;
		etwLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
		etwLogFile.EventRecordCallback = EtwEventCallback;

		hConsumerTrace = OpenTrace(&etwLogFile);
		dwLastErr = GetLastError();
		bRetVal = (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE) ? ERROR_SUCCESS : dwLastErr;
	}

	if (bRetVal == ERROR_SUCCESS) {
		DWORD dwThrId = 0;
		HANDLE hThread = NULL;
		printf("Success.\r\n");

		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestThread1, (LPVOID)NULL, 0, &dwThrId);
		CloseHandle(hThread);

		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TraceThread, (LPVOID)hConsumerTrace, 0, &dwThrId);
		CloseHandle(hThread);

		printf("Press ENTER key to stop the trace and exit...");
		rewind(stdin);
		getwchar();
	}
	else
		printf("Error %i.\r\n", (LPVOID)bRetVal);


	// Stop our Kernel Logger consumer
	if (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE)
		bRetVal = ControlTrace(hConsumerTrace, NULL, pEtwProp, EVENT_TRACE_CONTROL_STOP);
	return bRetVal == ERROR_SUCCESS;
}
int main()
{
	Initialize();
	//SYSCALL::Resolve_sys_Call();
	//initFunctions();
	StartEtwTrace();
	//printf("GetProcessNameByPid(ProcessId) %ws \n", GetProcessNameByPid(25560).c_str());
    std::cout << "Hello World!\n";
}
