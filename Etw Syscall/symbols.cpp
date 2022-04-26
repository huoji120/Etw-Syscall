#include "head.h"

typedef struct _PDBINFO
{
	ULONG Signature;
	GUID UID;
	ULONG Age;
	CHAR PDBFileName[128];
}PDBINFO, * PPDBINFO;

ULONG64 NtosBase = 0;
ULONG64 NtosKrnl = 0; 
HANDLE g_symbols_ProcessHandle = 0;
BOOLEAN
WINAPI
DownloadSymbol(
	IN PCHAR SymbolUrl,
	IN PCHAR SavePath
)
{
	std::string Url = std::string(SymbolUrl);
	Url = "http://msdl.microsoft.com" + Url;
	HRESULT Result = URLDownloadToFileA(NULL, Url.c_str(), SavePath, 0, NULL);
	switch (Result)
	{
		case S_OK:printf("The download started successfully.\n"); break;
		case E_OUTOFMEMORY: printf("The buffer length is invalid, or there is insufficient memory to complete the operation.\n"); break;
	}
	return Result == S_OK;

}
BOOLEAN
WINAPI
GetSymbol(
	IN ULONG64 ImageBase
)
{
	PIMAGE_DEBUG_DIRECTORY DebugDirectory = NULL;
	ULONG DirectorySize = 0;
	PDBINFO PDB = { 0 };

	CHAR PDBGUID[64] = { 0 };
	CHAR SymURL[128] = { 0 };
	CHAR SymPath[128] = { 0 };

	FILE* File;

	if (ImageBase)
	{
		DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)ImageDirectoryEntryToData(
			(PVOID)ImageBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			&DirectorySize
		);

		RtlCopyMemory(&PDB, (PCHAR)ImageBase + DebugDirectory->AddressOfRawData, sizeof(PDB));

		sprintf_s(
			PDBGUID, 64, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
			PDB.UID.Data1, PDB.UID.Data2, PDB.UID.Data3,
			PDB.UID.Data4[0], PDB.UID.Data4[1], PDB.UID.Data4[2],
			PDB.UID.Data4[3], PDB.UID.Data4[4], PDB.UID.Data4[5],
			PDB.UID.Data4[6], PDB.UID.Data4[7], PDB.Age);

		sprintf_s(
			SymURL, 128, "%s/%s/%s/%s",
			"/download/symbols",
			PDB.PDBFileName, PDBGUID, PDB.PDBFileName
		);

		sprintf_s(
			SymPath, 128, "%s%s",
			"C:\\", PDB.PDBFileName
		);

		File = fopen(SymPath, "rb+");
		if (File) {
			fclose(File);
			return TRUE;
		}
		if (DownloadSymbol(SymURL, SymPath)) {
			return TRUE;
		}
	}
	return FALSE;
}
ULONG64
WINAPI
GeSystemProcAddress(
	IN LPCSTR Name
)
{
	//这一段原本是有内存泄露的
	PSYMBOL_INFO SymInfo = (PSYMBOL_INFO)malloc(MAX_SYM_NAME);
	ZeroMemory(SymInfo, MAX_SYM_NAME);
	SymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	SymInfo->MaxNameLen = MAX_SYM_NAME;
	SymFromName(g_symbols_ProcessHandle, Name, SymInfo);
	if (!SymInfo->Address)
	{
		free(SymInfo);
		return 0;
	}
	ULONG64 Result = SymInfo->Address - NtosKrnl + NtosBase;
	free(SymInfo);
	return Result;
}
BOOL
WINAPI
GetSystemFunctionName(
	IN ULONG64 pAddress,
	OUT CHAR* pName
) {
	DWORD64  dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	BOOL result = SymFromAddr(g_symbols_ProcessHandle, pAddress - NtosBase + NtosKrnl, &dwDisplacement, pSymbol);
	memcpy(pName, pSymbol->Name, strlen(pSymbol->Name));
	return result;
}
BOOLEAN
WINAPI
Initialize(
	VOID
)
{
	g_symbols_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	BOOLEAN Status = FALSE;
	ULONG cbNeeded = 0;

	CHAR szBuff[MAX_PATH] = { 0 };

	if (EnumDeviceDrivers((LPVOID*)&NtosBase, sizeof(NtosBase), &cbNeeded))
	{
		NtosKrnl = (ULONG64)LoadLibrary(L"ntoskrnl.exe");

		if (GetSymbol(NtosKrnl))
		{
			SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME);
			if (SymInitialize(g_symbols_ProcessHandle, "C:\\", FALSE))
			{
				GetModuleFileNameA((HMODULE)NtosKrnl, szBuff, MAX_PATH);
				NtosKrnl = SymLoadModuleEx(g_symbols_ProcessHandle, NULL, szBuff, NULL, 0, 0, NULL, 0);
				return TRUE;
			}
		}
	}
	
	printf("Load error [%X].\n", GetLastError());
	return FALSE;
}