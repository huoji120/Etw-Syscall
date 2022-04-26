#include "head.h"
typedef struct _PDBINFO
{
	ULONG Signature;
	GUID UID;
	ULONG Age;
	CHAR PDBFileName[128];
}PDBINFO, * PPDBINFO;


HANDLE ProcessHandle;
HANDLE DriverHandle;

ULONG64 NtosBase = 0;
ULONG64 NtosKrnl = 0;

typedef PVOID HINTERNET;

BOOLEAN
WINAPI
DownloadSymbol(
	IN PCHAR SymbolUrl,
	IN PCHAR SavePath
)
{
	BOOL Success = FALSE;
	ULONG numOfBytesRead = 0;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	FILE* fp = NULL;

	UCHAR Buffer[8192] = { 0 };

	hSession = InternetOpenA("", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hSession)
	{
		return FALSE;
	}

	hConnect = InternetConnectA(hSession, "msdl.microsoft.com", 80, "", "", INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect)
	{
		InternetCloseHandle(hSession);
		return FALSE;
	}

	hRequest = HttpOpenRequestA(hConnect, "GET", SymbolUrl, NULL, NULL, NULL, 0, 0);
	if (!hRequest)
	{
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hSession);
		return FALSE;
	}

	Success = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
	if (Success)
	{
		fp = fopen(SavePath, "wb+");
		if (fp)
		{
			do
			{
				RtlZeroMemory(Buffer, sizeof(Buffer));
				Success = InternetReadFile(hRequest, Buffer, 8192, &numOfBytesRead);
				if (Success)
				{
					if (numOfBytesRead != 0)
					{
						fwrite(Buffer, numOfBytesRead, 1, fp);
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			} while (TRUE);
			fclose(fp);
		}
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
	return Success;
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
		DebugDirectory = ImageDirectoryEntryToData(
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

BOOLEAN
WINAPI
Initialize(
	VOID
)
{
	BOOLEAN Status = FALSE;
	ULONG cbNeeded = 0;

	CHAR szBuff[MAX_PATH] = { 0 };

	if (EnumDeviceDrivers((LPVOID*)&NtosBase, sizeof(NtosBase), &cbNeeded))
	{
		NtosKrnl = (ULONG64)LoadLibrary(L"ntoskrnl.exe");

		if (GetSymbol(NtosKrnl))
		{
			SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME);
			if (SymInitialize(ProcessHandle, "C:\\", FALSE))
			{
				GetModuleFileNameA((HMODULE)NtosKrnl, szBuff, MAX_PATH);
				NtosKrnl = SymLoadModuleEx(ProcessHandle, NULL, szBuff, NULL, 0, 0, NULL, 0);
				return TRUE;
			}
		}
	}
	printf("Load error [%X].\n", GetLastError());
	return FALSE;
}

ULONG64
WINAPI
GeSystemProcAddress(
	IN LPCSTR Name
)
{
	PSYMBOL_INFO SymInfo = malloc(MAX_SYM_NAME);
	ZeroMemory(SymInfo, MAX_SYM_NAME);
	SymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	SymInfo->MaxNameLen = MAX_SYM_NAME;
	SymFromName(ProcessHandle, Name, SymInfo);
	if (!SymInfo->Address)
	{
		return 0;
	}
	return SymInfo->Address - NtosKrnl + NtosBase;
}

ULONG
WINAPI
GetStructOffset(
	IN PCHAR StructName,
	IN PWCHAR MemberName
)
{
	ULONG MemberCount = 0;
	SYMBOL_INFO SymInfo = { 0 };
	TI_FINDCHILDREN_PARAMS* pFindParams = NULL;

	ULONG Index = 0;
	ULONG Offset = 0;
	PWCHAR Name = NULL;

	SymInfo.SizeOfStruct = sizeof(SYMBOL_INFO);

	if (SymGetTypeFromName(ProcessHandle, NtosKrnl, StructName, &SymInfo))
	{
		if (SymGetTypeInfo(ProcessHandle, NtosKrnl, SymInfo.TypeIndex, TI_GET_CHILDRENCOUNT, &MemberCount))
		{
			pFindParams = (TI_FINDCHILDREN_PARAMS*)malloc(sizeof(TI_FINDCHILDREN_PARAMS) + MemberCount * sizeof(ULONG64));
			RtlZeroMemory(pFindParams, sizeof(TI_FINDCHILDREN_PARAMS) + MemberCount * sizeof(ULONG64));
			pFindParams->Count = MemberCount;

			if (SymGetTypeInfo(ProcessHandle, NtosKrnl, SymInfo.TypeIndex, TI_FINDCHILDREN, pFindParams))
			{
				for (Index = pFindParams->Start; Index < pFindParams->Count; Index++)
				{
					SymGetTypeInfo(ProcessHandle, NtosKrnl, pFindParams->ChildId[Index], TI_GET_SYMNAME, &Name);
					SymGetTypeInfo(ProcessHandle, NtosKrnl, pFindParams->ChildId[Index], TI_GET_OFFSET, &Offset);
					if (Name)
					{
						if (!wcscmp(MemberName, Name))
						{
							return Offset;
							free(Name);
						}
						free(Name);
					}

				}
			}
		}
	}
	return 0;
}

VOID main()
{
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	if (Initialize())
	{
		printf("ObpCallPreOperationCallbacks:%llX\n", GeSystemProcAddress("ObpCallPreOperationCallbacks"));
		printf("PspCreateProcessNotifyRoutine:%llX\n", GeSystemProcAddress("PspCreateProcessNotifyRoutine"));
	}
	system("pause");
}
