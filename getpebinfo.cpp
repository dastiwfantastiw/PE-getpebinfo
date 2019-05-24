#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <typeinfo.h>

typedef NTSTATUS(NTAPI *fNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef NTSTATUS(NTAPI *fNtQueryInformationThread)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);


int main()
{
	fNtQueryInformationProcess NtQueryInformationProcess = (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		printf("[-] GetProcAddress failed with error = 0x%x\n", GetLastError());
		return 0;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("[-] OpenProcess error = 0x%x\n", GetLastError());
		return 0;
	}

	PROCESS_BASIC_INFORMATION PROC_BAS_INFO;

	if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &PROC_BAS_INFO, sizeof(PROCESS_BASIC_INFORMATION), nullptr)))
	{
		if (PROC_BAS_INFO.PebBaseAddress == 0)
		{
			printf("[-] Cannot get PROCESS_BASIC_INFORMATION\n");
			return 0;
		}
		printf(
			"\n[PROCESS_BASIC_INFORMATION]\n\n"
			"PebBaseAddress = 0x%x\n"
			"UniqueProcessId = 0x%x\n",
			PROC_BAS_INFO.PebBaseAddress,
			PROC_BAS_INFO.UniqueProcessId
		);

		PPEB pPEB = PROC_BAS_INFO.PebBaseAddress;

		if (pPEB == 0)
		{
			printf("[-] Cannot get PEB\n");
			return 0;
		}

		printf(
			"\n[PEB]\n\n"
			"BaseAddress = 0x%x\n"
			"AtlThunkSListPtr = 0x%x\n"
			"AtlThunkSListPtr32 = 0x%x\n"
			"BeingDebugged = 0x%x\n"
			"Ldr = 0x%x\n"
			"PostProcessInitRoutine = 0x%x\n"
			"ProcessParameters = 0x%x\n"
			"SessionId = 0x%x\n",
			(DWORD)(pPEB->Reserved3)[1],
			(DWORD)pPEB->AtlThunkSListPtr,
			(ULONG)pPEB->AtlThunkSListPtr32,
			(BYTE)pPEB->BeingDebugged,
			(DWORD)pPEB->Ldr,
			(DWORD)pPEB->PostProcessInitRoutine,
			(DWORD)pPEB->ProcessParameters,
			(ULONG)pPEB->SessionId
		);

		printf("\n[PROCESS PARAMETRS]\n\n");

		PRTL_USER_PROCESS_PARAMETERS ProcessParameters = pPEB->ProcessParameters;

		if (ProcessParameters == 0)
		{
			printf("[-] Cannot get PRTL_USER_PROCESS_PARAMETERS\n");
			return 0;
		}

		wprintf(
			L"CommandLine = %s\n"
			L"ImagePathName = %s\n",
			ProcessParameters->CommandLine.Buffer,
			ProcessParameters->ImagePathName.Buffer
		);

		PPEB_LDR_DATA pLdrData = pPEB->Ldr;

		if (pLdrData == 0)
		{
			printf("[-] Cannot get PPEB_LDR_DATA\n");
			return 0;
		}

		PLIST_ENTRY head = pLdrData->InMemoryOrderModuleList.Flink;
		PLIST_ENTRY next = head;

		if (head == 0)
		{
			printf("[-] Cannot get PLIST_ENTRY\n");
			return 0;
		}

		printf("\n[MODULES INFORMATION]\n");

		do
		{
			LDR_DATA_TABLE_ENTRY LdrEntry;
			PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (pLdrEntry->DllBase == 0)
				break;

			wprintf(
				L"\nCheckSum = 0x%x\n"
				L"DllBase = 0x%x\n"
				L"FullDllName = %s\n"
				L"TimeDateStamp = 0x%x\n",
				pLdrEntry->CheckSum,
				pLdrEntry->DllBase,
				pLdrEntry->FullDllName.Buffer,
				pLdrEntry->TimeDateStamp
			);
			head = pLdrEntry->InMemoryOrderLinks.Flink;

		} while (head != next);
	}
	else
		printf("[-] NtQueryInformationProcess failed with error = 0x%x\n", GetLastError());

	return 1;
}

