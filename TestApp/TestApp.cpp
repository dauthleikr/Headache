#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

#include <iostream>
#include <headache.h>
#include <stdio.h>
#include <Psapi.h>
#include "XorString.h"
using namespace headache;

typedef struct _PROCESS_BASIC_INFORMATION2
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION2, * PPROCESS_BASIC_INFORMATION2;


typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

pfnNtQueryInformationProcess gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
static int nice = 0xcd9aadd8;
static bool ShouldHaveDied = false;

#define Die()                         \
do {                                       \
  nice = 0xcd9aadd8; \
  Sleep(500);    \
  ExitProcess(1337);    \
  ShouldHaveDied = true;  \
  ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG, SHTDN_REASON_MINOR_OTHER);  \
} while (0)

static void OnAttach()
{
	printf("[-] I won the race\n");
	Die();
}

static DWORD GetParentPid(DWORD pid)
{
	PROCESS_BASIC_INFORMATION2 basicInfo;
	gNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);
	return reinterpret_cast<DWORD>(basicInfo.InheritedFromUniqueProcessId);
}

static bool WaitForParentProcess(int millis)
{
	auto parentPid = GetParentPid(GetCurrentProcessId());
	HANDLE parentHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, parentPid);
	auto stillAlive = WaitForSingleObject(parentHandle, millis) == 0x00000102L;
	CloseHandle(parentHandle);
	return stillAlive;
}

static void Target(int par)
{
	Sleep(1337);
	if (par < 0xc0000000 || par > 0xd0000000)
	{
		printf("Here is the function!\n");
		//Die();
	}
}

int main(int argc, char** argv)
{
	auto par = XorStr("authorized");
	if (argc == 1 && strcmp(argv[0], par) == 0)
	{
		StartAntiAttachRaceThread(OnAttach);
		StartDebuggerDosThread();

		if (WaitForParentProcess(1000))
		{
			printf(XorStr("[-] Illegal parent process\n"));
			Die();
		}

		printf(XorStr("[+] Valid Application Start\n"));
	}
	else
	{
		char ownPth[MAX_PATH];
		HMODULE hModule = GetModuleHandle(nullptr);
		GetModuleFileNameA(hModule, ownPth, (sizeof(ownPth)));

		STARTUPINFOA si = {};
		PROCESS_INFORMATION pi = {};

		CreateProcessA(ownPth, par, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		return 0;
	}


	UseReversedPEB();
	while (true)
	{
		
		if (/*IsNtsitBadlyHooked() ||*/ IsBeingDebugged())
		{
			std::cout << XorStr("[-] Debugger detected!\n");
			Die();
		}
		else if (IsTitanHideActive())
		{
			std::cout << XorStr("[-] Yuck TitanHide driver!\n");
			Die();
		}
		else if (IsKernelBeingDebugged())
		{
			std::cout << XorStr("[-] Kernel debugger detected!\n");
			Die();
		}
		else
			std::cout << XorStr("[+] No debugger detected.\n");
			

		if(*reinterpret_cast<unsigned char*>(Sleep) == 0xCC || *reinterpret_cast<unsigned char*>(SleepEx) == 0xCC)
		{
			std::cout << XorStr("[-] Software breakpoint on Sleep or SleepEx detected!\n");
			Die();
		}
		
		Target(nice ^ 0xdeadbeef);
		Target(nice ^ 0xdeadbeef);

		if (ShouldHaveDied)
		{
			std::cout << XorStr("[-] Dirty bastard :P\n");
			Sleep(500);
			TerminateProcess(GetCurrentProcess(), 1337);
			*((unsigned int*)0) = 0xDEAD;
			abort();
		}
	}
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

inline HMODULE GetCurrentModuleHandle()
{
	return (HMODULE)&__ImageBase;

}

void NTAPI TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID a)
{
	typedef NTSTATUS
	(NTAPI* NtQueryInformationThread_t)(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);


	if (dwReason == DLL_THREAD_ATTACH)
	{
		uint64_t startAddress = 0;
		NtQueryInformationThread_t pNtQueryInformationThread =
			reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(
				GetModuleHandle(L"ntdll.dll"), XorStr("NtQueryInformationThread")));
		pNtQueryInformationThread(GetCurrentThread(), THREADINFOCLASS(9),
			&startAddress, sizeof(startAddress), nullptr);

		nice = 0xc0ffc0ff ^ 0xdeadbeef;
		
		MODULEINFO kernel32Info = { };
		GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"kernel32.dll"), &kernel32Info, sizeof(MODULEINFO));
		MODULEINFO kernelbaseInfo = { };
		GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"kernelbase.dll"), &kernelbaseInfo, sizeof(MODULEINFO));


		MEMORY_BASIC_INFORMATION info = {};
		if (VirtualQuery(reinterpret_cast<LPCVOID>(startAddress), &info, 0x100) > 0)
		{
			if (info.AllocationProtect == 0x40)
			{
				printf("[-] Shellcode execution detected: %llx\n", startAddress);
				Die();
			}
		}

		auto kernel32Start = reinterpret_cast<uint64_t>(kernel32Info.lpBaseOfDll);
		auto kernelbaseStart = reinterpret_cast<uint64_t>(kernelbaseInfo.lpBaseOfDll);

		if (startAddress > kernel32Start && startAddress < kernel32Start + kernel32Info.SizeOfImage ||
			startAddress > kernelbaseStart && startAddress < kernelbaseStart + kernelbaseInfo.SizeOfImage)
		{
			printf("[-] DLL injection or process exit detected: %llx x\n", startAddress);
			Die();
		}
		else
		{
			Sleep(16);
			printf("[+] Friendly thread started: %llx\n", startAddress);
		}
	}
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")  // See p. 1 below
#pragma comment (linker, "/INCLUDE:p_thread_callback")  // See p. 3 below
#else
#pragma comment (linker, "/INCLUDE:__tls_used")  // See p. 1 below
#pragma comment (linker, "/INCLUDE:p_thread_callback")  // See p. 3 below
#endif


extern "C"
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
PIMAGE_TLS_CALLBACK p_thread_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()