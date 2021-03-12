// Headache.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include <iostream>
#include "include/headache.h"

namespace headache
{
	typedef NTSTATUS(*pNtSetInformationThread)(
		IN HANDLE               ThreadHandle,
		IN THREAD_INFORMATION_CLASS ThreadInformationClass,
		IN PVOID                ThreadInformation,
		IN ULONG                ThreadInformationLength);

	typedef NTSTATUS(*pNtQueryInformationThread)(
		IN HANDLE          ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID          ThreadInformation,
		IN ULONG           ThreadInformationLength,
		OUT PULONG         ReturnLength
		);

	static pNtSetInformationThread NtSetInformationThread = reinterpret_cast<pNtSetInformationThread>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationThread"));
	static pNtQueryInformationThread NtQueryInformationThread2 = reinterpret_cast<pNtQueryInformationThread>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread"));

#if defined(_M_X64) // x64
	static PTEB TebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	static PTEB TebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	static bool ReversedBeingDebugged = false;
	static bool(*IsDebuggerPresentPtr)() = reinterpret_cast<bool(*)()>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "IsDebuggerPresent"));

	void UseReversedPEB()
	{
		/*
		 * IDEA: Lazy tools will hook IsDebuggerPresent() and always return false, or set PEB->BeingDebugged to 0.
		 * Calling UseReversedPEB() will set PEB->BeingDebugged to 2, which means that if it is 0 again,
		 * there is a tool trying to be smart.
		 */

		TebPtr->ProcessEnvironmentBlock->BeingDebugged = 2;
		ReversedBeingDebugged = true;
	}

	static void DummyFunction() {}

	bool IsTitanHideActive()
	{
		/*
		 * IDEA: TitanHide will return zeroed debug registers from GetThreadContext.
		 * When setting a dummy hardware breakpoint, the registers should not be zero though.
		 */

		const auto dummy_breakpoint = reinterpret_cast<DWORD64>(&DummyFunction);

		CONTEXT ctx = {};
		ctx.Dr0 = dummy_breakpoint;
		ctx.Dr7 = 1;
		ctx.ContextFlags = 0x10;

		if (!SetThreadContext(GetCurrentThread(), &ctx))
			return false;

		if (!GetThreadContext(GetCurrentThread(), &ctx))
			return false;

		if (ctx.Dr0 == dummy_breakpoint)
			return false;

		return true;
	}

	bool IsNtsitBadlyHooked()
	{
		/*
		 * IDEA: Lazy tools will hook NtSetInformationThread and return success even if
		 * the parameters will not pass the actual validation done by the original NtSetInformationThread.
		 */
		bool check;
		auto ThreadHideFromDebugger = static_cast<THREAD_INFORMATION_CLASS>(0x11);
		auto status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, &check, sizeof(ULONG));

		if (status >= 0)
			return true;

		status = NtSetInformationThread(reinterpret_cast<HANDLE>(0xFFFFF), ThreadHideFromDebugger, nullptr, 0);
		if (status >= 0)
			return true;

		status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
		if (status >= 0)
		{
			status = NtQueryInformationThread2(GetCurrentThread(), static_cast<THREADINFOCLASS>(ThreadHideFromDebugger), &check, sizeof(BOOLEAN), nullptr);
			if (status >= 0 && !check)
				return true;
		}
		else
		{
			return true;
		}

		return false;
	}

	bool IsBeingDebugged()
	{
		// IDEA: Compare IsDebuggerPresent() to PEB value, if it's different, the function is hooked.
		auto debuggerPresent = IsDebuggerPresentPtr();
		auto beingDebugged = TebPtr->ProcessEnvironmentBlock->BeingDebugged;

		//std::cout << std::boolalpha << ReversedBeingDebugged << " " << debuggerPresent << " " << beingDebugged << std::endl;

		if (ReversedBeingDebugged)
			return beingDebugged != 2;

		return debuggerPresent || beingDebugged;
	}


	bool IsKernelBeingDebugged()
	{
		return *reinterpret_cast<unsigned char*>(0x7ffe02d4) > 0;
	}
}