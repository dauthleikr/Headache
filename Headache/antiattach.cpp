#include "pch.h"
#include <thread>
#include "include/headache.h"

namespace headache
{
	static void AntiAttachRaceThread(AttachCallback callback, int sleepMicroSeconds)
	{
		auto sleepDuration = std::chrono::microseconds(sleepMicroSeconds);
		auto dbgUiRemoteBreakin = reinterpret_cast<int64_t*>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "DbgBreakPoint"));
		auto callbackAddress = reinterpret_cast<unsigned char*>(&callback);
		
		unsigned char hook[] =
		{
			0x48,
			0xB8,
			callbackAddress[0],
			callbackAddress[1],
			callbackAddress[2],
			callbackAddress[3],
			callbackAddress[4],
			callbackAddress[5],
			callbackAddress[6],
			callbackAddress[7],
			0x50,
			0xC3,
			0x90,
			0x90,
			0x90,
			0x90,
		};
		auto hookQwordPtr = reinterpret_cast<int64_t*>(hook);
		
		DWORD proc;
		if (!VirtualProtect(dbgUiRemoteBreakin, 10, 0x40, &proc) || dbgUiRemoteBreakin == nullptr)
			return;

		while (true)
		{
			dbgUiRemoteBreakin[0] = hookQwordPtr[0];
			dbgUiRemoteBreakin[1] = hookQwordPtr[1];
			std::this_thread::sleep_for(sleepDuration);
		}
	}

	std::thread StartAntiAttachRaceThread(AttachCallback callback, int sleepMicroSeconds)
	{
		auto antiAttachThread = std::thread(AntiAttachRaceThread, callback, sleepMicroSeconds);
		antiAttachThread.detach();
		return antiAttachThread;
	}

	static std::thread DebuggerDosThread(int sleepMicroSeconds)
	{
		constexpr auto messageLength = 2550;
		const auto sleepDuration = std::chrono::microseconds(sleepMicroSeconds);
		char  message[messageLength];
		for (auto i = messageLength; i > 0; --i)
			message[messageLength - i] = static_cast<char>(i);

		while (true)
		{
			OutputDebugStringA(message);
			std::this_thread::sleep_for(sleepDuration);
		}
	}

	std::thread StartDebuggerDosThread(int sleepMicroSeconds)
	{
		auto debuggerDosThread = std::thread(DebuggerDosThread, sleepMicroSeconds);
		debuggerDosThread.detach();
		return debuggerDosThread;
	}
}