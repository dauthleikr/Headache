#pragma once
#include <thread>

namespace headache
{
	using AttachCallback = void (*)();
	
	bool IsBeingDebugged();
	bool IsKernelBeingDebugged();
	void UseReversedPEB();

	bool IsTitanHideActive();
	bool IsNtsitBadlyHooked();

	std::thread StartAntiAttachRaceThread(AttachCallback callback, int sleepMicroSeconds = 10);
	std::thread StartDebuggerDosThread(int sleepMicroSeconds = 10000);
}
