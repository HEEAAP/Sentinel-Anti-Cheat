#pragma once
#include <iostream>
#include <Windows.h>

namespace Sentinel::Security {

	enum class ResponsePolicy {
		LogsOnly,
		SuspendTarget,
		TerminateTarget
	};

	using NtSuspendProcessFn = NTSTATUS(NTAPI*)(HANDLE Process_handle);

	inline auto suspendTargetProcess(HANDLE process_handle) -> bool {
		HMODULE ntdll{ GetModuleHandleW(L"ntdll.dll") };
		if (ntdll == nullptr) {
			return false;
		}

		auto NtSuspendProcess{ reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess")) };

		if (NtSuspendProcess != nullptr) {
			return NtSuspendProcess(process_handle) == 0; //0 = STATUS_SUCCESS
		}

		return false;
	}

	inline void enforcePolicy(HANDLE process_handle, DWORD pid, ResponsePolicy policy, const char* threat_reason) {
		std::cout << "\n[ENFORCEMENT TRIGGERED] Threat: " << threat_reason << '\n';

		switch (policy) {
		case ResponsePolicy::LogsOnly:
			std::cout << "[Policy: LOG_ONLY] Alert recorded. Target process left running.\n\n";
			break;

		case ResponsePolicy::SuspendTarget:
			std::cout << "[Policy: SUSPEND] Freezing process execution..\n";
			if (suspendTargetProcess(process_handle)) {
				std::cout << "[SUCCESS] Target PID " << pid << " has been suspended.\n\n";
			}
			else {
				std::cerr << "[ERROR] Failed to suspend process.\n\n";
			}
			break;

		case ResponsePolicy::TerminateTarget:
			std::cout << "[Policy: TERMINATE] Killing process immediately..\n";

			HANDLE term_handle{ OpenProcess(PROCESS_TERMINATE, FALSE, pid) };
			if (term_handle != nullptr) {
				if (TerminateProcess(term_handle, 0xDEAD)) {
					std::cout << "[SUCCESS] Target PID " << pid << " terminated.\n\n";
				}
				else {
					std::cerr << "[ERROR] TerminateProcess failed: " << GetLastError() << '\n';
				}
				CloseHandle(term_handle);
			}
			else {
				std::cerr << "[ERROR] Failed to obtain TERMINATE handle: " << GetLastError() << '\n';
			}
			break;
		}
	}
}