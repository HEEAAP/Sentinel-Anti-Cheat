#pragma once
#include <windows.h>
#include <iostream>
#include <optional>

namespace Sentinel::Launcher {
	struct SpawnResult {
		HANDLE process_handle{ nullptr };
		HANDLE thread_handle{ nullptr };
		DWORD pid{ 0 };
	};

	[[nodiscard]] inline auto launchTargetProcess(const wchar_t* executable_path) -> std::optional<SpawnResult> {
		STARTUPINFOW startup_info{};
		PROCESS_INFORMATION process_info{};
		startup_info.cb = sizeof(STARTUPINFOW);

		//Create the process in suspended state so the AC attaches before main even runs
		BOOL success{ CreateProcessW(
			executable_path,
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
			nullptr,
			nullptr,
			&startup_info,
			&process_info
		) };

		if (!success) {
			return std::nullopt;
		}

		return SpawnResult{
			.process_handle = process_info.hProcess,
			.thread_handle = process_info.hThread,
			.pid = process_info.dwProcessId
		};

	}

	inline void resumeTargetProcess(HANDLE thread_handle) {
		if (thread_handle != nullptr) {
			ResumeThread(thread_handle);
		}
	}
} //namespace Sentinel::Launcher