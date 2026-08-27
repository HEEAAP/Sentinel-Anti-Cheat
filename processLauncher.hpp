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
}