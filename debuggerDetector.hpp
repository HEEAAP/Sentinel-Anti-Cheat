#pragma once
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

namespace Sentinel::Security {

	[[nodiscard]] inline auto isProcessBeingDebugged(HANDLE process_handle) -> bool {
		BOOL is_debugger_present{ FALSE };
		if (CheckRemoteDebuggerPresent(process_handle, &is_debugger_present)) {
			return is_debugger_present == TRUE;
		}
		return false;
	}

	[[nodiscard]] inline auto hasSoftwareBreakpoint(HANDLE process_handle, const void* target_address, size_t size_in_bytes) -> bool {
		std::vector<BYTE> buffer(size_in_bytes);
		SIZE_T bytes_read{ 0 };

		if (ReadProcessMemory(process_handle, target_address, buffer.data(), size_in_bytes, &bytes_read) && bytes_read == size_in_bytes) {
			for (BYTE byte : buffer) {
				if (byte == 0xCC) {
					return true;
				}
			}
		}
		return false;
	}

	[[nodiscard]] inline auto hasHardwareBreakpoints(DWORD pid) -> bool {
		HANDLE snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
		if (snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		THREADENTRY32 thread_entry{};
		thread_entry.dwSize = sizeof(THREADENTRY32);

		bool breakpoint_found{ false };

		if (Thread32First(snapshot, &thread_entry)) {
			do {
				if (thread_entry.th32OwnerProcessID == pid) {
					HANDLE thread_handle{ OpenThread(THREAD_GET_CONTEXT, FALSE, thread_entry.th32ThreadID) };

					if (thread_handle != nullptr) {
						CONTEXT context{};
						context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

						if (GetThreadContext(thread_handle, &context)) {
							if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
								breakpoint_found = true;
								CloseHandle(thread_handle);
								break;
							}
						}
						CloseHandle(thread_handle);
					}
				}
			} while (Thread32Next(snapshot, &thread_entry));
		}

		CloseHandle(snapshot);
		return breakpoint_found;
	}

} // namespace Sentinel::Security