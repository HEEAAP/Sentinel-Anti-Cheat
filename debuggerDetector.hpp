#pragma once
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace Sentinel::Security {

	[[nodiscard]] inline auto isProcessBeingDebugged(HANDLE process_handle) -> bool {
		BOOL is_debugger_present{ FALSE };
		if (CheckRemoteDebuggerPresent(process_handle, &is_debugger_present)) {
			return is_debugger_present == TRUE;
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

	[[nodiscard]] inline auto getProcessBaseAddressPEB(HANDLE process_handle) -> uintptr_t {
		PROCESS_BASIC_INFORMATION pbi{};
		ULONG return_lenth{ 0 };

		//Query kernel for process environment block address
		NTSTATUS status{ NtQueryInformationProcess(
			process_handle,
			ProcessBasicInformation,
			&pbi,
			sizeof(pbi),
			&return_lenth
		) };

		if (status != 0 || pbi.PebBaseAddress == nullptr) { return 0; }

		uintptr_t image_base{ 0 };
		constexpr uintptr_t peb_image_base_offset{ 0x10 };

		SIZE_T bytes_read{ 0 };
		if (ReadProcessMemory(process_handle, reinterpret_cast<const char*>(pbi.PebBaseAddress) + peb_image_base_offset, &image_base, sizeof(image_base), &bytes_read) && bytes_read == sizeof(image_base)) {
			return image_base;
		}

		return 0;
	}

	[[nodiscard]] inline auto hasSoftwareBreakpoint(HANDLE process_handle, uintptr_t base_address) -> bool {
		if (base_address == 0) { return false; }

		IMAGE_DOS_HEADER dos_header{};
		SIZE_T bytes_read{ 0 };
		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address), &dos_header, sizeof(dos_header), &bytes_read) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}

		IMAGE_NT_HEADERS nt_headers{};
		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), &bytes_read) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

		uintptr_t code_base{ base_address + nt_headers.OptionalHeader.BaseOfCode };
		DWORD code_size{ nt_headers.OptionalHeader.SizeOfCode };

		if (code_size == 0) { return false; }

		std::vector<unsigned char> code_buffer(code_size);
		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(code_base), code_buffer.data(), code_size, &bytes_read)) {
			return false;
		}

		for (DWORD i{ 0 }; i < bytes_read; ++i) {
			if (code_buffer[i] == 0xCC) { return true; } //0xCC = INT 3 opcode
		}

		return false;
	}

} // namespace Sentinel::Security