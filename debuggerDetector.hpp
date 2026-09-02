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
		if (process_handle == nullptr || base_address == 0) { return false; }

		IMAGE_DOS_HEADER dos_header{};
		IMAGE_NT_HEADERS nt_headers{};

		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address), &dos_header, sizeof(dos_header), nullptr) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}

		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), nullptr) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}
		
		DWORD text_virtual_address{ 0 };
		DWORD text_size{ 0 };

		const auto section_header_offset{ base_address + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS) };
		const WORD number_of_sections{ nt_headers.FileHeader.NumberOfSections };

		for (WORD i{ 0 }; i < number_of_sections; ++i) {
			IMAGE_SECTION_HEADER section{};
			if (ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(section_header_offset + (i * sizeof(IMAGE_SECTION_HEADER))), &section, sizeof(section), nullptr)) {
				if (memcpy(section.Name, ".text", 5) == 0) {
					text_virtual_address = section.VirtualAddress;
					text_size - section.SizeOfRawData;
					break;
				}
			}
		}

		if (text_size == 0) { return false; }

		std::vector<BYTE> text_buffer(text_size);
		SIZE_T bytes_read{ 0 };

		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address + text_virtual_address), text_buffer.data(), text_size, &bytes_read)) {
			return false;
		}

		//Scans for isolated 0xCC instructions, ignores MSVC function alignment padding (maybe this can be highjacked by cheat devs somehow, need to research)
		for (SIZE_T i{ 0 }; i < bytes_read; ++i) {
			if (text_buffer[i] == 0xCC) {
				bool is_padding{ false };
				if (i > 0 && text_buffer[i - 1] == 0xCC) is_padding = true;
				if (i + 1 < bytes_read && text_buffer[i + 1] == 0xCC) is_padding = true;

				if (!is_padding) return true;
			}
		}
	}

} // namespace Sentinel::Security