#pragma once
#include <Windows.h>
#include <vector>
#include <winnt.h>

namespace Sentinel::Security {

	class CodeHasher {
	public:
		//Calculates a 64bit non cryptographic hash of the targets .exe .text section
		[[nodiscard]] static auto calculateTextSectionHash(HANDLE process_handle, uintptr_t base_address) -> ULONG64 {
			if (process_handle == nullptr || base_address == 0) { return 0; }

			IMAGE_DOS_HEADER dos_header{};
			IMAGE_NT_HEADERS nt_headers{};

			if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address), &dos_header, sizeof(dos_header), nullptr) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
				return 0;
			}

			if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), nullptr) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
				return 0;
			}

			DWORD text_virtual_address{ 0 };
			DWORD text_size{ 0 };

			const auto section_header_offset{ base_address + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS) };
			const WORD number_of_sections{ nt_headers.FileHeader.NumberOfSections };

			for (WORD i{ 0 }; i < number_of_sections; ++i) {
				IMAGE_SECTION_HEADER section{};

				if (ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(section_header_offset + (i * sizeof(IMAGE_SECTION_HEADER))), &section, sizeof(section), nullptr)) {
					if (memcmp(section.Name, ".text", 5) == 0) {
						text_virtual_address = section.VirtualAddress;
						text_size = section.SizeOfRawData;
						break;
					}
				}
			}

			if (text_size == 0) { return 0; }

			//Reads .text section contents
			std::vector<BYTE> text_buffer(text_size);
			SIZE_T bytes_read{ 0 };

			if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(base_address + text_virtual_address), text_buffer.data(), text_size, &bytes_read)) {
				return 0;
			}

			//Generate 64bit FNV-1a hash
			ULONG64 hash{ 14695981039346656037ULL };
			constexpr ULONG64 fnv_prime{ 1099511628211ULL };

			for (SIZE_T i{ 0 }; i < bytes_read; ++i) {
				hash ^= text_buffer[i];
				hash *= fnv_prime;
			}

			return hash;
		}
	};
}