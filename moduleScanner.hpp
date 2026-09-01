//Dll Injection monitoring
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#include "signatureVerifier.hpp"

namespace Sentinel::Security {

	[[nodiscard]] inline auto toLower(std::wstring str) -> std::wstring {
		std::transform(str.begin(), str.end(), str.begin(), ::tolower);
		return str;
	}

	//Checks the DLL resides in a trusted directory (sys32, syswow, app folder)
	[[nodiscard]] inline auto isTrustedModulePath(const std::wstring& module_path) -> bool {
		std::wstring path_lower{ toLower(module_path) };

		//Std windows directories
		if (path_lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
			path_lower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
			path_lower.find(L"\\windows\\winsxs\\") != std::wstring::npos) {
			return true;
		}

		//Allow modules running directly from the apps exe directory
		wchar_t current_dir[MAX_PATH]{};
		if (GetCurrentDirectoryW(MAX_PATH, current_dir) > 0) {
			std::wstring app_dir_lower{ toLower(current_dir) };
			if (path_lower.find(app_dir_lower) != std::wstring::npos) {
				return true;
			}
		}

		//Fallback, verify if external DLL has a valid, trusted authenticode digital signature
		return isFileSignatureValid(module_path);
	}

	//Scans all loaded DLLs in the target process and returns true if an untrusted one is detected
	[[nodiscard]] inline auto hasUnauthorizedModules(DWORD pid, std::wstring& detected_module_name) -> bool {
		HANDLE snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
		if (snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		MODULEENTRY32W module_entry{};
		module_entry.dwSize = sizeof(MODULEENTRY32W);

		bool untrusted_found{ false };

		if (Module32FirstW(snapshot, &module_entry)) {
			do {
				std::wstring full_path{ module_entry.szExePath };

				if (!isTrustedModulePath(full_path)) {
					detected_module_name = module_entry.szModule;
					untrusted_found = true;
					break;
				}
			} while (Module32NextW(snapshot, &module_entry));
		}

		CloseHandle(snapshot);
		return untrusted_found;
	}
} //namespace Sentinel::Security