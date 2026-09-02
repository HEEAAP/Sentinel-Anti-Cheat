#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>

namespace Sentinel::Security {

	class WindowScanner {
	public:

		WindowScanner() = default;

		struct BlacklistedTarget {
			std::wstring window_title;
			std::wstring class_name;
		};

		static auto hasBlacklistedWindow(std::wstring& detected_name) -> bool {
			struct scanContext {
				std::wstring found_target;
				bool detected{ false };
			} context;

			EnumWindows([](HWND hwnd, LPARAM lparam) -> BOOL {
				auto* ctx{ reinterpret_cast<scanContext*>(lparam) };

				if (!IsWindowVisible(hwnd)) { return TRUE; } //Skips invisible windows

				wchar_t title_buffer[256]{ 0 };
				wchar_t class_buffer[256]{ 0 };

				GetWindowTextW(hwnd, title_buffer, 256);
				GetClassNameW(hwnd, class_buffer, 256);

				std::wstring title{ title_buffer };
				std::wstring class_name{ class_buffer };

				std::transform(title.begin(), title.end(), title.begin(), ::towlower);
				std::transform(class_name.begin(), class_name.end(), class_name.begin(), ::towlower);

				//Blacklisted definitions
				static const std::vector<BlacklistedTarget> blacklist{
					{L"cheat engine", L""},
					{L"cheatengine", L""},
					{L"x64dbg", L""},
					{L"x32dbg", L""},
					{L"process hacker", L""},
					{L"system informer", L""},
					{L"reclass", L""},
					{L"renderdoc", L""},

					//Catch renamed exes/titles
					{L"", L"window_cheatengine"},
					{L"", L"qt5152qwindowicon"} //x64dbg/tools
				};

				for (const auto& entry : blacklist) {
					bool title_match{ !entry.window_title.empty() && title.find(entry.window_title) != std::wstring::npos };
					bool class_match{ !entry.class_name.empty() && class_name.find(entry.class_name) != std::wstring::npos };

					if (title_match || class_match) {
						ctx->detected = true;
						ctx->found_target = title_buffer[0] != L'\0' ? title_buffer : class_buffer;
						return FALSE;
					}
				}

				return TRUE;
			}, reinterpret_cast<LPARAM>(&context));

			if (context.detected) {
				detected_name = context.found_target;
				return true;
			}

			return false;
		}
	};
}