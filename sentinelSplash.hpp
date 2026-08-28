#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <thread>
#include <atomic>

#pragma comment(lib, "comctl32.lib")

namespace Sentinel::UI {

	using TaskDialogIndirectFn = HRESULT(WINAPI*)(const TASKDIALOGCONFIG*, int*, int*, BOOL*);

	class SplashWindow {
	public:
		SplashWindow() = default;

		void showAsync(const std::wstring& title, const std::wstring& status) {
			current_status_ = status;
			is_running_ = true;

			ui_thread_ = std::thread([this, title]() {
				HMODULE comctl32{ LoadLibraryW(L"comctl32.dll") };
				if (comctl32 == nullptr) { return; }

				auto task_dialog_indirect{ reinterpret_cast<TaskDialogIndirectFn>( GetProcAddress(comctl32, "TaskDialogIndirect")) };

				if (task_dialog_indirect == nullptr) {
					FreeLibrary(comctl32);
					return;
				}

				INITCOMMONCONTROLSEX icc{ sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES };
				InitCommonControlsEx(&icc);

				TASKDIALOGCONFIG config{ sizeof(TASKDIALOGCONFIG) };
				config.hwndParent = nullptr;
				config.dwFlags = TDF_SHOW_MARQUEE_PROGRESS_BAR | TDF_CALLBACK_TIMER;
				config.pszWindowTitle = title.c_str();
				config.pszMainInstruction = L"SENTINEL ANTI-CHEAT DAEMON";
				config.pszContent = current_status_.c_str();
				config.pszMainIcon = TD_SHIELD_ICON;
				config.pfCallback = &SplashWindow::taskDialogCallback;
				config.lpCallbackData = reinterpret_cast<LONG_PTR>(this);

				TaskDialogIndirect(&config, nullptr, nullptr, nullptr);

				FreeLibrary(comctl32);
			});
		}

		void updateStatus(const std::wstring& new_status) {
			current_status_ = new_status;
			if (dialog_hwnd_ != nullptr) {
				SendMessageW(dialog_hwnd_, TDM_SET_ELEMENT_TEXT, TDE_CONTENT, reinterpret_cast<LPARAM>(new_status.c_str()));
			}
		}

		void close() {
			is_running_ = false;
			if (dialog_hwnd_ != nullptr) { SendMessageW(dialog_hwnd_, TDM_CLICK_BUTTON, IDCANCEL, 0); }
			if (ui_thread_.joinable()) { ui_thread_.join(); }
		}

	private:
		std::wstring current_status_{ L"Initializing.." };
		std::thread ui_thread_;
		std::atomic<HWND> dialog_hwnd_{ nullptr };
		std::atomic<bool> is_running_{ false };

		static HRESULT CALLBACK taskDialogCallback(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, LONG_PTR data) {
			auto* instance = reinterpret_cast<SplashWindow*>(data);

			if (msg == TDN_CREATED) {
				instance->dialog_hwnd_ = hwnd;
				SendMessageW(hwnd, TDM_SET_PROGRESS_BAR_MARQUEE, TRUE, 30);
			}
			return S_OK;
		}
	};
} //namespace Sentinel::UI