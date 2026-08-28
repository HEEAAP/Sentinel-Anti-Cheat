#include <iostream>
#include <optional>
#include <span>
#include <vector>
#include <thread>
#include <chrono>
#include <windows.h>

#include "debuggerDetector.hpp"
#include "threatResponder.hpp"
#include "processLauncher.hpp"
#include "sentinelSplash.hpp"

//Console output text colours
#define GREEN  "\x1B[32m"
#define RED    "\x1B[31m"
#define MAGENTA "\x1B[35m"
#define RESET  "\x1B[0m"

template <typename T>
[[nodiscard]] auto ReadMemory(HANDLE process_handle, const void* target_address) -> std::optional<T> {
	T buffer{};
	SIZE_T bytes_read{ 0 };

	if (ReadProcessMemory(process_handle, target_address, &buffer, sizeof(T), &bytes_read) && bytes_read == sizeof(T))
		return buffer;

	return std::nullopt;
}

int main() {
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	Sentinel::UI::SplashWindow splash;
	splash.showAsync(L"Sentinel Engine", L"Bootstrapping target process...");

	std::this_thread::sleep_for(std::chrono::milliseconds(800));

	std::cout << "=======================================\n";
	std::cout << "   SENTINEL ANTI-CHEAT DAEMON (v1.0)   \n";
	std::cout << "=======================================\n\n";


	//Launch TargetApp.exe in suspended state first
	auto target_app{ Sentinel::Launcher::launchTargetProcess(L"TargetApp.exe") };
	if (!target_app.has_value()) {
		splash.updateStatus(L"Error: Failed to launch TargetApp.exe");
		std::this_thread::sleep_for(std::chrono::seconds(2));
		splash.close();
		return 1;
	}

	HANDLE process_handle{ target_app->process_handle };
	HANDLE thread_handle{ target_app->thread_handle };
	DWORD pid{ target_app->pid };

	splash.updateStatus(L"Resolving memory mapping (PEB)..");

	uintptr_t base_address{ Sentinel::Security::getProcessBaseAddressPEB(process_handle)};
	if (base_address == 0) {
		splash.updateStatus(L"Error: Failed PEB base address resolution!");
		std::this_thread::sleep_for(std::chrono::seconds(2));
		TerminateProcess(process_handle, 1);
		splash.close();
		return 1;
	}
	
	splash.updateStatus(L"Verifying target integrity & enforcing hook protection..");
	std::this_thread::sleep_for(std::chrono::seconds(1));

	//Resume TargetApp.exe execution
	Sentinel::Launcher::resumeTargetProcess(thread_handle);
	CloseHandle(thread_handle);

	splash.updateStatus(L"Protection ACTIVE. Enjoy your game!");
	std::this_thread::sleep_for(std::chrono::seconds(2));

	splash.close();

	//Set the level of enforcement action
	constexpr auto active_policy{ Sentinel::Security::ResponsePolicy::TerminateTarget }; //LogsOnly, SuspendTarget, TerminateTarget

	std::cout << MAGENTA << "[SENTINEL]" << GREEN << " Monitoring Target Process " << RESET << "(PID " << pid << ")...\n";

	//Security scan loop
	while (true) {
		if (Sentinel::Security::isProcessBeingDebugged(process_handle)) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "User-mode Debugger Attached");
			break;
		}

		if (Sentinel::Security::hasHardwareBreakpoints(pid)) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "Hardware Breakpoint (DR0-DR3) Detected");
			break;
		}

		if (Sentinel::Security::hasSoftwareBreakpoint(process_handle, base_address)) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "Software Breakpoint (0xCC) Detected in .text Section");
			break;
		}

		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	CloseHandle(process_handle);
	std::cout << MAGENTA << "\n[SENTINEL] Session Closed. Press Enter to exit..";
	std::cin.get();
}