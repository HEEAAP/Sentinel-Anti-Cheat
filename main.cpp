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
#include "moduleScanner.hpp"
#include "sentinelHeartbeatServer.hpp"
#include "protectProcess.hpp"
#include "windowScanner.hpp"
#include "codeHasher.hpp"

//Console output text colours
constexpr const char* GREEN		= "\x1B[32m";
constexpr const char* RED		= "\x1B[31m";
constexpr const char* MAGENTA	= "\x1B[35m";
constexpr const char* RESET		= "\x1B[0m";

template <typename T>
[[nodiscard]] auto ReadMemory(HANDLE process_handle, const void* target_address) -> std::optional<T> {
	T buffer{};
	SIZE_T bytes_read{ 0 };

	if (ReadProcessMemory(process_handle, target_address, &buffer, sizeof(T), &bytes_read) && bytes_read == sizeof(T))
		return buffer;

	return std::nullopt;
}

int main() {
	if (!Sentinel::Security::enableProcessProtection) {
		std::cout << MAGENTA << "[SENTINEL]" << RED << " Error: Failed to apply process ACL protection.\n" << RESET;
	}

	Sentinel::Security::HeartbeatServer heartbeat;
	if (!heartbeat.start()) {
		std::cout << MAGENTA << "[SENTINEL]" << RED << " Error: Failed to initialize Heartbeat IPC server.\n" << RESET;
		return 1;
	}

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

	//Capture code section hash baseline
	const ULONG64 baseline_text_hash{ Sentinel::Security::CodeHasher::calculateTextSectionHash(process_handle, base_address) };
	if (baseline_text_hash == 0) {
		std::cout << MAGENTA << "[SENTINEL]" << RED << "Warning: Failed ot generate initial .text section baseline hash.\n";
	}

	splash.updateStatus(L"Protection ACTIVE. Enjoy your game!");
	std::this_thread::sleep_for(std::chrono::seconds(2));

	splash.close();

	//Set the level of enforcement action
	constexpr auto active_policy{ Sentinel::Security::ResponsePolicy::TerminateTarget }; //LogsOnly, SuspendTarget, TerminateTarget

	std::cout << MAGENTA << "[SENTINEL]" << GREEN << " Monitoring Target Process " << RESET << "(PID " << pid << ")...\n";
	
	std::wstring untrusted_module_name;
	std::wstring detected_window;

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

		if (Sentinel::Security::hasUnauthorizedModules(pid, untrusted_module_name)) {
			std::string reason("Unauthorized DLL Module Detected: " + std::string(untrusted_module_name.begin(), untrusted_module_name.end()));
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, reason.c_str());
			break;
		}

		if (Sentinel::Security::WindowScanner::hasBlacklistedWindow(detected_window)) {
			std::string reason("Blacklisted Window/Tool Detected: " + std::string(detected_window.begin(), detected_window.end()));
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, reason.c_str());
			break;
		}

		if (baseline_text_hash != 0) {
			const ULONG64 current_text_hash{ Sentinel::Security::CodeHasher::calculateTextSectionHash(process_handle, base_address) };
			if (current_text_hash != baseline_text_hash) {
				Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "Code Integrity Violation (memory byte modification)");
				break;
			}
		}

		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	heartbeat.stop();
	CloseHandle(process_handle);

	std::cout << MAGENTA << "\n[SENTINEL] Session Closed. Press Enter to exit.." << RESET;
	std::cin.get();
	return 0;
}