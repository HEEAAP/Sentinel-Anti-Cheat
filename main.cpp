#include <iostream>
#include <optional>
#include <span>
#include <vector>
#include <thread>
#include <chrono>
#include <windows.h>

#include "debuggerDetector.hpp"
#include "threatResponder.hpp"

template <typename T>
[[nodiscard]] auto ReadMemory(HANDLE process_handle, const void* target_address) -> std::optional<T> {
	T buffer{};
	SIZE_T bytes_read{ 0 };

	if (ReadProcessMemory(process_handle, target_address, &buffer, sizeof(T), &bytes_read) && bytes_read == sizeof(T))
		return buffer;

	return std::nullopt;
}

int main() {
	DWORD pid{ 0 };
	std::cout << "[Sentinel] Enter Target Process ID: ";
	if (!(std::cin >> pid))
		return 1;

	uintptr_t target_address_raw{ 0 };
	std::cout << "[Sentinel] Enter Health Variable Address (in hex): ";
	if (!(std::cin >> std::hex >> target_address_raw))
		return 1;

	const void* target_address{ reinterpret_cast<const void*>(target_address_raw) };
	
	HANDLE process_handle{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pid) };
	if (process_handle == nullptr) {
		std::cerr << "[Sentinel] Failed to open process. Error: " << GetLastError() << "\n";
		return 1;
	}

	constexpr auto active_policy{ Sentinel::Security::ResponsePolicy::TerminateTarget }; //LogsOnly, SuspendTarget, TerminateTarget

	std::cout << "[Sentinel] Successfully attached to PID " << pid << "\n\n";

	std::optional<int> last_known_value{ ReadMemory<int>(process_handle, target_address) };

	if (!last_known_value.has_value()) {
		std::cerr << "[Sentinel] Initial memory read failed! Exiting..\n";
		CloseHandle(process_handle);
		return 1;
	}

	std::cout << "[Sentinel] Baseline Established | Initial Value: " << *last_known_value << "\n";
	std::cout << "[Monitoring memory for modifications...\n\n";

	while (true) {
		//Check for attatched debuggers
		if (Sentinel::Security::isProcessBeingDebugged(process_handle)) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "User mode Debugger Attached");
			break;
		}

		if (Sentinel::Security::hasSoftwareBreakpoint(process_handle, target_address, sizeof(int))) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "Software Breakpoint (0xCC / INT 3) Detected");
			break;
		}

		if (Sentinel::Security::hasHardwareBreakpoints(pid)) {
			Sentinel::Security::enforcePolicy(process_handle, pid, active_policy, "Hardware Breakpoint (DR0-DR3) Detected");
			break;
		}

		//Check memory state
		if (auto health_val{ ReadMemory<int>(process_handle, target_address) }) {
			if (*health_val != *last_known_value) {
				std::cout << "\n[ALERT] Value Changed: " << *last_known_value << " -> " << *health_val << "\n";
				last_known_value = health_val;
			}
			std::cout << "[Sentinel] Inspected Health Value: " << *health_val << "   /r" << std::flush;
		}
		else {
			std::cerr << "\n[Sentinel] Target process closed or memory unreadable.\n\n";
			break;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	CloseHandle(process_handle);

}