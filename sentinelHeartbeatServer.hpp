//Inter process communication using windows named pipes, prevents cheaters from simply freezing, suspending or killing sentinel
#pragma once
#include <Windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>

namespace Sentinel::Security {

	class HeartbeatServer {
	public:
		HeartbeatServer() = default;
		~HeartbeatServer() { stop(); }

		auto start() -> bool {
			//Create an inbound/outbound duplex named Pipe
			pipe_handle_ = CreateNamedPipeW(
				pipe_name_,
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				1,
				1024,
				1024,
				0,
				nullptr
			);

			if (pipe_handle_ == INVALID_HANDLE_VALUE) { return false; }

			is_running_ = true;

			//Run pipe listener in background thread
			server_thread_ = std::thread([this]() {
				BOOL connected{ ConnectNamedPipe(pipe_handle_, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED) };

				if (!connected) {
					CloseHandle(pipe_handle_);
					pipe_handle_ = INVALID_HANDLE_VALUE;
					return;
				}

				DWORD current_token{ 1000 };

				while (is_running_) {
					DWORD bytes_written{ 0 };

					//Write the token to pipe
					BOOL success{ WriteFile(
						pipe_handle_,
						&current_token,
						sizeof(current_token),
						&bytes_written,
						nullptr
					) };

					if (!success || bytes_written != sizeof(current_token)) { break; }

					++current_token;
					std::this_thread::sleep_for(std::chrono::milliseconds(500));
				}
			});
			return true;
		}

		void stop() {
			is_running_ = false;
			if (pipe_handle_ != INVALID_HANDLE_VALUE) {
				CloseHandle(pipe_handle_);
				pipe_handle_ = INVALID_HANDLE_VALUE;
			}
			if (server_thread_.joinable()) {
				server_thread_.join();
			}
		}

	private:
		const wchar_t* pipe_name_{ L"\\\\.\\pipe\\SentinelHeartbeatPipe" };
		HANDLE pipe_handle_{ INVALID_HANDLE_VALUE };
		std::atomic<bool> is_running_{ false };
		std::thread server_thread_;
	};
} //namespace Sentinel::Security