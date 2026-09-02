# Sentinel Anti-Cheat Engine

**Sentinel** is a lightweight, production-grade client-side anti-cheat engine and security daemon written in modern C++20. It acts as a secure bootstrapper that launches a target application in a suspended state, establishes active process protections, and continuously monitors runtime execution integrity via an isolated background loop.

---

## 🛡️ Security Features & Protections

Sentinel employs a multi-layered defense model covering process initialization, static signature scanning, dynamically injected code detection, and inter-process communication (IPC) anti-tampering:

### 1. Process Protection & ACL Hardening
* **Anti-Termination (Process ACL Shield):** Modifies Sentinel’s own Discretionary Access Control List (DACL) upon startup to strip `PROCESS_TERMINATE` and `PROCESS_VM_READ` rights for non-SYSTEM user groups. Prevents cheat loaders, Task Manager, or third-party process termination utilities from killing Sentinel while the target application is running.

### 2. Debugger & Hardware Breakpoint Detection
* **User-Mode PEB Debugger Scanner:** Queries process execution flags via the Process Environment Block (`PEB.BeingDebugged`) to catch attached user-mode debuggers (`x64dbg`, `x32dbg`, `Visual Studio Debugger`).
* **Hardware Register Inspection (`DR0`–`DR3`):** Accesses thread context blocks (`GetThreadContext`) via native APIs to detect hardware execution breakpoints set on debug registers `DR0`, `DR1`, `DR2`, and `DR3`.

### 3. Dynamic Injection & Module Verification
* **Toolhelp Module Enumeration:** Periodically scans all loaded `.dll` files in the target process address space (`TH32CS_SNAPMODULE`).
* **Path Filtering:** Validates loaded dynamic libraries against standard OS directories (`System32`, `SysWOW64`, `WinSxS`) and the application's root execution folder.
* **Authenticode Signature Verification (`WinVerifyTrust`):** Any external DLL loaded outside standard system folders is parsed via `wintrust.dll` to verify its PKCS #7 digital signature against trusted root certificate authorities.

### 4. Window & Class Name Blacklist Scanner
* **Enumeration Guard:** Periodically sweeps all active desktop windows (`EnumWindows`) to flag hidden or running cheat tools.
* **Title & Class Matching:** Matches window titles and underlying window classes (e.g., Cheat Engine, x64dbg, Process Hacker, ReClass, System Informer) case-insensitively, bypassing obfuscated or renamed executable titles.

### 5. Code & Memory Integrity Monitoring
* **Software Breakpoint Detection (`0xCC` / `INT 3` Scanning):** Reads and parses the target's `.text` code section in memory to catch inline software breakpoints, function hooks, or injected `INT 3` instruction modifications while skipping MSVC alignment padding.
* **In-Memory Code Section Hashing (FNV-1a Checksum):** Captures a pristine baseline hash of the `.text` section right after process resumption and continuously validates live memory against it to catch byte-patching and memory tampering instantly.
* **Configurable Threat Response Policy:** Supports dynamic policy actions upon threat detection (`LogsOnly`, `SuspendTarget`, or `TerminateTarget`).

### 6. Inter-Process Communication (IPC) Heartbeat
* **Bidirectional Named Pipe Heartbeat:** Establishes a local duplex Named Pipe (`\\.\pipe\SentinelHeartbeatPipe`) between `Sentinel.exe` (Server) and `TargetApp.exe` (Client).
* **Self-Termination Safeguard:** Sentinel transmits cyclic cryptographic sequence tokens every 500ms. If `Sentinel.exe` is frozen, suspended, or forcefully closed, `TargetApp.exe` fails pipe verification and automatically invokes `ExitProcess(0)` within ~400ms.

---

## 📐 System Architecture

```text
                      +----------------------------------+
                      |           SENTINEL.EXE           |
                      |    (Anti-Cheat Security Daemon)   |
                      +-----------------+----------------+
                                        |
      +---------------------------------+---------------------------------+
      |                                 |                                 |
      v                                 v                                 v
[Initialization & UI]         [IPC Heartbeat Server]       [Active Protection Loops]
 ├── Process ACL Stripping     └── Named Pipe Server        ├── PEB Debugger Detector
 ├── TaskDialogIndirect Splash      (Tokens via IPC)        ├── DR0-DR3 Reg Scanner
 └── Suspended Process Spawn                                ├── 0xCC .text Patch Scan
                                                            └── WinVerifyTrust DLL Scan
                                        |
                                        v
                      +----------------------------------+
                      |          TARGETAPP.EXE           |
                      |   (Client Self-Termination)      |
                      +----------------------------------+
```
---

## 🛠️ Build Requirements

* **OS:** Windows 10 / 11 (x64)
* **Compiler:** MSVC v143 (Visual Studio 2022 or later)
* **Language Standard:** C++20 (`/std:c++20`)
* **Windows SDK:** 10.0.19041.0 or higher
* **Libraries Linked:** `wintrust.lib`, `comctl32.lib`

---

## 🚀 Getting Started

### 1. Enable Common Controls v6 Manifest
To ensure the graphical splash window (`TaskDialogIndirect`) initializes properly:
1. Open Project Properties -> **Linker** -> **Manifest File**.
2. Set **Additional Manifest Dependencies** to:
   ```text
   type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'
