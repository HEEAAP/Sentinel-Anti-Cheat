//Anti termination
#pragma once
#include <Windows.h>
#include <AclAPI.h>

namespace Sentinel::Security {
	//Removed PROCESS_TERMINATE from Sentinel so std users or tools cant kill the process
	inline auto enableProcessProtection() -> bool {
		HANDLE process_handle{ GetCurrentProcess() };
		PACL old_acl{ nullptr };
		PSECURITY_DESCRIPTOR sd{ nullptr };

		if (GetSecurityInfo(process_handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_acl, nullptr, &sd) != ERROR_SUCCESS) {
			return false;
		}

		//Creates explicit access rule revoking PROCESS_TERMINATE
		EXPLICIT_ACCESS_W ea{};
		ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_READ;
		ea.grfAccessMode = DENY_ACCESS;
		ea.grfInheritance = NO_INHERITANCE;
		ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
		ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea.Trustee.ptstrName = const_cast<wchar_t*>(L"EVERYONE");

		PACL new_acl{ nullptr };

		if (SetEntriesInAclW(1, &ea, old_acl, &new_acl) != ERROR_SUCCESS) {
			LocalFree(sd);
			return false;
		}

		DWORD result{ SetSecurityInfo(process_handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, new_acl, nullptr) };

		LocalFree(new_acl);
		LocalFree(sd);

		return result == ERROR_SUCCESS;
;	}
} //namespace Sentinel::Security