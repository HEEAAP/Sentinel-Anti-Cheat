//Checks file authenticode signatures
#pragma once
#include <windows.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <iostream>
#include <string>

#pragma comment(lib, "wintrust.lib")

namespace Sentinel::Security {

	//Verifies the file on disk has a valid, trusted authenticode signature
	[[nodiscard]] inline auto isFileSignatureValid(const std::wstring& file_path) -> bool {
		WINTRUST_FILE_INFO file_info{};
		file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
		file_info.pcwszFilePath = file_path.c_str();
		file_info.hFile = nullptr;
		file_info.pgKnownSubject = nullptr;

		GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		WINTRUST_DATA trust_data{};
		trust_data.cbStruct = sizeof(WINTRUST_DATA);
		trust_data.pPolicyCallbackData = nullptr;
		trust_data.pSIPClientData = nullptr;
		trust_data.dwUIChoice = WTD_UI_NONE;
		trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
		trust_data.dwUnionChoice = WTD_CHOICE_FILE;
		trust_data.pFile = &file_info;
		trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
		trust_data.hWVTStateData = nullptr;
		trust_data.pwszURLReference = nullptr;
		trust_data.dwProvFlags = WTD_SAFER_FLAG;
		trust_data.dwUIContext = WTD_UICONTEXT_EXECUTE;

		//Call WinVerifyTrust to evaluate the cert chain
		LONG status = WinVerifyTrust(nullptr, &policy_guid, &trust_data);

		trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(nullptr, &policy_guid, &trust_data);

		return (status == ERROR_SUCCESS);
	}
} //namespace Sentinel::Security