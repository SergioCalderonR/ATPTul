#include <Windows.h>
#include <tchar.h>

VOID ShowError(DWORD errCode)
{
	//FormatMessage
	DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS;
	DWORD langId = LANG_USER_DEFAULT;
	LPWSTR errMsg;

	if (FormatMessageW(flags, NULL, errCode, langId, (LPWSTR)&errMsg, 0, NULL) == 0)
	{
		wprintf(L"Could not show the error message. Code: %lu\n", GetLastError());
	}
	else
	{
		wprintf(L"\n%s\n", errMsg);
		LocalFree(errMsg);
	}
}


int wmain(int argc, WCHAR * argv[])
{
	/*	For each endpoint, you can set a configuration value to state whether samples can be collected from the endpoint when a request is
	made through the Windows Defender ATP portal to submit a file for deep analysis.
	
	Path: “HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection”
	Name: "AllowSampleCollection"
	Value: 0 or 1	*/

	//RegCreateKeyEx
	LONG createKey;
	HKEY hRegKey = HKEY_LOCAL_MACHINE;
	LPCWSTR pSubKey = L"SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection";
	DWORD reserved = 0;
	DWORD options = REG_OPTION_NON_VOLATILE;
	REGSAM accessRights = KEY_CREATE_SUB_KEY;
	HKEY hResult;
	DWORD regDisposition;

	//RegSetValueEx
	LONG setValue;
	LPCWSTR pValueName = L"AllowSampleCollection";
	DWORD typeOfData = REG_DWORD;
	DWORD valueData = 1;	//Allow sample collection
	const BYTE * pData = (BYTE*)&valueData;
	DWORD sizeOfData = sizeof(valueData);

	if (argc != 2)
	{
		fwprintf(stderr, L"\nUsage: %s [-ensample] | [-disample]\n", argv[0]);
		exit(1);
	}

	createKey = RegCreateKeyExW(hRegKey, pSubKey, reserved, NULL,
								options, accessRights, NULL, &hResult,
								&regDisposition);

	if (createKey != ERROR_SUCCESS)
	{
		//Shows error message from Windows Error Handler
		ShowError(createKey);
	}
	else //Registry key was created/opened
	{
		if (_wcsicmp(argv[1], L"-ensample") == 0)
		{
			setValue = RegSetValueExW(hResult, pValueName, reserved, typeOfData, pData, sizeOfData);

			if (setValue != ERROR_SUCCESS)
				ShowError(setValue);
			else
			{
				wprintf(L"\nSample Collection has been enabled for this endpoint.\n");
			}
		}
		else if (_wcsicmp(argv[1], L"-disample") == 0)
		{
			valueData = 0;	//Does'nt allow sample collection
			setValue = RegSetValueExW(hResult, pValueName, reserved, typeOfData, pData, sizeOfData);

			if (setValue != ERROR_SUCCESS)
				ShowError(setValue);
			else
			{
				wprintf(L"\nSample Collection has been disabled for this endpoint.\n");
			}
		}
		else
		{
			fwprintf(stderr, L"\nUsage: %s [-ensample] | [-disample]\n", argv[0]);
			exit(1);
		}

		//Closing the handle to the opened/created regkey
		RegCloseKey(hResult);

	}

	return 0;
}