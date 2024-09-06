#include "BcdHelper.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <functional>
#include <assert.h>
#include <guiddef.h>
#include <cguid.h>
#include <shellapi.h>
#include <shlwapi.h>

#pragma comment( lib, "ntdll.lib" )
#pragma comment( lib, "shlwapi.lib" )

// Dynamic WinAPI table for BCD APIs
std::shared_ptr <SWinAPITable> g_spWinAPIs;

// Helper funcs
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
static std::string to_ansi(const std::wstring& in)
{
	auto out = std::string(in.begin(), in.end());
	return out;
}
static std::wstring to_wide(const std::string& in)
{
	auto out = std::wstring(in.begin(), in.end());
	return out;
}
static std::wstring to_lower_wide(const std::wstring& in)
{
	std::wstring out = in;
	std::transform(out.begin(), out.end(), out.begin(), [](int c) -> wchar_t {
		return static_cast<wchar_t>(::towlower(c));
	});
	return out;
}
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32

std::wstring GuidToString(const GUID* id)
{
	std::wstringstream wss;

	// Add Data1, Data2, and Data3 parts
	wss << std::hex << std::uppercase << std::setfill(L'0');
	wss << std::setw(8) << id->Data1 << L"-"
		<< std::setw(4) << id->Data2 << L"-"
		<< std::setw(4) << id->Data3 << L"-";

	// Add Data4 part, breaking after the second byte
	for (int i = 0; i < sizeof(id->Data4); ++i)
	{
		wss << std::setw(2) << static_cast<int>(id->Data4[i]);
		if (i == 1) wss << L'-';  // Insert hyphen after the second byte
	}

	return wss.str();
}

std::wstring GetRootDevice()
{
	wchar_t wszDirectory[MAX_PATH * 2]{ L'\0' };
	if (!GetSystemDirectoryW(wszDirectory, MAX_PATH))
	{
		wprintf(L"GetSystemDirectoryW failed with error code %u\n", GetLastError());
		return {};
	}

	wszDirectory[3] = L'\0';
	return wszDirectory;
}

std::string GetVolumePath(PCHAR VolumeName)
{
	std::string stName;
	BOOL Success = FALSE;
	PCHAR Names = NULL;
	DWORD CharCount = MAX_PATH + 1;

	for (;;)
	{
		Names = (PCHAR)new (std::nothrow) BYTE[CharCount * sizeof(CHAR)];
		if (!Names)
			return stName;

		Success = GetVolumePathNamesForVolumeNameA(VolumeName, Names, CharCount, &CharCount);
		if (Success)
			break;

		if (GetLastError() != ERROR_MORE_DATA)
			break;

		delete[] Names;
		Names = NULL;
	}

	stName = std::string(Names);

	if (Names != NULL)
	{
		delete[] Names;
		Names = NULL;
	}

	return stName;
}

bool EnumerateSystemVolumes(std::function<bool(std::wstring, std::wstring, void*)> cb, void* lpUserData)
{
	auto bRet = false;

	if (!cb)
		return bRet;

	wchar_t wszVolumeName[MAX_PATH]{ L'\0' };
	auto hFindHandle = FindFirstVolumeW(wszVolumeName, ARRAYSIZE(wszVolumeName));
	if (!hFindHandle || hFindHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"FindFirstVolumeW failed with error: %u\n", GetLastError());
		return bRet;
	}

	do
	{
		auto Index = wcslen(wszVolumeName) - 1;

		if (wszVolumeName[0] != L'\\' || wszVolumeName[1] != L'\\' || wszVolumeName[2] != L'?' ||
			wszVolumeName[3] != L'\\' || wszVolumeName[Index] != L'\\')
		{
			wprintf(L"FindFirstVolume/FindNextVolume returned a bad path: %s\n", wszVolumeName);
			break;
		}

		wszVolumeName[Index] = L'\0';

		wchar_t wszDeviceName[MAX_PATH]{ L'\0' };
		const auto CharCount = QueryDosDeviceW(&wszVolumeName[4], wszDeviceName, ARRAYSIZE(wszDeviceName));
		if (CharCount == 0)
		{
			wprintf(L"QueryDosDeviceA failed with error: %u\n", GetLastError());
			break;
		}

		wszVolumeName[Index] = '\\';

//		wprintf(L"Found a device: %s", wszDeviceName);
//		wprintf(L"Volume name: %s", wszVolumeName);

		const auto stVolumeName = to_ansi(wszVolumeName);
		const auto wstPath = to_wide(GetVolumePath(const_cast<char*>(stVolumeName.c_str())));

		if (!cb(wszDeviceName, wstPath, lpUserData))
		{
			bRet = true;
			break;
		}
	} while (FindNextVolumeW(hFindHandle, wszVolumeName, ARRAYSIZE(wszVolumeName)));

	FindVolumeClose(hFindHandle);
	return bRet;
}

bool OpenVolumeHandle(const std::wstring& wstDeviceName, HANDLE& hrfDevice)
{
	std::wstring wstTargetVolumePath;
	const auto bEnumRet = EnumerateSystemVolumes([&](std::wstring wstDeviceName, std::wstring wstPath, void* lpUserData) {
		if (!wstTargetVolumePath.empty())
			return false;

		std::wstring wstLookingPath = reinterpret_cast<wchar_t*>(lpUserData);
		// wprintf(L"Device name: %s, Volume path: %s, Looking path: %s\n", wstDeviceName.c_str(), wstPath.c_str(), wstLookingPath.c_str());

		if (wstDeviceName.find(wstLookingPath) != std::wstring::npos)
		{
			wstPath.pop_back();

			wstTargetVolumePath = L"\\\\.\\" + wstPath;
			return false;
		}
		return true;
	}, (void*)wstDeviceName.data());
	if (!bEnumRet)
	{
		wprintf(L"Failed to enumerate system volumes\n");
		return false;
	}
	else if (wstTargetVolumePath.empty())
	{
		wprintf(L"Failed to find target volume path\n");
		return false;
	}

	HANDLE hVolume = CreateFileW(
		wstTargetVolumePath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (!hVolume || hVolume == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Failed to open volume: %s, error: %u\n", wstTargetVolumePath.c_str(), GetLastError());
		return false;
	}

	// wprintf(L"Successfully opened volume: %s\n", currentVolume.c_str());
	hrfDevice = hVolume;

	return true;
}

bool IsPartitionActive(std::wstring wstPartitionPath)
{
	HANDLE hDevice = nullptr;
	if (!OpenVolumeHandle(wstPartitionPath, hDevice) || !hDevice || hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Failed to open partition: %s, error: %u\n", wstPartitionPath.c_str(), GetLastError());
		return false;
	}
	
	PARTITION_INFORMATION_EX partitionInfo{};
	DWORD bytesReturned = 0;
	bool bIsActive = false;

	if (DeviceIoControl(
		hDevice,
		IOCTL_DISK_GET_PARTITION_INFO_EX,
		NULL,
		0,
		&partitionInfo,
		sizeof(partitionInfo),
		&bytesReturned,
		NULL))
	{
		bIsActive = partitionInfo.PartitionStyle == PARTITION_STYLE_MBR ? partitionInfo.Mbr.BootIndicator : true;
	}
	else
	{
		wprintf(L"Failed to get partition info for: %s, error: %u\n", wstPartitionPath.c_str(), GetLastError());
	}

	CloseHandle(hDevice);
	return bIsActive;
}

// Check Methods
bool CheckUEFIEntries(const std::shared_ptr <CBCDHelper>& spBCDHelper)
{
	auto vecObjects = spBCDHelper->QueryFirmwareBootApplicationList();
	for (const auto& spObjectCtx : vecObjects)
	{
		wprintf(L"BCD Object: %s\n", spObjectCtx->wstObjectName.c_str());

		HANDLE hObject = nullptr;
		if (!spBCDHelper->OpenObject(&spObjectCtx->guidObject, &hObject))
		{
			wprintf(L"Failed to open BCD object: %s\n", spObjectCtx->wstObjectName.c_str());
			continue;
		}

		std::vector <BCD_ELEMENT> vecElements;
		if (spBCDHelper->EnumerateElements(hObject, vecElements))
		{
			for (const auto& pkValue : vecElements)
			{
				/*
				wprintf(L"Value :: Ver: %u Data: %p (%u), Type: %p\n",
					pkValue.Description->Version, pkValue.Data, pkValue.Description->DataSize, pkValue.Description->Type
				);
				*/
				if (pkValue.Description->Type == BcdLibraryString_Description)
				{
					std::wstring wstElementData;
					const auto bCompleted = spBCDHelper->GetElementString(hObject, pkValue.Description->Type, wstElementData);
					if (bCompleted)
					{
						wprintf(L"[BcdLibraryString_Description] BCD Entry: %s\n", wstElementData.c_str());

						if (!wstElementData.empty())
						{
							if (wstElementData.substr(0, 5) == L"UEFI:")
							{
								wprintf(L"[*WARNING*] UEFI entry found: '%s'\n", wstElementData.c_str());
								std::cin.get();
								return false;
							}
						}
					}
				}
			}
		}

		spBCDHelper->CloseObject(hObject);
	}

	return true;
}

bool CheckBCDEntries(const std::shared_ptr <CBCDHelper>& spBCDHelper)
{
	static auto ProcessBCDEntry = [&](HANDLE hObject, ULONG ulElementType) {
		if (ulElementType == BcdLibraryString_ApplicationPath)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted)
			{
				wprintf(L"[BcdLibraryString_ApplicationPath] BCD Entry: %s\n", wstElementData.c_str());

				const auto wstLowerAppPath = to_lower_wide(wstElementData);
				if (wstLowerAppPath.find(L"\\windows\\system32\\winload.efi") == std::wstring::npos &&
					wstLowerAppPath.find(L"\\windows\\system32\\winload.exe") == std::wstring::npos)
				{
					wprintf(L"[*WARNING*] Invalid BCD Entry: %s\n", wstElementData.c_str());
					return false;
				}
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryString_LoadOptionsString)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted)
			{
				wprintf(L"[BcdLibraryString_LoadOptionsString] BCD Entry: %s\n", wstElementData.c_str());

				const auto wstLowerAppPath = to_lower_wide(wstElementData);
				if (wstLowerAppPath.find(L"nointegritychecks=on") != std::wstring::npos)
				{
					wprintf(L"[*WARNING*] Invalid BCD Entry: %s\n", wstElementData.c_str());
					return false;
				}
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryString_AdditionalCiPolicy)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted)
			{
				wprintf(L"[BcdLibraryString_AdditionalCiPolicy] BCD Entry: %s\n", wstElementData.c_str());

				if (!wstElementData.empty())
				{
					wprintf(L"[*WARNING*] Invalid BCD Entry: %s\n", wstElementData.c_str());
					return false;
				}
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryString_Description)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted)
			{
				wprintf(L"[BcdLibraryString_Description] BCD Entry: %s\n", wstElementData.c_str());
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryDevice_ApplicationDevice ||
			ulElementType == BcdLibraryDevice_WindowsSystemDevice ||
			ulElementType == BcdOSLoaderDevice_OSDevice)
		{
			auto fnValidateDeviceName = [](const auto c_wszInDevice, std::wstring& wstRefDeviceName) {
				if (!c_wszInDevice || !*c_wszInDevice)
					return false;
				wstRefDeviceName = c_wszInDevice;

				if (wstRefDeviceName.substr(0, 5) == L"evice")
					wstRefDeviceName = L"D" + wstRefDeviceName; // idk why it's happens...

				if (wstRefDeviceName.find(L"\\") == std::wstring::npos)
				{
					wstRefDeviceName.clear();
					return false;
				}

				auto wstDeviceName = wstRefDeviceName.substr(wstRefDeviceName.find_last_of(L"\\") + 1);
				if (wstDeviceName.empty())
				{
					wstRefDeviceName.clear();
					return false;
				}

				if (!IsPartitionActive(wstRefDeviceName))
				{
					wprintf(L"[*WARNING*] Partition is not active: %s\n", wstRefDeviceName.c_str());
					wstRefDeviceName.clear();
					return false;
				}

				wstRefDeviceName = wstDeviceName;
				return true;
			};

			std::shared_ptr <BCD_ELEMENT_DEVICE> spElementDevice;
			const auto bCompleted = spBCDHelper->GetElementDevice(hObject, ulElementType, spElementDevice);
			if (bCompleted && spElementDevice.get())
			{
				wprintf(L"[BcdLibraryDevice_ApplicationDevice] BCD Entry: %s\n", spElementDevice->File.Path ? spElementDevice->File.Path : L"");

				if (spElementDevice->DeviceType != BCD_ELEMENT_DEVICE_TYPE_PARTITION)
				{
					wprintf(L"[*WARNING*] Invalid device type: %d\n", spElementDevice->DeviceType);
					return false;
				}

				std::wstring wstFileName;
				if (!fnValidateDeviceName(spElementDevice->File.Path, wstFileName))
				{
					wprintf(L"Invalid BCD Entry(File): %s\n", spElementDevice->File.Path ? spElementDevice->File.Path : L"");
					return false;
				}
				std::wstring wstPartitionName;
				if (!fnValidateDeviceName(spElementDevice->Partition.Path, wstPartitionName))
				{
					wprintf(L"Invalid BCD Entry(Partition): %s\n", spElementDevice->Partition.Path ? spElementDevice->Partition.Path : L"");
					return false;
				}
				std::wstring wstLocateName;
				if (!fnValidateDeviceName(spElementDevice->Locate.Path, wstLocateName))
				{
					wprintf(L"Invalid BCD Entry(Locate): %s\n", spElementDevice->Locate.Path ? spElementDevice->Locate.Path : L"");
					return false;
				}

				wprintf(L"BCD Entry; File: %s, Partition: %s, Locate: %s\n", wstFileName.c_str(), wstPartitionName.c_str(), wstLocateName.c_str());

				if (wstFileName != wstPartitionName || wstFileName != wstLocateName)
				{
					wprintf(L"Device values are not equal!\n");
					return false;
				}

				std::wstring wstTargetVolumePath;
				const auto bEnumRet = EnumerateSystemVolumes([&](std::wstring wstDeviceName, std::wstring wstPath, void* lpUserData) {
					if (!wstTargetVolumePath.empty())
						return false;

					std::wstring wstLookingPath = reinterpret_cast<wchar_t*>(lpUserData);
					// wprintf(L"Device name: %s, Volume path: %s, Looking path: %s\n", wstDeviceName.c_str(), wstPath.c_str(), wstLookingPath.c_str());

					if (wstDeviceName.find(wstLookingPath) != std::wstring::npos)
					{
						wstTargetVolumePath = wstPath;
						return false;
					}
					return true;
				}, (void*)wstFileName.data());
				if (!bEnumRet)
				{
					wprintf(L"Failed to enumerate system volumes\n");
					return false;
				}
				else if (wstTargetVolumePath.empty())
				{
					wprintf(L"Failed to find target volume path\n");
					return false;
				}

				const auto wstRootDevice = GetRootDevice();
				if (wstRootDevice.empty())
				{
					wprintf(L"Failed to get root device, last error: %u\n", GetLastError());
					return false;
				}
				wprintf(L"Target volume path: %s, Root device: %s\n", wstTargetVolumePath.c_str(), wstRootDevice.c_str());

				if (wstRootDevice != wstTargetVolumePath)
				{
					wprintf(L"[*WARNING*] Root device is not equal to target volume path\n");
					return false;
				}

				// wprintf(L"Application device partition style: %p", spElementDevice->QualifiedPartition.PartitionStyle);

				if (!spElementDevice->QualifiedPartition.Mbr.DiskSignature &&
					!spElementDevice->QualifiedPartition.Gpt.DiskSignature.Data1)
				{
					wprintf(L"[*WARNING*] Invalid disk signature\n");
					return false;
				}
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryBoolean_DebuggerEnabled)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Debugger enabled: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryBoolean_DisableIntegrityChecks)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Disable integrity checks: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryBoolean_AllowFlightSignatures)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Allow flight signatures: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdLibraryBoolean_AllowPrereleaseSignatures)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Allow prerelease signatures: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderInteger_NxPolicy)
		{
			ULONG64 ul64ElementData = 0;
			const auto bCompleted = spBCDHelper->GetElementInteger(hObject, ulElementType, ul64ElementData);
			if (bCompleted && ul64ElementData == NxPolicyAlwaysOff)
			{
				wprintf(L"[*WARNING*] Nx policy always off!\n");
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderBoolean_KernelDebuggerEnabled)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Kernel debugger enabled: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderBoolean_DisableCodeIntegrityChecks)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Disable code integrity checks: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderBoolean_AllowPrereleaseSignatures)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Allow prerelease signatures: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderBoolean_HypervisorDebuggerEnabled)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Hypervisor debugger enabled: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderBoolean_WinPEMode)
		{
			bool bElementData = false;
			const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
			if (bCompleted && bElementData)
			{
				wprintf(L"[*WARNING*] Win PE mode enabled: %d\n", bElementData);
				return false;
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderString_SystemRoot)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted && !wstElementData.empty())
			{
				wprintf(L"System root: '%s'\n", wstElementData.c_str());

				const auto wstLowerSystemRoot = to_lower_wide(wstElementData);
				if (wstLowerSystemRoot.size() < 8 || wstLowerSystemRoot.substr(0, 8) != L"\\windows")
				{
					wprintf(L"[*WARNING*] System root is not windows: %s\n", wstElementData.c_str());
					return false;
				}
			}
			else
			{
				wprintf(L"Failed to get BCD Entry for: %p\n", ulElementType);
			}
		}
		else if (ulElementType == BcdOSLoaderString_KernelPath)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted && !wstElementData.empty())
			{
				wprintf(L"[*WARNING*] Custom kernel path detected: %s\n", wstElementData.c_str());
			}
		}
		else if (ulElementType == BcdOSLoaderString_HalPath)
		{
			std::wstring wstElementData;
			const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
			if (bCompleted && !wstElementData.empty())
			{
				wprintf(L"[*WARNING*] Custom HAL path detected: %s\n", wstElementData.c_str());
			}
		}

		return true;
	};

	if (!spBCDHelper->Initialize())
	{
		wprintf(L"Failed to initialize BCDHelper\n");
		return false;
	}
	// spBCDHelper->SetVerbose();

	// Windows Boot Manager
	const auto lstCheckedGUIDs = {
//		GUID_DEFAULT_BOOT_ENTRY,
//		GUID_CURRENT_BOOT_ENTRY,
//		GUID_WINDOWS_SETUP_BOOT_ENTRY,
		GUID_WINDOWS_BOOTMGR,
//		GUID_WINDOWS_LEGACY_NTLDR,
//		GUID_FIRMWARE_BOOTMGR
	};

	uint8_t idx = 0;
	for (auto guidID : lstCheckedGUIDs)
	{
		idx++;

		std::vector <std::shared_ptr <SBCDObjectValueEntry>> vecObjects;
		if (!spBCDHelper->EnumerateValueObjects(&guidID, BcdBootMgrObjectList_DisplayOrder, vecObjects))
		{
			wprintf(L"Failed to enumerate value objects for index: %u\n", idx);
			continue;
		}

		for (const auto& spObject : vecObjects)
		{
			std::wstring wstGUID = GuidToString(&spObject->guidObject);

			// wprintf(L"Object: %p >> %s\n", hObject, wstGUID.c_str());

			std::vector <BCD_ELEMENT> vecElements;
			if (spBCDHelper->EnumerateElements(spObject->hValueObject, vecElements))
			{
				for (const auto& pkValue : vecElements)
				{
					/*
					wprintf(L"Value :: Ver: %u Data: %p (%u), Type: %p\n",
						pkValue.Description->Version, pkValue.Data, pkValue.Description->DataSize, ulElementType
					);
					*/

					ProcessBCDEntry(spObject->hValueObject, pkValue.Description->Type);
				}
			}

			spBCDHelper->CloseObject(spObject->hValueObject);
		}
	}

	return true;
}

bool IsEfiSupported()
{
	UNICODE_STRING uVarName = RTL_CONSTANT_STRING((wchar_t*)L" ");
	PVOID pvVarValue = NULL;
	ULONG ulVarLength = 0;

	return (NtQuerySystemEnvironmentValueEx(&uVarName, (PGUID)&GUID_NULL, pvVarValue, &ulVarLength, NULL) == STATUS_VARIABLE_NOT_FOUND);
}

bool ReadEfiBootEntries()
{
	bool bRet = false;
	PBOOT_OPTIONS pBootOptions = nullptr;
	PULONG pulOrder = nullptr;
	PBOOT_ENTRY_LIST pBootEntryList = nullptr;

	do {
		// Enable privilege to get access to query NVRAM variables
		BOOLEAN boAdjustPrivRet = FALSE;
		auto ntStatus = RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &boAdjustPrivRet);
		if (!NT_SUCCESS(ntStatus))
		{
			wprintf(L"RtlAdjustPrivilege failed: %p\n", ntStatus);
			break;
		}

		// Get the boot options
		ULONG ulLength = 0;
		ntStatus = NtQueryBootOptions(nullptr, &ulLength);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
		{
			wprintf(L"NtQueryBootOptions(1) failed with status 0x%p\n", ntStatus);
			break;
		}

		pBootOptions = (PBOOT_OPTIONS)malloc(ulLength);
		if (!pBootOptions)
		{
			wprintf(L"Failed to allocate memory for BootOptions, Error: %u\n", errno);
			break;
		}

		ntStatus = NtQueryBootOptions(pBootOptions, &ulLength);
		if (ntStatus != STATUS_SUCCESS)
		{
			wprintf(L"NtQueryBootOptions(2) failed with status 0x%p\n", ntStatus);
			break;
		}

		// Get the boot order list
		ULONG ulCount = 0;
		ntStatus = NtQueryBootEntryOrder(NULL, &ulCount);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
		{
			if (ntStatus == STATUS_SUCCESS) // No entries
			{
				ulCount = 0;
			}
			else
			{
				wprintf(L"NtQueryBootEntryOrder(1) failed with status 0x%p\n", ntStatus);
				break;
			}
		}

		if (ulCount)
		{
			pulOrder = (PULONG)malloc(ulCount * sizeof(ULONG));
			if (!pulOrder)
			{
				wprintf(L"Failed to allocate memory for BootEntryOrder, Error: %u\n", errno);
				break;
			}

			ntStatus = NtQueryBootEntryOrder(pulOrder, &ulCount);
			if (ntStatus != STATUS_SUCCESS)
			{
				wprintf(L"NtQueryBootEntryOrder(2) failed with status 0x%p\n", ntStatus);
				break;
			}
		}

		// Get the boot entries
		ulLength = 0;
		ntStatus = NtEnumerateBootEntries(NULL, &ulLength);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
		{
			if (ntStatus == STATUS_SUCCESS) // No entries in NVRAM
			{
				wprintf(L"No entries in NVRAM\n");
				break;
			}
			else
			{
				wprintf(L"NtEnumerateBootEntries(1) failed with status 0x%p\n", ntStatus);
				break;
			}
		}

		if (!ulLength)
		{
			wprintf(L"Invalid length returned by NtEnumerateBootEntries\n");
			break;
		}

		pBootEntryList = (PBOOT_ENTRY_LIST)malloc(ulLength);
		if (!pBootEntryList)
		{
			wprintf(L"Failed to allocate memory for BootEntryList, Error: %u\n", errno);
			break;
		}

		ntStatus = NtEnumerateBootEntries(pBootEntryList, &ulLength);
		if (ntStatus != STATUS_SUCCESS)
		{
			wprintf(L"NtEnumerateBootEntries(2) failed with status 0x%p\n", ntStatus);
			break;
		}

		// Duplicate the boot entry list
		auto pDupBootEntryList = pBootEntryList;
		while (true)
		{
			auto pkBootEntry = &pDupBootEntryList->BootEntry;

			std::wstring wstName = (PWSTR)((PBYTE)pkBootEntry + pkBootEntry->FriendlyNameOffset);
			if (wstName != L"Windows Boot Manager")
			{
				wprintf(L"[*WARNING*] Unknown boot entry: %s", wstName.c_str());
				break;
			}

			// Check another entry
			if (pDupBootEntryList->NextEntryOffset == 0)
				break;

			// Get the next entry
			pDupBootEntryList = (PBOOT_ENTRY_LIST)((PBYTE)pDupBootEntryList + pDupBootEntryList->NextEntryOffset);
		}

		bRet = true;
	} while (FALSE);

	if (pBootOptions)
	{
		free(pBootOptions);
		pBootOptions = nullptr;
	}
	if (pulOrder)
	{
		free(pulOrder);
		pulOrder = nullptr;
	}
	if (pBootEntryList)
	{
		free(pBootEntryList);
		pBootEntryList = nullptr;
	}

	return bRet;
}

bool IsBootSectorFileIntegrityValidated()
{
	const auto wstRootDev = GetRootDevice();
	if (wstRootDev.empty())
	{
		wprintf(L"Failed to get root device\n");
		return false;
	}
	auto wstBootSectorFile = wstRootDev + L"\\bootmgr";
	if (!PathFileExistsW(wstBootSectorFile.c_str()))
	{
		// wprintf(L"Failed to find boot sector file: %s\n", wstBootSectorFile.c_str());
		return true; // false positive
	}

	WIN32_FILE_ATTRIBUTE_DATA wfad{};
	if (!GetFileAttributesExW(wstBootSectorFile.c_str(), GetFileExInfoStandard, &wfad))
	{
		wprintf(L"Failed to get file attributes of boot sector file: %s (Error: %u)\n", wstBootSectorFile.c_str(), GetLastError());
		return false;
	}

	const auto dwAttributes = wfad.dwFileAttributes;
	wprintf(L"Boot sector file attributes: 0x%p\n", dwAttributes);

	// Check if the file is not hidden
	if (!(dwAttributes & FILE_ATTRIBUTE_HIDDEN))
	{
		wprintf(L"[*WARNING*] Boot sector file is not hidden\n");
		return false;
	}

	// Check if the file is system
	if (!(dwAttributes & FILE_ATTRIBUTE_SYSTEM))
	{
		wprintf(L"[*WARNING*] Boot sector file is not system\n");
		return false;
	}

	// Check if the file is read-only
	if (!(dwAttributes & FILE_ATTRIBUTE_READONLY))
	{
		wprintf(L"[*WARNING*] Boot sector file is not read-only\n");
		return false;
	}

	return true;
}

bool IsNVRAMsIntegrityValidated()
{
	auto fnGetNVRAMValue = [](const std::wstring& wstKey, const std::wstring& wstGUID) -> std::vector <uint8_t> {
		auto vecBuffer = std::vector <uint8_t>{};

		if (wstKey.empty() || wstGUID.empty())
			return vecBuffer;

		GUID kGUID{};
		if (!g_spWinAPIs->GUIDFromStringW(wstGUID.c_str(), &kGUID))
		{
			wprintf(L"GUIDFromStringW (%s) failed with error: %u\n", wstGUID.c_str(), GetLastError());
			return vecBuffer;
		}

		UNICODE_STRING uVarName;
		RtlInitUnicodeString(&uVarName, wstKey.c_str());

		ULONG ulLength = 0;
		ULONG ulAttr = 0;
		auto ntStatus = NtQuerySystemEnvironmentValueEx(&uVarName, &kGUID, 0, &ulLength, &ulAttr);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL)
		{
			wprintf(L"NtQuerySystemEnvironmentValueEx(1) failed with status: %p\n", ntStatus);
			return vecBuffer;
		}

		vecBuffer.resize(ulLength);

		ntStatus = NtQuerySystemEnvironmentValueEx(&uVarName, &kGUID, &vecBuffer[0], &ulLength, &ulAttr);
		if (!NT_SUCCESS(ntStatus))
		{
			wprintf(L"NtQuerySystemEnvironmentValueEx(2) failed with status: %p\n", ntStatus);
			return vecBuffer;
		}

		return vecBuffer;
	};

	// TODO https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/overview-of-boot-options-in-efi

	const auto vecBootOrderValue = fnGetNVRAMValue(L"BootOrder", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
	if (vecBootOrderValue.empty())
	{
		wprintf(L"[*WARNING*] Failed to get BootOrder NVRAM value\n");
		return false;
	}
	else if (vecBootOrderValue.size() > 2)
	{
		wprintf(L"[*WARNING*] BootOrder NVRAM value(%u) is invalid, Multiple boot entries are not supported\n", vecBootOrderValue.size());
		return false;
	}

	const auto vecSecureBootValue = fnGetNVRAMValue(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
	if (vecSecureBootValue.empty())
	{
		wprintf(L"[*WARNING*] Failed to get SecureBoot NVRAM value\n");
		return false;
	}
	else if (vecSecureBootValue.size() != 1)
	{
		wprintf(L"[*WARNING*] SecureBoot NVRAM value(%u) is invalid\n", vecSecureBootValue.size());
		return false;
	}
	else if (vecSecureBootValue[0] != 0x01)
	{
		wprintf(L"[*WARNING*] SecureBoot NVRAM value is not enabled\n");
		return false;
	}

	return true;
}


int main()
{
	// Dynamic modules
	const auto hBCD = LoadLibraryW(L"bcd.dll");
	assert(hBCD);

	const auto hShell32 = LoadLibraryW(L"shell32.dll");
	assert(hShell32);

	// Dynamic WinAPIs
	g_spWinAPIs = std::make_shared<SWinAPITable>();
	assert(g_spWinAPIs.get());

	g_spWinAPIs->BcdOpenSystemStore = decltype(g_spWinAPIs->BcdOpenSystemStore)(GetProcAddress(hBCD, "BcdOpenSystemStore"));
	g_spWinAPIs->BcdCloseStore = decltype(g_spWinAPIs->BcdCloseStore)(GetProcAddress(hBCD, "BcdCloseStore"));
	g_spWinAPIs->BcdOpenObject = decltype(g_spWinAPIs->BcdOpenObject)(GetProcAddress(hBCD, "BcdOpenObject"));
	g_spWinAPIs->BcdCloseObject = decltype(g_spWinAPIs->BcdCloseObject)(GetProcAddress(hBCD, "BcdCloseObject"));
	g_spWinAPIs->BcdGetElementData = decltype(g_spWinAPIs->BcdGetElementData)(GetProcAddress(hBCD, "BcdGetElementData"));
	g_spWinAPIs->BcdSetElementData = decltype(g_spWinAPIs->BcdSetElementData)(GetProcAddress(hBCD, "BcdSetElementData"));
	g_spWinAPIs->BcdEnumerateObjects = decltype(g_spWinAPIs->BcdEnumerateObjects)(GetProcAddress(hBCD, "BcdEnumerateObjects"));
	g_spWinAPIs->BcdEnumerateAndUnpackElements = decltype(g_spWinAPIs->BcdEnumerateAndUnpackElements)(GetProcAddress(hBCD, "BcdEnumerateAndUnpackElements"));
	g_spWinAPIs->BcdSetLogging = decltype(g_spWinAPIs->BcdSetLogging)(GetProcAddress(hBCD, "BcdSetLogging"));

	g_spWinAPIs->GUIDFromStringW = (TGUIDFromStringW)(GetProcAddress(hShell32, (LPCSTR)704));
	assert(g_spWinAPIs->GUIDFromStringW);

	// Helper
	const auto spBCDHelper = std::make_shared<CBCDHelper>();
	if (!spBCDHelper || !spBCDHelper.get())
	{
		wprintf(L"Failed to create BCDHelper\n");
		return EXIT_FAILURE;
	}

	// Initialize Helper
	if (!spBCDHelper->Initialize())
	{
		wprintf(L"Failed to initialize BCDHelper\n");
		return EXIT_FAILURE;
	}

	// Anti Rootkit part

	/*
	if (!IsEfiSupported())
	{
		wprintf(L"EFI is not supported in your system, checks skipped!\n");
		return EXIT_FAILURE;
	}
	*/
	
	// Check UEFI entries
	if (!CheckUEFIEntries(spBCDHelper))
		return EXIT_FAILURE;

	if (!CheckBCDEntries(spBCDHelper))
		return EXIT_FAILURE;

	if (!ReadEfiBootEntries())
		return EXIT_FAILURE;

	if (!IsBootSectorFileIntegrityValidated())
		return EXIT_FAILURE;

	if (!IsNVRAMsIntegrityValidated())
		return EXIT_FAILURE;

	/* TODO 
	 * - MBR Validation
	 * - Windows patcher(kmspico, ez activator etc.) specific checks
	 */

	// Release helper resources
	spBCDHelper->Release();

	// Complete
	return EXIT_SUCCESS;
}
