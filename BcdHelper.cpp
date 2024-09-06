#include "BcdHelper.hpp"
#include <assert.h>

// c&p compability stuffs
inline const wchar_t* convert(const std::wstring& str) { return str.c_str(); }
inline const wchar_t* convert(const wchar_t* str) { return str; }
template <typename T> inline T convert(const T& val) { return val; }

template <typename... Args>
void log_fn(int lv, const wchar_t* fmt, Args... args) {
	fwprintf(stdout, fmt, convert(args)...);
	fwprintf(stdout, L"\n");
}
enum dummy_ll
{
	LL_ERR,
	LL_WARN,
	LL_SYS
};
#define APP_TRACE_LOG(dummy, format, ...) log_fn(0, format, __VA_ARGS__)
// ---


CBCDHelper::CBCDHelper() :
	m_hBCDStore(nullptr)
{
}
CBCDHelper::~CBCDHelper()
{
}

bool CBCDHelper::Initialize()
{
	const auto ntStatus = g_spWinAPIs->BcdOpenSystemStore(&m_hBCDStore);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD store open failed with status: %p", ntStatus);
		return false;
	}
	return true;
}
void CBCDHelper::Release()
{
	if (m_hBCDStore)
	{
		const auto ntStatus = g_spWinAPIs->BcdCloseStore(m_hBCDStore);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"BCD store close failed with status: %p", ntStatus);
		}
		m_hBCDStore = nullptr;
	}
}

void CBCDHelper::SetVerbose()
{
	const auto ntStatus = g_spWinAPIs->BcdSetLogging(BCD_MESSAGE_TYPE_TRACE, [](BCD_MESSAGE_TYPE type, PWSTR Message) {
		APP_TRACE_LOG(LL_SYS, L"[BCD] %d >> %ls", type, Message);
		});
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD set logging failed with status: %p", ntStatus);
	}
}

bool CBCDHelper::OpenObject(PGUID pvIdentifierGUID, PHANDLE phObject)
{
	if (!m_hBCDStore)
		return false;

	HANDLE hBCDObject = nullptr;
	const auto ntStatus = g_spWinAPIs->BcdOpenObject(m_hBCDStore, pvIdentifierGUID, &hBCDObject);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD object open failed with status: %p", ntStatus);
		return false;
	}

	if (phObject) *phObject = hBCDObject;
	return true;
}
bool CBCDHelper::CloseObject(HANDLE hObject)
{
	if (!m_hBCDStore)
		return false;

	const auto ntStatus = g_spWinAPIs->BcdCloseObject(hObject);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD object close failed with status: %p", ntStatus);
		return false;
	}
	return true;
}

bool CBCDHelper::GetElementData(HANDLE hObject, ULONG ulElementType, PVOID pvBuffer, PULONG pulBufferSize)
{
	if (!m_hBCDStore)
		return false;

	const auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, pvBuffer, pulBufferSize);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
		return false;
	}
	return true;
}
bool CBCDHelper::GetElementDataFrom(ULONG ulElementType, GUID guidID, PVOID pvBuffer, PULONG pulBufferSize)
{
	if (!m_hBCDStore)
		return false;

	HANDLE hBCDObject = nullptr;
	auto ntStatus = g_spWinAPIs->BcdOpenObject(m_hBCDStore, &guidID, &hBCDObject);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD object open failed with status: %p", ntStatus);
		return false;
	}

	ntStatus = g_spWinAPIs->BcdGetElementData(hBCDObject, ulElementType, pvBuffer, pulBufferSize);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
	}

	if (hBCDObject)
	{
		g_spWinAPIs->BcdCloseObject(hBCDObject);
		hBCDObject = nullptr;
	}
	return NT_SUCCESS(ntStatus);
}
bool CBCDHelper::SetElementData(HANDLE hObject, ULONG ulElementType, PVOID pvBuffer, ULONG BufferSize)
{
	if (!m_hBCDStore)
		return false;

	const auto ntStatus = g_spWinAPIs->BcdSetElementData(hObject, ulElementType, pvBuffer, BufferSize);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data set failed with status: %p", ntStatus);
		return false;
	}
	return true;
}

bool CBCDHelper::GetElementDevice(HANDLE hObject, ULONG ulElementType, std::shared_ptr <BCD_ELEMENT_DEVICE>& spElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_DEVICE);

	if (!m_hBCDStore)
		return false;

	auto spValueBuffer = std::make_shared<BCD_ELEMENT_DEVICE>();
	ULONG ulValueLength = sizeof(BCD_ELEMENT_DEVICE);
	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, spValueBuffer.get(), &ulValueLength);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
		return false;
	}

	spElementData = std::move(spValueBuffer);
	return true;
}
bool CBCDHelper::GetElementString(HANDLE hObject, ULONG ulElementType, std::wstring& wstElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_STRING);

	if (!m_hBCDStore)
		return false;

	ULONG ulStringLength = 0x80;
	auto wstBuffer = std::wstring(ulStringLength, L'\0');
	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, (PVOID)wstBuffer.data(), &ulStringLength);
	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		wstBuffer.resize(ulStringLength);

		ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, (PVOID)wstBuffer.data(), &ulStringLength);
	}

	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
		return false;
	}

	wstElementData = wstBuffer;
	return true;
}
bool CBCDHelper::GetElementObject(HANDLE hObject, ULONG ulElementType, GUID& pkElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_OBJECT);

	if (!m_hBCDStore)
		return false;

	GUID pkValue{};
	ULONG ulValueLength = sizeof(pkValue);

	const auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &pkValue, &ulValueLength);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
		return false;
	}

	pkElementData = pkValue;
	return NT_SUCCESS(ntStatus);
}
bool CBCDHelper::GetElementObjectList(HANDLE hObject, ULONG ulElementType, std::vector <GUID>& vecElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_OBJECTLIST);

	if (!m_hBCDStore)
		return false;

	ULONG ulValueLength = 1;
	std::vector <GUID> vecValue(ulValueLength);
	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vecValue.data(), &ulValueLength);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get (1) failed with status: %p", ntStatus);
		return false;
	}

	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		vecValue.resize(ulValueLength);

		ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vecValue.data(), &ulValueLength);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"BCD element data get (2) failed with status: %p", ntStatus);
			return false;
		}
	}

	vecElementData = std::move(vecValue);
	return true;
}
bool CBCDHelper::GetElementInteger(HANDLE hObject, ULONG ulElementType, ULONG64& pul64ElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_INTEGER);

	if (!m_hBCDStore)
		return false;

	ULONG ulValueLength = sizeof(ULONG64);
	ULONG64 ul64ValueBuffer = 0;

	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &ul64ValueBuffer, &ulValueLength);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get failed with status: %p", ntStatus);
		return false;
	}

	pul64ElementData = ul64ValueBuffer;
	return true;
}
bool CBCDHelper::GetElementIntegerList(HANDLE hObject, ULONG ulElementType, std::vector <ULONG64>& vecElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_INTEGERLIST);

	if (!m_hBCDStore)
		return false;

	ULONG ulValueLength = 1;
	std::vector <ULONG64> vecValue(ulValueLength);
	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vecValue.data(), &ulValueLength);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get (1) failed with status: %p", ntStatus);
		return false;
	}

	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		vecValue.resize(ulValueLength);

		ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vecValue.data(), &ulValueLength);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"BCD element data get (2) failed with status: %p", ntStatus);
			return false;
		}
	}

	vecElementData = std::move(vecValue);
	return true;
}
bool CBCDHelper::GetElementBoolean(HANDLE hObject, ULONG ulElementType, bool& pkElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_BOOLEAN);

	if (!m_hBCDStore)
		return false;

	ULONG ulValueLength = sizeof(BOOLEAN);
	BOOLEAN boValueBuffer = FALSE;

	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &boValueBuffer, &ulValueLength);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_WARN, L"BCD element data get first attempt failed with status: %p, Required length: %u", ntStatus, ulValueLength);

		uint64_t tempBuffer = 0;
		if (ulValueLength == 2)
		{
			uint16_t u16ValueBuffer = 0;
			ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &u16ValueBuffer, &ulValueLength);
			tempBuffer = u16ValueBuffer;
		}
		else if (ulValueLength == 4)
		{
			uint32_t u32ValueBuffer = 0;
			ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &u32ValueBuffer, &ulValueLength);
			tempBuffer = u32ValueBuffer;
		}
		else if (ulValueLength == 8)
		{
			uint64_t u64ValueBuffer = 0;
			ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, &u64ValueBuffer, &ulValueLength);
			tempBuffer = u64ValueBuffer;
		}

		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"BCD element data get second attempt failed with status: %p", ntStatus);
			return false;
		}

		boValueBuffer = (tempBuffer != 0);
	}

	pkElementData = (boValueBuffer != FALSE);
	return true;
}
bool CBCDHelper::GetElementBinary(HANDLE hObject, ULONG ulElementType, std::vector <uint8_t>& vElementData)
{
	assert(GET_BCDE_DATA_FORMAT(ulElementType) == BCD_ELEMENT_DATATYPE_FORMAT_BINARY);

	if (!m_hBCDStore)
		return false;

	ULONG ulValueLength = 1;
	auto vBuffer = std::vector<uint8_t>(ulValueLength, 0);

	auto ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vBuffer.data(), &ulValueLength);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element data get (1) failed with status: %p", ntStatus);
		return false;
	}

	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		vBuffer.resize(ulValueLength);

		ntStatus = g_spWinAPIs->BcdGetElementData(hObject, ulElementType, vBuffer.data(), &ulValueLength);

		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"BCD element data get (2) failed with status: %p", ntStatus);
			return false;
		}
	}

	vElementData = std::move(vBuffer);
	return NT_SUCCESS(ntStatus);
}

NTSTATUS CBCDHelper::EnumerateElements(HANDLE hObject, PVOID pvBuffer, PULONG pulBufferSize, PULONG pulElementCount)
{
	if (!m_hBCDStore)
		return false;

	const auto kEnumFlags = static_cast<BCD_FLAGS>(BCD_FLAG_ENUMERATE_INHERITED_OBJECTS | BCD_FLAG_ENUMERATE_DEVICE_OPTIONS);

	const auto ntStatus = g_spWinAPIs->BcdEnumerateAndUnpackElements(m_hBCDStore, hObject, kEnumFlags, pvBuffer, pulBufferSize, pulElementCount);
	if (!NT_SUCCESS(ntStatus))
	{
		const auto bIsError = (ntStatus != STATUS_BUFFER_TOO_SMALL);
		APP_TRACE_LOG(bIsError ? LL_ERR : LL_WARN, L"BCD element enumeration failed with status: %p", ntStatus);
		return ntStatus;
	}
	return STATUS_SUCCESS;
}
bool CBCDHelper::EnumerateElements(HANDLE hObject, std::vector <BCD_ELEMENT>& vecElements)
{
	if (!m_hBCDStore)
		return false;

	ULONG ulBufferSize = vecElements.size();
	ULONG ulElementCount = 0;

	auto ntStatus = this->EnumerateElements(hObject, vecElements.data(), &ulBufferSize, &ulElementCount);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL)
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element enumeration (1) failed with status: %p", ntStatus);
		return false;
	}
	vecElements.resize(ulBufferSize);

	ntStatus = this->EnumerateElements(hObject, vecElements.data(), &ulBufferSize, &ulElementCount);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD element enumeration (2) failed with status: %p", ntStatus);
		return false;
	}
	vecElements.resize(ulElementCount);

	return true;
}

NTSTATUS CBCDHelper::EnumerateObjects(PBCD_OBJECT_DESCRIPTION pkEnumDescriptor, PVOID pvBuffer, PULONG pulBufferSize, PULONG pulObjectCount)
{
	if (!m_hBCDStore)
		return false;

	const auto ntStatus = g_spWinAPIs->BcdEnumerateObjects(m_hBCDStore, pkEnumDescriptor, pvBuffer, pulBufferSize, pulObjectCount);
	if (!NT_SUCCESS(ntStatus))
	{
		APP_TRACE_LOG(LL_ERR, L"BCD object enumeration failed with status: %p", ntStatus);
		return ntStatus;
	}
	return STATUS_SUCCESS;
}
bool CBCDHelper::EnumerateOsLoaderList(std::vector <std::shared_ptr <SBCDObjectEntry>>& vecObjects)
{
	BCD_OBJECT_DESCRIPTION kEnumDescriptor{};
	kEnumDescriptor.Version = BCD_OBJECT_DESCRIPTION_VERSION;
	kEnumDescriptor.Type = BCD_OBJECT_OSLOADER_TYPE;

	ULONG ulObjectCount = 0;
	ULONG ulObjectSize = 0;
	PBCD_OBJECT pObjectBuffer = nullptr;
	auto ntStatus = this->EnumerateObjects(&kEnumDescriptor, pObjectBuffer, &ulObjectSize, &ulObjectCount);
	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		pObjectBuffer = static_cast<PBCD_OBJECT>(malloc(ulObjectSize));
		ntStatus = this->EnumerateObjects(&kEnumDescriptor, pObjectBuffer, &ulObjectSize, &ulObjectCount);
	}
	if (!NT_SUCCESS(ntStatus) || !pObjectBuffer)
	{
		APP_TRACE_LOG(LL_ERR, L"BCD object enumeration failed with status: %p", ntStatus);
		if (pObjectBuffer)
		{
			free(pObjectBuffer);
			pObjectBuffer = nullptr;
		}
		return false;
	}

	for (std::size_t i = 0; i < ulObjectCount; i++)
	{
		HANDLE hObject = nullptr;
		if (!this->OpenObject(&pObjectBuffer[i].Identifer, &hObject))
			continue;

		std::wstring objectDescription;
		if (this->GetElementString(hObject, BcdLibraryString_Description, objectDescription))
		{
			auto entry = std::make_shared<SBCDObjectEntry>();
			if (entry && entry.get())
			{
				memcpy(&entry->guidObject, &pObjectBuffer[i].Identifer, sizeof(GUID));
				entry->wstObjectName = objectDescription;

				vecObjects.push_back(entry);
			}
		}

		this->CloseObject(hObject);
	}

	free(pObjectBuffer);
	pObjectBuffer = nullptr;

	return true;
}
bool CBCDHelper::EnumerateBootMgrList(PGUID Identifier, ULONG ElementType, std::vector <std::shared_ptr <SBCDObjectEntry>>& vecObjects)
{
	HANDLE hObject = nullptr;
	if (!this->OpenObject(Identifier, &hObject))
		return false;

	BCD_ELEMENT_OBJECT_LIST kElementObjectList[64]{};
	ULONG ulObjectListLength = sizeof(kElementObjectList);
	if (!this->GetElementData(hObject, ElementType, kElementObjectList, &ulObjectListLength))
	{
		this->CloseObject(hObject);
		return false;
	}

	for (ULONG i = 0; i < ulObjectListLength / sizeof(BCD_ELEMENT_OBJECT_LIST); i++)
	{
		HANDLE hEntryObject = nullptr;
		if (!this->OpenObject(&kElementObjectList->ObjectList[i], &hEntryObject))
			continue;

		std::wstring wstObjectEntryDescription;
		if (this->GetElementString(hEntryObject, BcdLibraryString_Description, wstObjectEntryDescription))
		{
			auto entry = std::make_shared<SBCDObjectEntry>();
			if (entry && entry.get())
			{
				memcpy(&entry->guidObject, &kElementObjectList->ObjectList[i], sizeof(GUID));
				entry->wstObjectName = wstObjectEntryDescription;

				vecObjects.push_back(entry);
			}
		}

		this->CloseObject(hEntryObject);
	}

	this->CloseObject(hObject);
	return true;
}
bool CBCDHelper::EnumerateValueObjects(PGUID Identifier, ULONG ElementType, std::vector <std::shared_ptr <SBCDObjectValueEntry>>& vecObjects)
{
	HANDLE hObject = nullptr;
	if (!this->OpenObject(Identifier, &hObject))
		return false;

	BCD_ELEMENT_OBJECT_LIST kElementObjectList[64]{};
	ULONG ulObjectListLength = sizeof(kElementObjectList);
	if (!this->GetElementData(hObject, ElementType, kElementObjectList, &ulObjectListLength))
	{
		this->CloseObject(hObject);
		return false;
	}

	for (ULONG i = 0; i < ulObjectListLength / sizeof(BCD_ELEMENT_OBJECT_LIST); i++)
	{
		HANDLE hEntryObject = nullptr;
		if (!this->OpenObject(&kElementObjectList->ObjectList[i], &hEntryObject))
			continue;

		auto entry = std::make_shared<SBCDObjectValueEntry>();
		if (entry && entry.get())
		{
			entry->guidObject = kElementObjectList->ObjectList[i];
			entry->hValueObject = hEntryObject;

			vecObjects.push_back(entry);
		}
	}

	this->CloseObject(hObject);
	return true;
}

std::vector <std::shared_ptr <SBCDObjectEntry>> CBCDHelper::QueryBootApplicationList(bool EnumerateAllObjects)
{
	std::vector <std::shared_ptr <SBCDObjectEntry>> vecObjects;

	if (EnumerateAllObjects)
	{
		this->EnumerateOsLoaderList(vecObjects);
	}
	else
	{
		this->EnumerateBootMgrList((PGUID)&GUID_WINDOWS_BOOTMGR, BcdBootMgrObjectList_DisplayOrder, vecObjects);

		this->EnumerateBootMgrList((PGUID)&GUID_WINDOWS_BOOTMGR, BcdBootMgrObjectList_ToolsDisplayOrder, vecObjects);
	}

	return vecObjects;
}

std::vector <std::shared_ptr <SBCDObjectEntry>> CBCDHelper::QueryFirmwareBootApplicationList()
{
	std::vector <std::shared_ptr <SBCDObjectEntry>> vecObjects;

	this->EnumerateBootMgrList((PGUID)&GUID_FIRMWARE_BOOTMGR, BcdBootMgrObjectList_DisplayOrder, vecObjects);

	this->EnumerateBootMgrList((PGUID)&GUID_FIRMWARE_BOOTMGR, BcdBootMgrObjectList_ToolsDisplayOrder, vecObjects);

	return vecObjects;
}
