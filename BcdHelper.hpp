#pragma once
#include "phnt.h"
#include <vector>
#include <memory>
#include <string>

typedef BOOL(WINAPI* TGUIDFromStringW)(LPCTSTR psz, LPGUID pguid);
struct SWinAPITable
{
	decltype(&BcdCloseObject) BcdCloseObject{ nullptr };
	decltype(&BcdCloseStore) BcdCloseStore{ nullptr };
	decltype(&BcdEnumerateAndUnpackElements) BcdEnumerateAndUnpackElements{ nullptr };
	decltype(&BcdEnumerateObjects) BcdEnumerateObjects{ nullptr };
	decltype(&BcdGetElementData) BcdGetElementData{ nullptr };
	decltype(&BcdOpenObject) BcdOpenObject{ nullptr };
	decltype(&BcdOpenSystemStore) BcdOpenSystemStore{ nullptr };
	decltype(&BcdSetElementData) BcdSetElementData{ nullptr };
	decltype(&BcdSetLogging) BcdSetLogging{ nullptr };

	TGUIDFromStringW GUIDFromStringW;
};
extern std::shared_ptr <SWinAPITable> g_spWinAPIs;

struct SBCDObjectEntry
{
	GUID guidObject;
	std::wstring wstObjectName;
};
struct SBCDObjectValueEntry
{
	GUID guidObject;
	HANDLE hValueObject;
};

class CBCDHelper
{
public:
	CBCDHelper();
	~CBCDHelper();

	bool Initialize();
	void Release();

	void SetVerbose();

	bool OpenObject(PGUID pvIdentifierGUID, PHANDLE phObject);
	bool CloseObject(HANDLE hObject);

	//	protected:
	bool GetElementData(HANDLE hObject, ULONG ulElementType, PVOID pvBuffer, PULONG pulBufferSize);
	bool GetElementDataFrom(ULONG ulElementType, GUID guidID, PVOID pvBuffer, PULONG pulBufferSize);
	bool SetElementData(HANDLE hObject, ULONG ulElementType, PVOID pvBuffer, ULONG BufferSize);

	bool GetElementDevice(HANDLE hObject, ULONG ulElementType, std::shared_ptr <BCD_ELEMENT_DEVICE>& spElementData);
	bool GetElementString(HANDLE hObject, ULONG ulElementType, std::wstring& wstElementData);
	bool GetElementObject(HANDLE hObject, ULONG ulElementType, GUID& pkElementData);
	bool GetElementObjectList(HANDLE hObject, ULONG ulElementType, std::vector <GUID>& vecElementData);
	bool GetElementInteger(HANDLE hObject, ULONG ulElementType, ULONG64& pul64ElementData);
	bool GetElementIntegerList(HANDLE hObject, ULONG ulElementType, std::vector <ULONG64>& vecElementData);
	bool GetElementBoolean(HANDLE hObject, ULONG ulElementType, bool& pkElementData);
	bool GetElementBinary(HANDLE hObject, ULONG ulElementType, std::vector <uint8_t>& vElementData);

	NTSTATUS EnumerateObjects(PBCD_OBJECT_DESCRIPTION pkEnumDescriptor, PVOID pvBuffer, PULONG pulBufferSize, PULONG pulObjectCount);
	bool EnumerateOsLoaderList(std::vector <std::shared_ptr <SBCDObjectEntry>>& vecObjects);
	bool EnumerateBootMgrList(PGUID Identifier, ULONG ElementType, std::vector <std::shared_ptr <SBCDObjectEntry>>& vecObjects);
	bool EnumerateValueObjects(PGUID Identifier, ULONG ElementType, std::vector <std::shared_ptr <SBCDObjectValueEntry>>& vecObjects);

public:
	NTSTATUS EnumerateElements(HANDLE hObject, PVOID pvBuffer, PULONG pulBufferSize, PULONG pulElementCount);
	bool EnumerateElements(HANDLE hObject, std::vector <BCD_ELEMENT>& vecElements);

	std::vector <std::shared_ptr <SBCDObjectEntry>> QueryBootApplicationList(bool EnumerateAllObjects);

	std::vector <std::shared_ptr <SBCDObjectEntry>> QueryFirmwareBootApplicationList();

private:
	HANDLE m_hBCDStore;
};
