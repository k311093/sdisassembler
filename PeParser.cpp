#include "StdAfx.h"
#include "PeParser.h"
#include <iostream>
#include <Windows.h>
#include <vector>
#include <algorithm>
#include <map>
#include <string>

bool operator==(const IMAGE_IMPORT_DESCRIPTOR desc1, const IMAGE_IMPORT_DESCRIPTOR desc2)
{
	return (memcmp(&desc1, &desc2, sizeof(desc1)) == 0);
}

HRESULT PeParser::Open(const TCHAR* fileName)
{
	HRESULT ret = S_OK;
	HANDLE hFile = NULL;
	HANDLE hMapFile = NULL;
	DWORD* peSignature = NULL;

	size_t sectionIterator = 0;
	PIMAGE_SECTION_HEADER sectionHeader = {0,};
	PIMAGE_SECTION_HEADER modifiedSectionHeader = NULL;
	size_t sectionAlignment = 0;

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_IMPORT_DESCRIPTOR nullDescriptor = {0,};
	PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
	PIMAGE_IMPORT_BY_NAME importByName = {0,};
	DWORD* chunkAddress = NULL;
	DWORD* addressArray = NULL;
	PULONG64 addressArray64 = NULL;
	PULONG64 chunkAddress64 = NULL;
	size_t importIndex = 0;
	size_t addressIndex = 0;
	size_t exportIndex = 0;
	INT_ITEM INTItem = {0,};

	DWORD* nameTable = NULL;
	WORD* ordinalTable = NULL;
	DWORD* addressTable = NULL;
	ENT_ITEM ENTItem = {0,};
	

	hFile = ::CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)	{ ret = E_FAIL; }
	
	if (ret == S_OK)
	{
		hMapFile = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hMapFile == INVALID_HANDLE_VALUE) { ret = E_FAIL; }
	}

	if (ret == S_OK)
	{
		fileBuffer = static_cast<PBYTE>(::MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0));
		if (fileBuffer == NULL) { ret = E_FAIL; }
	}

	if (ret == S_OK)
	{
		dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer);
		if (dosHeader->e_magic != DOS_STUB_MAGIC) { ret = E_FAIL; }
		else
		{
			peSignature = reinterpret_cast<DWORD*>(fileBuffer + dosHeader->e_lfanew);
			if (*peSignature != PE_HEADER_MAGIC) { ret = E_FAIL; }
			else
			{
				fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(fileBuffer + dosHeader->e_lfanew + sizeof(DWORD));
				if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386)
				{
					machineType = MACHINE_X86;
					header32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(fileBuffer + dosHeader->e_lfanew);
					if (header32->OptionalHeader.Magic != PE_HEADER_OPTIONAL32_MAGIC) { ret = E_FAIL; }
					else
					{
						imageBase = header32->OptionalHeader.ImageBase;
						entryPoint = header32->OptionalHeader.AddressOfEntryPoint;
						sectionAlignment = header32->OptionalHeader.SectionAlignment;
					}
				}
				else
				{
					machineType = MACHINE_X64;
					header64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(fileBuffer + dosHeader->e_lfanew);
					if (header64->OptionalHeader.Magic != PE_HEADER_OPTIONAL64_MAGIC) { ret = E_FAIL; }
					else
					{
						imageBase = header64->OptionalHeader.ImageBase;
						entryPoint = header64->OptionalHeader.AddressOfEntryPoint;
						sectionAlignment = header64->OptionalHeader.SectionAlignment;
					}
				}
			}
		}
	}

	if (ret == S_OK)
	{
		sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(fileBuffer + dosHeader->e_lfanew + sizeof(DWORD) 
			+ sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader);
		for (sectionIterator = 0; sectionIterator < fileHeader->NumberOfSections; ++sectionIterator)
		{
			modifiedSectionHeader = new IMAGE_SECTION_HEADER;
			*modifiedSectionHeader = *sectionHeader;
			modifiedSectionHeader->VirtualAddress -= modifiedSectionHeader->VirtualAddress % sectionAlignment;
			sections.push_back(modifiedSectionHeader);
			++sectionHeader;
		}

		if (machineType == MACHINE_X86)
		{
			importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(GetBufferByRVA(header32->OptionalHeader.DataDirectory[1].VirtualAddress));
			exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(GetBufferByRVA(header32->OptionalHeader.DataDirectory[0].VirtualAddress));
		}
		else if (machineType == MACHINE_X64)
		{
			importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(GetBufferByRVA(header64->OptionalHeader.DataDirectory[1].VirtualAddress));
			exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(GetBufferByRVA(header64->OptionalHeader.DataDirectory[0].VirtualAddress));
		}

		importIndex = 0;

		while(!(importDescriptor[importIndex] == nullDescriptor)) 
		{
			dllList.push_back(reinterpret_cast<char*>(GetBufferByRVA(importDescriptor[importIndex].Name)));

			chunkAddress = reinterpret_cast<DWORD*>(GetBufferByRVA(importDescriptor[importIndex].OriginalFirstThunk));
			addressArray = reinterpret_cast<DWORD*>(GetBufferByRVA(importDescriptor[importIndex].FirstThunk));
			for(addressIndex = 0; ;++addressIndex) 
			{
				if (machineType == MACHINE_X86) 
				{
					if (addressArray[addressIndex] == 0) { break; }
					if (IMAGE_SNAP_BY_ORDINAL32(addressArray[addressIndex])) 
					{
						sprintf(INTItem.name, "ordinal_%d", IMAGE_ORDINAL32(addressArray[addressIndex]));
						INTItem.DLLIndex = importIndex;
						INTItem.address = imageBase + importDescriptor[importIndex].FirstThunk + addressIndex * 4;
						INTItem.ordinal = IMAGE_ORDINAL32(addressArray[addressIndex]);
					}
					else 
					{
						importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(GetBufferByRVA(chunkAddress[addressIndex]));
						strcpy(INTItem.name, reinterpret_cast<const char*>(importByName->Name));
						INTItem.DLLIndex = importIndex;
						INTItem.address = imageBase + importDescriptor[importIndex].FirstThunk + addressIndex * 4;
						INTItem.ordinal = importByName->Hint;
					}
				}

				if (machineType == MACHINE_X64) 
				{
					addressArray64 = reinterpret_cast<PULONG64>(addressArray);
					chunkAddress64 = reinterpret_cast<PULONG64>(chunkAddress);

					if (addressArray64[addressIndex] == 0) break;

					if (IMAGE_SNAP_BY_ORDINAL64(addressArray64[addressIndex])) 
					{
						sprintf(INTItem.name, "ordinal_%d", IMAGE_ORDINAL64(addressArray64[addressIndex]));
						INTItem.DLLIndex = importIndex;
						INTItem.address = imageBase + importDescriptor[importIndex].FirstThunk + addressIndex * 8;
						INTItem.ordinal = IMAGE_ORDINAL64(addressArray64[addressIndex]);
					}
					else 
					{
						importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(GetBufferByRVA(chunkAddress64[addressIndex]));
						strcpy(INTItem.name, reinterpret_cast<const char*>(importByName->Name));
						INTItem.DLLIndex = importIndex;
						INTItem.address = imageBase + importDescriptor[importIndex].FirstThunk + addressIndex * 8;
						INTItem.ordinal = importByName->Hint;
					}
				}
				importList.push_back(INTItem);
			}
			++importIndex;
		}

		if (exportDir->NumberOfFunctions != 0)
		{
			nameTable = reinterpret_cast<DWORD*>(GetBufferByRVA(exportDir->AddressOfNames));
			ordinalTable = reinterpret_cast<WORD*>(GetBufferByRVA(exportDir->AddressOfNameOrdinals));
			addressTable = reinterpret_cast<DWORD*>(GetBufferByRVA(exportDir->AddressOfFunctions));

			for (exportIndex = 0; exportIndex < exportDir->NumberOfNames; ++exportIndex) {
				char tmp[256];
				ENTItem.address = addressTable[exportIndex];
				strcpy(ENTItem.name, reinterpret_cast<const char*>(GetBufferByRVA(nameTable[exportIndex])));
				ENTItem.ordinal = ordinalTable[exportIndex];
				//sprintf(tmp, "%s, %d, %016x\n", GetBufferByRVA(nameTable[exportIndex]), ordinalTable[exportIndex], addressTable[exportIndex]);
				//OutputDebugStringA(tmp);

				exportList.push_back(ENTItem);
			}
			exportFunctionAddresses = addressTable;
		}
	}

	return ret;
}

ULONG64 PeParser::RVA2RAW(ULONG64 rva)
{
	ULONG64 raw = 0;
	SECTION_LIST::iterator foundSection = sections.end();

	struct HasAddress
	{
		ULONG64 addr;
		HasAddress(ULONG64 aAddr) : addr(aAddr) {}
		bool operator()(PIMAGE_SECTION_HEADER section)
		{
			return (section->VirtualAddress <= addr) && (addr <= (section->VirtualAddress) + (section->Misc.VirtualSize));
		}
	};
	
	foundSection = std::find_if(sections.begin(), sections.end(), HasAddress(rva));

	if (foundSection != sections.end())
	{
		raw = rva - (*foundSection)->VirtualAddress + (*foundSection)->PointerToRawData;
	}
	else { raw = NULL; }

	return raw;
}

PBYTE PeParser::GetEntryPoint()
{
	PBYTE ret = NULL;

	ret = fileBuffer + RVA2RAW(entryPoint);

	return ret;
}

PBYTE PeParser::GetVirtualMemoryBuffer(ULONG64 address)
{
	PBYTE ret = NULL;

	ret = fileBuffer + RVA2RAW(address - imageBase);

	return ret;
}

PBYTE PeParser::GetBufferByRVA(ULONG64 rva)
{
	PBYTE ret = NULL;

	ret = fileBuffer + RVA2RAW(rva);

	return ret;
}

std::map<std::wstring, PeParser*> dllmap;

ULONG64 PeParser::GetFuncAddr(char* name)
{
	int i;

	if (!strncmp(name, "ordinal_", 8)) {
		int ordinal = atoi(name+8);
		return exportFunctionAddresses[ordinal];
	}
	else 
	{
		for(i=0;i<exportList.size(); i++) {
			if (!strcmp(name, exportList[i].name)) {
				return exportList[i].address;
			}
		}
	}

	return 0;
}

char* PeParser::callName(ULONG64 addr, char outName[])
{
	INTList::iterator foundIterator = importList.end();

	struct MatchAddress
	{
		ULONG64 addr;
		MatchAddress(ULONG64 aAddr) : addr(aAddr) {}
		bool operator()(INT_ITEM item)
		{
			return (item.address == addr);
		}
	};

	outName[0] = 0;

	foundIterator = find_if(importList.begin(), importList.end(), MatchAddress(addr));

	if (foundIterator == importList.end()) { strcpy(outName, ""); }

	else {
		TCHAR dllPath[256];
		TCHAR fileName[256];

		PeParser* dllFile;

		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, dllList[foundIterator->DLLIndex], strlen(dllList[foundIterator->DLLIndex])+1, fileName, 256);

		wsprintf(dllPath, _T("c:\\dlls\\%s"), fileName);

		if(dllmap.find(dllPath) == dllmap.end()) {
			dllFile = new PeParser();
			dllmap[dllPath] = dllFile;
			if (dllFile->Open(dllPath) == E_FAIL)
			{
				OutputDebugString(dllPath);
				return "";
			}
		}
		else {
			dllFile = dllmap[dllPath];
		}

		if (!strncmp(foundIterator->name, "ordinal_", 8)) {
			for(int i=0;i<dllFile->exportList.size();i++) {
				if(foundIterator->ordinal == dllFile->exportList[i].ordinal)
					sprintf(outName, "%s!%s", dllList[foundIterator->DLLIndex], dllFile->exportList[i].name);
			}
		}
		else 
		{
			sprintf(outName, "%s!%s", dllList[foundIterator->DLLIndex], foundIterator->name);
		}
	}

	if (!strcmp(outName, "")) { strcpy(outName, "none"); }

	return outName;
}

void PeParser::Test()
{

}

PeParser::PeParser(void)
{
}

PeParser::~PeParser(void)
{
	struct SafeDelete
	{
		void operator()(PIMAGE_SECTION_HEADER item)
		{
			if (item != NULL) { delete item; }
		}
	};

	for_each(sections.begin(), sections.end(), SafeDelete());

	sections.clear();
	importList.clear();
}
