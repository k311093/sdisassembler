#ifndef _PEPARSER_H_
#define _PEPARSER_H_

#include "stdafx.h"
#include "Types.h"
#include <windows.h>
#include <vector>

class PeParser
{
public:
	HRESULT Open(const TCHAR* fileName);
	ULONG64 GetImageBase() const { return imageBase; }
	PBYTE GetEntryPoint();
	MACHINE_TYPE GetMachineType() const { return machineType; }
	ULONG64 GetEntryPointAddr() { return imageBase+entryPoint; }
	ULONG64 GetImageBase() { return imageBase; }
	PBYTE GetVirtualMemoryBuffer(ULONG64 address);
	PBYTE GetBufferByRVA(ULONG64 rva);
	ULONG64 GetFuncAddr(char* name);
	char* callName(ULONG64 addr, char outName[]);
	void Test();

	PeParser(void);
	~PeParser(void);
private:
	ULONG64 RVA2RAW(ULONG64 rva);

	SECTION_LIST sections;
	PIMAGE_FILE_HEADER fileHeader;
	MACHINE_TYPE machineType;
	PBYTE fileBuffer;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS32 header32;
	PIMAGE_NT_HEADERS64 header64;
	ULONG64 imageBase;
	ULONG64 entryPoint;
	INTList importList;
	ENTList exportList;
	DWORD* exportFunctionAddresses;
	DLLNameList dllList;
};

#endif /* _PEPARSER_H_ */