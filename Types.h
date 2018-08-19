#ifndef _TYPES_H_
#define _TYPES_H_

#include <vector>
#include <windows.h>

/*
	MOD 
		[]			00
		[] + disp8	01
		[] + disp32 10
		REG			11

	R/M
		EAX / AX / AL / MM0 / XMM0	000
		ECX / CX / CL / MM1 / XMM1	001
		EDX / DX / DL / MM2 / XMM2	010
		EBX / BX / BL / MM3 / XMM3	011
		ESP / SP / AH / MM4 / XMM4	100
		[--][--]					100
		EBP / BP / CH / MM5 / XMM5	101
		ESI / SI / DH / MM6 / XMM6	110
		EDI / DI / BH / MM7 / XMM7	111

	SIB
		Scale	00 = x1
				01 = x2
				10 = x4
				11 = x8
		Scale Reg
				AX		000
				CX		001
				DX		010
				BX		011
				None	100
				BP		101
				SI		110
				DI		111
		Base
				AX		000
				CX		001
				DX		010
				BX		011
				SP		100
				[*]		101
				SI		110
				DI		111

		[*] = 
		MOD bits	Effective Address
		00			[scaled index] + disp32
		01			[scaled index] + disp8 + [EBP]
		10			[scaled index] + disp32 + [EBP]
*/

typedef unsigned char BYTE, *PBYTE;
typedef unsigned long long ULONG64, *PULONG64;

enum ADDRESSING_MODE
{
	ADDRMODE_NONE = 0x00,
	ADDRMODE_A, ADDRMODE_BA, ADDRMODE_BB, ADDRMODE_BD, ADDRMODE_C, ADDRMODE_D, ADDRMODE_E, ADDRMODE_ES, ADDRMODE_EST, ADDRMODE_F,
	ADDRMODE_G, ADDRMODE_H, ADDRMODE_I, ADDRMODE_J, ADDRMODE_M, ADDRMODE_N, ADDRMODE_O, ADDRMODE_P, ADDRMODE_Q, ADDRMODE_R, ADDRMODE_S,
	ADDRMODE_SC,ADDRMODE_T, ADDRMODE_U, ADDRMODE_V, ADDRMODE_W, ADDRMODE_X, ADDRMODE_Y, ADDRMODE_Z, ADDRMODE_S2, ADDRMODE_S30, ADDRMODE_S33,
	ADDRMODE_AL, ADDRMODE_CS, ADDRMODE_SS, ADDRMODE_DS, ADDRMODE_DX, ADDRMODE_ST, ADDRMODE_AX, ADDRMODE_UD, ADDRMODE_FS, ADDRMODE_GS, ADDRMODE_CL,
};

enum OPERAND_TYPE
{
	OPTYPE_NONE = 0x00,
	OPTYPE_A, OPTYPE_B, OPTYPE_BCD, OPTYPE_BS, OPTYPE_BSQ, OPTYPE_BSS, OPTYPE_C, OPTYPE_D, OPTYPE_DI, OPTYPE_DQ, OPTYPE_DQP,
	OPTYPE_DR, OPTYPE_DS, OPTYPE_E, OPTYPE_ER, OPTYPE_P, OPTYPE_PI, OPTYPE_PD, OPTYPE_PS, OPTYPE_PSQ, OPTYPE_PT, OPTYPE_PTP,
	OPTYPE_Q, OPTYPE_QI, OPTYPE_QP, OPTYPE_S, OPTYPE_SD, OPTYPE_SI, OPTYPE_SR, OPTYPE_SS, OPTYPE_ST, OPTYPE_STX, OPTYPE_T,
	OPTYPE_V, OPTYPE_VDS, OPTYPE_VQ, OPTYPE_VQP, OPTYPE_VS, OPTYPE_W, OPTYPE_WI, OPTYPE_VA, OPTYPE_DQA, OPTYPE_WA, OPTYPE_WO,
	OPTYPE_WS, OPTYPE_DA, OPTYPE_DO, OPTYPE_QA, OPTYPE_QS, OPTYPE_RAX, OPTYPE_EAX, OPTYPE_NUM, OPTYPE_NULL,
};

enum SIB_TYPE
{
	SIB_TYPE_NONE = 0x00,
	SIB_TYPE_NORMAL, SIB_TYPE_ASTERISK,
};

struct OPERAND_SIZE
{
	bool signExtended;
	size_t size;
};

enum MACHINE_TYPE
{
	MACHINE_NONE = 0x00,
	MACHINE_X86, MACHINE_X64,
};

#define PREFIX_NONE					0xFF
#define PREFIX_LOCK					0xF0
#define PREFIX_REPNE				0xF2
#define PREFIX_REPNZ				0xF2
#define PREFIX_REPE					0xF3
#define PREFIX_REPZ					0xF3
#define PREFIX_SEGMENT_CS			0x2E
#define PREFIX_SEGMENT_SS			0x36
#define PREFIX_SEGMENT_DS			0x3E
#define PREFIX_SEGMENT_ES			0x26
#define PREFIX_SEGMENT_FS			0x64
#define PREFIX_SEGMENT_GS			0x65
#define PREFIX_BRANCH_TAKEN			0x2E
#define PREFIX_BRANCH_NOT_TAKEN		0x3E
#define PREFIX_OPERAND_SIZE			0x66
#define PREFIX_ADDRESS_SIZE			0x67

#pragma pack(1)

union REX
{
	struct REXBits 
	{
		BYTE B : 1;
		BYTE X : 1;
		BYTE R : 1;
		BYTE W : 1;
		BYTE REXPrefix : 4;
	} bitData;

	BYTE byteData;

	bool IsValidREX() const { return this->bitData.REXPrefix == 0x4; }
	void operator=(BYTE inByte) { this->byteData = inByte; }
};

union MODRM
{
	struct MODRMBITS
	{
		BYTE RM : 3;
		BYTE REG : 3;
		BYTE MOD : 2;
	} bitData;

	BYTE byteData;

	bool NeedSib() { return this->bitData.MOD != 0x03 && this->bitData.RM == 0x04; }
};

union SIB
{
	struct SIBBITS
	{
		BYTE BASE : 3;
		BYTE INDEX : 3;
		BYTE SCALE : 2;
	} bitData;

	BYTE byteData;

	size_t GetScale() { return (static_cast<size_t>(1) << bitData.SCALE); }
};

inline bool IsREX(BYTE inByte)
{
	REX rex = {0,};

	rex = inByte;

	return rex.IsValidREX();
}

inline bool IsPrefix(BYTE inByte)
{
	static BYTE prefixArray[] = {PREFIX_LOCK, PREFIX_REPNE, PREFIX_REPE, PREFIX_SEGMENT_CS, PREFIX_SEGMENT_DS, PREFIX_SEGMENT_ES, 
		PREFIX_SEGMENT_FS, PREFIX_SEGMENT_GS, PREFIX_BRANCH_TAKEN, PREFIX_BRANCH_NOT_TAKEN, PREFIX_OPERAND_SIZE, PREFIX_ADDRESS_SIZE};
	int i;

	for (i = 0; i < sizeof(prefixArray)/sizeof(BYTE); i++)
	{
		if (prefixArray[i] == inByte) { return true; }
	}

	return false;
}

struct OPERAND
{
	unsigned short addrMode : 6;
	unsigned short opType : 6;
	unsigned short numValue : 4;
};

struct INST_TYPE
{
	BYTE x64 : 1;
	BYTE num : 1;
	BYTE mem : 1;
	BYTE no_mem : 1;
	BYTE prefix : 1;
	BYTE second : 1;
	BYTE mem_value : 2;
	BYTE num_value : 3;
	BYTE mem_all : 1;
	BYTE prefix_value;
	BYTE second_value;
};

struct INSTRUCTION
{
	unsigned short opCode;
	unsigned short mnemonic;
	struct INST_TYPE instType;
	struct OPERAND operand[3];
};

struct OPERAND_USES
{
	bool modrm;
	bool sib;
	size_t immediate;
	size_t disp;
};

struct INSTRUCTION_OPTION
{
	MACHINE_TYPE machineType;
	bool hasPrefix;
	BYTE prefix;
	bool hasRex;
	REX rex;
};

#pragma pack()

struct INT_ITEM
{
	size_t DLLIndex;
	char name[256];
	size_t ordinal;
	ULONG64 address;
};

struct ENT_ITEM
{
	char name[256];
	size_t ordinal;
	ULONG64 address;
};

typedef std::vector<INT_ITEM> INTList; 
typedef std::vector<ENT_ITEM> ENTList; 
typedef std::vector<char*> DLLNameList;

#define DOS_STUB_MAGIC 0x5a4d
#define PE_HEADER_MAGIC 0x4550
#define PE_HEADER_OPTIONAL32_MAGIC 0x10b
#define PE_HEADER_OPTIONAL64_MAGIC 0x20b

#define EXTREGISTER_INDEX 8
#define REGISTERSTR_SIZE 5

typedef unsigned char BYTE;
typedef std::vector<IMAGE_SECTION_HEADER*> SECTION_LIST;

#endif /* _TYPES_H_ */