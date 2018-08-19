#include "stdafx.h"

#include "InstructionParser.h"

#include "Types.h"
#include "OpCodeTab.h"
#include "Mnemonics.h"

const char* InstructionParser::GP_REG_64 = "rax\0\0rcx\0\0rdx\0\0rbx\0\0rsp\0\0rbp\0\0rsi\0\0rdi\0\0r8\0\0\0r9\0\0\0r10\0\0r11\0\0r12\0\0r13\0\0r14\0\0r15\0\0";
const char* InstructionParser::GP_REG_32 = "eax\0\0ecx\0\0edx\0\0ebx\0\0esp\0\0ebp\0\0esi\0\0edi\0\0r8d\0\0r9d\0\0d10d\0r11d\0r12d\0r13d\0r14d\0r15d\0";
const char* InstructionParser::BYTE_REG = "al\0\0\0cl\0\0\0dl\0\0\0bl\0\0\0ah\0\0\0ch\0\0\0dh\0\0\0bh\0\0\0r8b\0\0r9b\0\0r10b\0r11b\0r12b\0r13b\0r14b\0r15b\0";
const char* InstructionParser::ADDR32_STR = "0x%08x";
const char* InstructionParser::ADDR64_STR = "0x%016llx";

inline const char* InstructionParser::SizePtrString(size_t size)
{
	switch (size)
	{
		case 8:  return "byte ";
		case 16: return "word ";
		case 32: return "dword ";
		case 64: return "qword ";
		default: return "";
	}

	return "";
}

inline const char* InstructionParser::GetSegmentPrefixStr(BYTE prefix)
{
	switch (prefix)
	{
		case PREFIX_SEGMENT_CS: return "cs:";
		case PREFIX_SEGMENT_DS: return "ds:";
		case PREFIX_SEGMENT_ES: return "es:";
		case PREFIX_SEGMENT_FS: return "fs:";
		case PREFIX_SEGMENT_GS: return "gs:";
		default: return "";
	}
}

inline OPERAND_SIZE InstructionParser::GetOperandSize(OPERAND_TYPE mode, bool hasSizePrefix, bool hasRex)
{
	size_t size = 0;
	bool signExtended = false;
	OPERAND_SIZE ret = {0,};

	switch (mode)
	{
		case OPTYPE_A:		if (hasSizePrefix) { size = 32; } else { size = 64; } break;
		case OPTYPE_B:		size = 8; break;
		case OPTYPE_BCD:	size = 80; break;
		case OPTYPE_BS:		size = 8; signExtended = true; break;
		case OPTYPE_BSQ:	size = 8; break;
		case OPTYPE_BSS:	signExtended = true; size = 8; break;
		case OPTYPE_C:		if (hasSizePrefix) { size = 8; } else { size = 16; } break;
		case OPTYPE_D:		size = 32; break;
		case OPTYPE_DI:		size = 32; break;
		case OPTYPE_DQ:		size = 128; break;
		case OPTYPE_DQP:	if(!hasRex) { size = 32; } else { size = 64; } break;
		case OPTYPE_DR:		size = 64; break;
		case OPTYPE_DS:		signExtended = true; size = 32; break;
		case OPTYPE_E:		size = 28; break;
		case OPTYPE_ER:		size = 80; break;
		case OPTYPE_P:		if (hasSizePrefix) { size = 32; } else { size = 48; } break;
		case OPTYPE_PI:		size = 64; break;
		case OPTYPE_PD:		size = 128; break;
		case OPTYPE_PS:		size = 128; break;
		case OPTYPE_PSQ:	size = 64; break;
		case OPTYPE_PT:		size = 80; break;
		case OPTYPE_PTP:	if(!hasRex) { size = 32; } else { size = 48; } break;
		case OPTYPE_Q:		size = 64; break;
		case OPTYPE_QI:		size = 64; break;
		case OPTYPE_QP:		size = 64; break;
		case OPTYPE_S:		size = 80; break;
		case OPTYPE_SD:		size = 128; break;
		case OPTYPE_SI:		size = 32; break;
		case OPTYPE_SR:		size = 32; break;
		case OPTYPE_SS:		size = 128; break;
		case OPTYPE_ST:		size = 108; break;
		case OPTYPE_STX:	size = 512; break;
		case OPTYPE_T:		size = 80; break;
		case OPTYPE_V:		if (hasSizePrefix) { size = 16; } else { size = 32; } break;
		case OPTYPE_VDS:	signExtended = true; if (hasSizePrefix) { size = 16; } else { size = 32; } break;
		case OPTYPE_VQ:		if (hasSizePrefix) { size = 16; } else { size = 64; } break;
		case OPTYPE_VQP:	if (hasSizePrefix) { size = 16; } else { size = 32; } if (hasRex) { size = 64; } break;
		case OPTYPE_VS:		signExtended = true; size = 32; break;
		case OPTYPE_W:		size = 16; break;
		case OPTYPE_WI:		size = 16; break;
		case OPTYPE_VA:		if (hasSizePrefix) { size = 16; } else { size = 32; } break;
		case OPTYPE_DQA:	if (machineType == MACHINE_X64) { size = 64; } else { size = 32; } break;
		case OPTYPE_WA:		size = 0; break;
		case OPTYPE_WO:		size = 0; break;
		case OPTYPE_WS:		if (machineType == MACHINE_X64) { size = 64; } else { size = 32; } break;
		case OPTYPE_DA:		size = 32; break;
		case OPTYPE_DO:		size = 32; break;
		case OPTYPE_QA:		size = 64; break;
		case OPTYPE_QS:		size = 64; break;
		case OPTYPE_RAX:	break; 
		case OPTYPE_EAX:	break;
		case OPTYPE_NUM:	size = 3; break;
		case OPTYPE_NULL:	break;
		default:			break;
	}

	ret.size = size;
	ret.signExtended = signExtended;

	return ret;
}

inline SIB_TYPE InstructionParser::ParseSib(BYTE sibByte, INSTRUCTION_OPTION option, char sibString[])
{
	SIB sib = {0,};
	size_t scale = 0;
	SIB_TYPE ret = SIB_TYPE_NORMAL;
	size_t rexBase = 0;
	size_t rexIndex = 0;

	if (option.hasRex && option.rex.bitData.B) { rexBase = EXTREGISTER_INDEX * REGISTERSTR_SIZE; }

	if (option.hasRex && option.rex.bitData.X) { rexIndex = EXTREGISTER_INDEX * REGISTERSTR_SIZE; }

	sib.byteData = sibByte;

	scale = sib.GetScale();

	if (sib.bitData.BASE == 0x05) { ret = SIB_TYPE_ASTERISK; }
	
	if (sib.bitData.INDEX == 0x04)
	{
		if (sib.bitData.BASE != 0x05) { sprintf(sibString, "%s", GP_REG+sib.bitData.BASE * REGISTERSTR_SIZE + rexBase); }
	}
	else
	{
		if (scale == 1)
		{
			if (sib.bitData.BASE == 0x05) { sprintf(sibString, "%s", GP_REG+sib.bitData.INDEX * REGISTERSTR_SIZE + rexIndex); }
			else { sprintf(sibString, "%s+%s", GP_REG+sib.bitData.INDEX*5 + rexIndex, GP_REG+sib.bitData.BASE * REGISTERSTR_SIZE + rexBase); }
		}
		else
		{
			if (sib.bitData.BASE == 0x05) { sprintf(sibString, "%s*%d", GP_REG+sib.bitData.INDEX * REGISTERSTR_SIZE + rexIndex, scale); }
			else { sprintf(sibString, "%s*%d+%s", GP_REG+sib.bitData.INDEX*5 + rexIndex, scale, GP_REG+sib.bitData.BASE * REGISTERSTR_SIZE + rexBase); }
		}
	}

	return ret;

}

inline size_t InstructionParser::CalcModRM_SIZE(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, SIB sib, OPERAND_USES& uses)
{
	OPERAND_SIZE operandSize;

	operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
		option.hasRex && option.rex.bitData.W);

	switch (modrm.bitData.MOD)
	{
		case 0:
			if (modrm.NeedSib()) 
			{ 
				uses.sib = 1; 
				if (sib.bitData.BASE == 0x05) { uses.disp = 4; }
			}
			else if (modrm.bitData.RM == 5)	{ uses.disp = 4; }
			break;
		case 1:
			uses.disp = 1;
			if (modrm.NeedSib()) { uses.sib = 1; }
			break;
		case 2:
			uses.disp = 4;
			if (modrm.NeedSib()) { uses.sib = 1; }
			break;
		case 3:
			break;
		default:
			break;
	}

	return 0;
}

inline size_t InstructionParser::ParseModRM_OPERAND(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, char outOperandStr[], const OPERAND_USES& uses)
{
	OPERAND_SIZE operandSize = {0,};
	ULONG64 nextPc = 0;

	char sibString[24] = {0,};
	SIB_TYPE sibType = SIB_TYPE_NONE;

	ULONG64 rexindexBase = 0;

	if (option.hasRex && option.rex.bitData.B)
	{
		rexindexBase = EXTREGISTER_INDEX * REGISTERSTR_SIZE;
	}

	sibString[0] = 0;

	operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
		option.hasRex && option.rex.bitData.W);

	switch (modrm.bitData.MOD)
	{
		case 0:
			if (modrm.NeedSib()) { 
				sibType = ParseSib( machineCode[parsingIndex+1], option, sibString);
				if (sibType == SIB_TYPE_ASTERISK)
				{
					sprintf(outOperandStr, "%s%s[%s%c0x%08x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), sibString, 
						*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]) & 0x80000000 ? '-' : '+',
						*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]) & 0x80000000 ? 
						((~*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2])+1)) 
						: *reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]));
				}
				else
				{
					sprintf(outOperandStr, "%s[%s]", SizePtrString(operandSize.size), sibString);
				}
			}
			else if (modrm.bitData.RM == 5)
			{
				nextPc = parsingIndex+uses.modrm+uses.sib+uses.immediate+origin+uses.disp;
				if (option.machineType == MACHINE_X64)
				{
					sprintf(outOperandStr, "%s%s[0x%016llx]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), 
						*reinterpret_cast<int*>(&machineCode[parsingIndex+1])+nextPc);
				}
				else
				{
					sprintf(outOperandStr, "%s%s[0x%08x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), 
						*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+1]));
				}
			}
			else { sprintf(outOperandStr, "%s%s[%s]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), GP_REG+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase); }
			break;
		case 1:
			if (modrm.NeedSib()) 
			{ 
				sibType = ParseSib( machineCode[parsingIndex+1], option, sibString);
				if (sibType == SIB_TYPE_ASTERISK)
				{
					//cout << "????" << endl;
				}
				sprintf(outOperandStr, "%s%s[%s%c0x%02x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), sibString, 
					machineCode[parsingIndex+2] & 0x80 ? '-' : '+', 
					machineCode[parsingIndex+2] & 0x80 ? (static_cast<BYTE>(~machineCode[parsingIndex+2]))+1 : machineCode[parsingIndex+2]);
			}
			else { sprintf(outOperandStr, "%s%s[%s%c0x%02x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), GP_REG+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase, machineCode[parsingIndex+1] & 0x80 ? '-' : '+', machineCode[parsingIndex+1] & 0x80 ? ((BYTE)~machineCode[parsingIndex+1])+1 : machineCode[parsingIndex+1]); }
			break;
		case 2:
			if (modrm.NeedSib()) 
			{ 
				sibType = ParseSib( machineCode[parsingIndex+1], option, sibString);
				if (sibType == SIB_TYPE_ASTERISK)
				{
					//cout << "????" << endl;
				}
				sprintf(outOperandStr, "%s%s[%s%c0x%08x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), sibString, 
					*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]) & 0x80000000 ? '-' : '+',
					*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]) & 0x80000000 ? 
					((~*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2])+1))
					: *reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+2]));
			}
			else 
			{ 
				sprintf(outOperandStr, "%s%s[%s%c0x%08x]", SizePtrString(operandSize.size), GetSegmentPrefixStr(option.prefix), 
					GP_REG+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase, 
					*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+1]) & 0x80000000 ? '-' : '+',
					*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+1]) & 0x80000000 ? 
					((~*reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+1])+1))
					: *reinterpret_cast<unsigned int*>(&machineCode[parsingIndex+1]));
			}
			break;
		case 3:
			if (operandSize.size == 8) { strcpy(outOperandStr, BYTE_REG+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase); }
			if (operandSize.size == 32) { strcpy(outOperandStr, GP_REG_32+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase); }
			if (operandSize.size == 64) { strcpy(outOperandStr, GP_REG_64+modrm.bitData.RM * REGISTERSTR_SIZE + rexindexBase); }
			break;
		default:
			break;
	}

	return 0;
}

inline size_t InstructionParser::ParseModRM_REG(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, char outOperandStr[])
{
	OPERAND_SIZE operandSize;
	size_t rexRegIndex = 0;

	if (option.hasRex && option.rex.bitData.R) {
		rexRegIndex = EXTREGISTER_INDEX * REGISTERSTR_SIZE;
	}

	operandSize = GetOperandSize((OPERAND_TYPE)operand.opType, option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
		option.hasRex && option.rex.bitData.W);

	if (operandSize.size == 8) { strcpy(outOperandStr, BYTE_REG+modrm.bitData.REG * REGISTERSTR_SIZE + rexRegIndex); }
	if (operandSize.size == 32) { strcpy(outOperandStr, GP_REG_32+modrm.bitData.REG * REGISTERSTR_SIZE + rexRegIndex); }
	if (operandSize.size == 64) { strcpy(outOperandStr, GP_REG_64+modrm.bitData.REG * REGISTERSTR_SIZE + rexRegIndex); }

	return 0;
}

inline size_t InstructionParser::CalcOperand(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, SIB sib, OPERAND_USES& uses)
{
	bool outHas = false;
	OPERAND_SIZE operandSize;

	outHas =  !(operand.opType == OPTYPE_NULL && operand.addrMode == ADDRMODE_NONE);

	if (outHas)
	{
		switch (operand.addrMode)
		{
			case ADDRMODE_A:
			case ADDRMODE_BA:
			case ADDRMODE_BB:
			case ADDRMODE_BD:
			case ADDRMODE_C:
			case ADDRMODE_D:
				break;
			case ADDRMODE_E:
				uses.modrm = 1;
				CalcModRM_SIZE(operand, option, modrm, sib, uses);
				break;
			case ADDRMODE_ES:
			case ADDRMODE_EST:
			case ADDRMODE_F:
			case ADDRMODE_G:
				uses.modrm = 1;
				CalcModRM_SIZE(operand, option, modrm, sib, uses);
				break;
			case ADDRMODE_H:
				break;
			case ADDRMODE_I:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				uses.immediate = operandSize.size / 8;
				break;
			case ADDRMODE_J:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				uses.disp = operandSize.size / 8;
				break;
			case ADDRMODE_M:
				uses.modrm = 1;
				CalcModRM_SIZE(operand, option, modrm, sib, uses);
				break;
			case ADDRMODE_N:
			case ADDRMODE_O:
				uses.modrm = 0;
				uses.disp = 4;
				break;
			case ADDRMODE_P:
			case ADDRMODE_Q:
			case ADDRMODE_R:
			case ADDRMODE_S:
			case ADDRMODE_SC:
			case ADDRMODE_T:
			case ADDRMODE_U:
			case ADDRMODE_V:
			case ADDRMODE_W:
			case ADDRMODE_X:
			case ADDRMODE_Y:
			case ADDRMODE_S2:
			case ADDRMODE_S30:
			case ADDRMODE_S33:
			case ADDRMODE_Z:
			case ADDRMODE_AL:
			case ADDRMODE_DX:
			case ADDRMODE_ST:
			case ADDRMODE_AX:
			case ADDRMODE_UD:
			case ADDRMODE_CL:
			case ADDRMODE_NONE:
			case ADDRMODE_FS:
			case ADDRMODE_GS:
			case ADDRMODE_CS:
			case ADDRMODE_SS:
			case ADDRMODE_DS:
			default:
				break;
		}
	}

	return 0;
}

inline size_t InstructionParser::ParseOperand(BYTE opCode, MODRM modrm, INSTRUCTION_OPTION option, const OPERAND& operand, 
								  bool &outHas, char outOperandStr[], const OPERAND_USES& uses)
{
	outHas =  !(operand.opType == OPTYPE_NULL && operand.addrMode == ADDRMODE_NONE);
	size_t ret = 0;
	ULONG64 nextPc = 0;
	OPERAND_SIZE operandSize = {0,};
	
	if (outHas)
	{
		switch (operand.addrMode)
		{
			case ADDRMODE_A:
			case ADDRMODE_BA:
			case ADDRMODE_BB:
			case ADDRMODE_BD:
			case ADDRMODE_C:
			case ADDRMODE_D:
				break;
			case ADDRMODE_E:
				ParseModRM_OPERAND(operand, option, modrm, outOperandStr, uses);
				break;
			case ADDRMODE_ES:
			case ADDRMODE_EST:
			case ADDRMODE_F:
			case ADDRMODE_G:
				ParseModRM_REG(operand, option, modrm, outOperandStr);
				break;
			case ADDRMODE_H:
				break;
			case ADDRMODE_I:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				if (operandSize.size == 8) { sprintf(outOperandStr, "0x%02x", machineCode[parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-1]); }
				if (operandSize.size == 16) { sprintf(outOperandStr, "0x%04x", *reinterpret_cast<unsigned short*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-2)); }
				if (operandSize.size == 32) { sprintf(outOperandStr, "0x%08x", *reinterpret_cast<unsigned int*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-4)); }
				if (operandSize.size == 64) { sprintf(outOperandStr, "0x%016llx", *reinterpret_cast<PULONG64>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-8)); }
				break;
			case ADDRMODE_J:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				nextPc = parsingIndex+uses.modrm+uses.sib+operandSize.size/8+origin;
				if (operandSize.size == 8) { sprintf(outOperandStr, ADDR_STR, static_cast<char>(machineCode[parsingIndex+uses.modrm+uses.sib+uses.immediate])+nextPc); }
				if (operandSize.size == 16) { sprintf(outOperandStr, ADDR_STR, *reinterpret_cast<short*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate)+nextPc); }
				if (operandSize.size == 32) { sprintf(outOperandStr, ADDR_STR, *reinterpret_cast<int*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate)+nextPc); }
				if (operandSize.size == 64) { sprintf(outOperandStr, ADDR_STR, *reinterpret_cast<long long*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate)+nextPc); }
				break;
			case ADDRMODE_M:
				ParseModRM_OPERAND(operand, option, modrm, outOperandStr, uses);
				break;
			case ADDRMODE_N:
			case ADDRMODE_O:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				if (operandSize.size == 16) sprintf(outOperandStr, "word%s[0x%04x]", GetSegmentPrefixStr(option.prefix), *reinterpret_cast<unsigned short*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-2));
				if (operandSize.size == 32) sprintf(outOperandStr, "dword%s[0x%08x]", GetSegmentPrefixStr(option.prefix), *reinterpret_cast<unsigned int*>(machineCode+parsingIndex+uses.modrm+uses.sib+uses.immediate+uses.disp-4));
				break;
			case ADDRMODE_P:
			case ADDRMODE_Q:
			case ADDRMODE_R:
			case ADDRMODE_S:
			case ADDRMODE_SC:
			case ADDRMODE_T:
			case ADDRMODE_U:
			case ADDRMODE_V:
			case ADDRMODE_W:
			case ADDRMODE_X:
			case ADDRMODE_Y:
			case ADDRMODE_S2:
			case ADDRMODE_S30:
			case ADDRMODE_S33:
				break;
			case ADDRMODE_Z:
				operandSize = GetOperandSize(static_cast<OPERAND_TYPE>(operand.opType), option.hasPrefix && option.prefix == PREFIX_ADDRESS_SIZE, 
					option.hasRex && option.rex.bitData.W);
				if (operandSize.size == 64) { strcpy(outOperandStr, GP_REG_64+((opCode % 8) * REGISTERSTR_SIZE)); }
				else { strcpy(outOperandStr, GP_REG_32+((opCode % 8) * REGISTERSTR_SIZE)); }
				break;
			case ADDRMODE_AL:
				strcpy(outOperandStr, "al");
				break;
			case ADDRMODE_DX:
				strcpy(outOperandStr, "dx");
				break;
			case ADDRMODE_ST:
				strcpy(outOperandStr, "st");
				break;
			case ADDRMODE_AX:
				strcpy(outOperandStr, "ax");
				break;
			case ADDRMODE_UD:
				strcpy(outOperandStr, "ud");
				break;
			case ADDRMODE_CL:
				strcpy(outOperandStr, "cl");
				break;
			case ADDRMODE_NONE:
				if (operand.opType == OPTYPE_NUM) { sprintf(outOperandStr, "%d", operand.numValue); }
				if (operand.opType == OPTYPE_EAX) { strcpy(outOperandStr, "eax"); }
				if (operand.opType == OPTYPE_RAX) 
				{ 
					if (option.machineType == MACHINE_X64 && option.hasRex && option.rex.bitData.W) { strcpy(outOperandStr, "rax"); }
					else { strcpy(outOperandStr, "eax"); }
				}
				break;
			case ADDRMODE_FS:
			case ADDRMODE_GS:
			case ADDRMODE_CS:
			case ADDRMODE_SS:
			case ADDRMODE_DS:
			default:
				break;
		}
	}

	return ret;
}

ULONG64 InstructionParser::ParseInstruction(ParsedInstruction& outResult)
{
	INSTRUCTION instructionFormat = {0,};
	BYTE second = 0x00;
	BYTE opCode = 0x00;
	MODRM modrm = {0,};
	SIB sib = {0,};
	size_t prefixIterator = 0;
	INSTRUCTION_OPTION option = {MACHINE_NONE, 0,};
	OPERAND_USES uses = {0,};
	ULONG64 ret = 0;
	ULONG64 savedIndex = parsingIndex;

	option.machineType = machineType;

	outResult.mnemonic_num = MNEMONIC_NONE;
	outResult.mnemonic = mnemonicStr[MNEMONIC_NONE];

	outResult.has_op1 = false;
	outResult.has_op2 = false;
	outResult.has_op3 = false;

	outResult.op1[0] = 0;
	outResult.op2[0] = 0;
	outResult.op3[0] = 0;

	if (machineType == MACHINE_NONE) { return 0; }

	for (prefixIterator = 0; prefixIterator < 16; ++prefixIterator)
	{
		if (IsPrefix(machineCode[parsingIndex])) 
		{
			option.hasPrefix = true;
			option.prefix = machineCode[parsingIndex];
			++parsingIndex;
		}
		else if(machineType == MACHINE_X64)
		{
			if (IsREX(machineCode[parsingIndex]))
			{
				option.hasRex = true;
				option.rex.byteData = machineCode[parsingIndex];
				++parsingIndex;
			}
			else { break; }
		}
		else { break; }
	}

	if (option.hasPrefix) { --parsingIndex; }

	instructionFormat = OpCodeTable::GetInstance()->FindInstruction(machineCode+parsingIndex, machineType);

	for (prefixIterator = 0; prefixIterator < 2; ++prefixIterator)
	{
		if (IsPrefix(machineCode[parsingIndex])) 
		{
			option.hasPrefix = true;
			option.prefix = machineCode[parsingIndex];
			++parsingIndex;
		}
		if(machineType == MACHINE_X64)
		{
			if (IsREX(machineCode[parsingIndex]))
			{
				option.hasRex = true;
				option.rex.byteData = machineCode[parsingIndex];
				++parsingIndex;
			}
		}
	}

	if (!option.hasPrefix) { option.prefix = PREFIX_NONE; }

	if (machineCode[parsingIndex] == 0x0F)
	{
		opCode = machineCode[parsingIndex+1];
		parsingIndex += 2;
	}
	else
	{
		opCode = machineCode[parsingIndex];
		++parsingIndex;
	}

	if (instructionFormat.instType.second)
	{
		second = machineCode[parsingIndex];
		++parsingIndex;
	}

	modrm.byteData = machineCode[parsingIndex];
	sib.byteData = machineCode[parsingIndex+1];

	outResult.mnemonic_num = instructionFormat.mnemonic;
	outResult.mnemonic = mnemonicStr[instructionFormat.mnemonic];

	CalcOperand(instructionFormat.operand[0], option, modrm, sib, uses);
	CalcOperand(instructionFormat.operand[1], option, modrm, sib, uses);
	CalcOperand(instructionFormat.operand[2], option, modrm, sib, uses);

	ParseOperand(opCode, modrm, option, instructionFormat.operand[0], outResult.has_op1, outResult.op1, uses);
	ParseOperand(opCode, modrm, option, instructionFormat.operand[1], outResult.has_op2, outResult.op2, uses);
	ParseOperand(opCode, modrm, option, instructionFormat.operand[2], outResult.has_op3, outResult.op3, uses);

	ret = parsingIndex - savedIndex;

	if (uses.modrm) { ++ret; }
	if (uses.modrm && uses.sib) { ++ret; }
	ret += uses.immediate + uses.disp;

	parsingIndex = savedIndex + ret;

	return ret;
}