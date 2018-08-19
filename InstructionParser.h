#ifndef _INSTRUCTIONPARSER_H_
#define _INSTRUCTIONPARSER_H_

#include "Types.h"
#include "Mnemonics.h"

class InstructionParser
{
	public:
		struct ParsedInstruction;

		InstructionParser() : origin(0), parsingIndex(0), machineCode(NULL), machineType(MACHINE_NONE), GP_REG(NULL), ADDR_STR(NULL) {}
		InstructionParser(ULONG64 aStartAddr) : origin(aStartAddr), parsingIndex(0), machineCode(NULL), machineType(MACHINE_NONE) {}

		ULONG64 GetOrigin() { return origin; }
		void SetOrigin(ULONG64 aStartAddr) { origin = aStartAddr; }

		void SetMachineCode(PBYTE aMachineCode) { machineCode = aMachineCode; }

		ULONG64 GetCurrentParsingLocation() { return origin + parsingIndex; }
		void SetCurrentParsingLocation(ULONG64 parseAddress) { parsingIndex = parseAddress - origin; }

		MACHINE_TYPE GetMachineType() { return machineType; }
		void SetMachineType(MACHINE_TYPE aMachineType) 
		{ 
			machineType = aMachineType; 
			if (machineType == MACHINE_X64) { GP_REG = GP_REG_64; ADDR_STR = ADDR64_STR; }
			if (machineType == MACHINE_X86) { GP_REG = GP_REG_32; ADDR_STR = ADDR32_STR; }
		}

		ULONG64 ParseInstruction(ParsedInstruction& outResult);

	private:
		inline const char* SizePtrString(size_t size);
		inline OPERAND_SIZE GetOperandSize(OPERAND_TYPE mode, bool hasSizePrefix, bool hasRex);
		inline size_t ParseOperand(BYTE opCode, MODRM modrm, INSTRUCTION_OPTION option, const OPERAND& operand, 
									bool &outHas, char outOperandStr[], const OPERAND_USES& uses);
		inline SIB_TYPE ParseSib(BYTE sibByte, INSTRUCTION_OPTION option, char sibString[]);
		inline size_t CalcModRM_SIZE(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, SIB sib, OPERAND_USES& uses);
		inline size_t ParseModRM_REG(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, char outOperandStr[]);
		inline size_t CalcOperand(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, SIB sib, OPERAND_USES& uses);
		inline size_t ParseModRM_OPERAND(OPERAND operand, INSTRUCTION_OPTION option, MODRM modrm, char outOperandStr[], const OPERAND_USES& uses);
		inline const char* GetSegmentPrefixStr(byte prefix);

		ULONG64 origin;
		ULONG64 parsingIndex;
		PBYTE machineCode;
		MACHINE_TYPE machineType;

		const char* GP_REG;
		const char* ADDR_STR;

		static const char* GP_REG_64;
		static const char* GP_REG_32;
		static const char* BYTE_REG;
		static const char* ADDR32_STR;
		static const char* ADDR64_STR;
};

struct InstructionParser::ParsedInstruction
{
	const char* mnemonic;
	size_t mnemonic_num;

	bool has_op1;
	bool has_op2;
	bool has_op3;

	char op1[128];
	char op2[128];
	char op3[128];

	inline bool IsConditionalBranch()
	{
		return (mnemonic_num == MNEMONIC_JA || mnemonic_num == MNEMONIC_JAE || mnemonic_num == MNEMONIC_JB || mnemonic_num == MNEMONIC_JBE ||
			mnemonic_num == MNEMONIC_JC || mnemonic_num == MNEMONIC_JCXZ || mnemonic_num == MNEMONIC_JECXZ || mnemonic_num == MNEMONIC_JRCXZ ||
			mnemonic_num == MNEMONIC_JE || mnemonic_num == MNEMONIC_JG || mnemonic_num == MNEMONIC_JGE || mnemonic_num == MNEMONIC_JL ||
			mnemonic_num == MNEMONIC_JLE || mnemonic_num == MNEMONIC_JNA || mnemonic_num == MNEMONIC_JNAE || mnemonic_num == MNEMONIC_JNB ||
			mnemonic_num == MNEMONIC_JNBE || mnemonic_num == MNEMONIC_JNC || mnemonic_num == MNEMONIC_JNE || mnemonic_num == MNEMONIC_JNG ||
			mnemonic_num == MNEMONIC_JNGE || mnemonic_num == MNEMONIC_JNL || mnemonic_num == MNEMONIC_JNLE || mnemonic_num == MNEMONIC_JNO ||
			mnemonic_num == MNEMONIC_JNP || mnemonic_num == MNEMONIC_JNS || mnemonic_num == MNEMONIC_JNZ || mnemonic_num == MNEMONIC_JO ||
			mnemonic_num == MNEMONIC_JP || mnemonic_num == MNEMONIC_JPE || mnemonic_num == MNEMONIC_JPO || mnemonic_num == MNEMONIC_JS ||
			mnemonic_num == MNEMONIC_JZ);
	}
};

#endif /* _INSTRUCTIONPARSER_H_ */