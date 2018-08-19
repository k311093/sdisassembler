#ifndef _OPCODETAB_H_
#define _OPCODETAB_H_

#include "Types.h"

#include <Windows.h>

#include <vector>

class OpCodeTable 
{
public:
	static OpCodeTable* GetInstance();
	INSTRUCTION& FindInstruction(const BYTE machineCode[], MACHINE_TYPE type);

private:
	OpCodeTable();
	static OpCodeTable* instance_;


	class OpCodeItems 
	{
		public:
			bool InsertInstruction(INSTRUCTION& item);
			INSTRUCTION& FindInstruction(const BYTE machineCode[], INSTRUCTION_OPTION& option);
			OpCodeItems() { ZeroMemory(&instruction_, sizeof(instruction_)); }

		private:
			INSTRUCTION instruction_;
			std::vector<INSTRUCTION> conditionalInstruction_;
	};

	OpCodeItems oneByteItems_[256];
	OpCodeItems twoByteItems_[256];
};

#endif /* _OPCODETAB_H_ */