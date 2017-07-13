#include "utils.h"

#include <iostream>

std::string getGuestString(CPUState *cpu, size_t maxSize, target_ulong addr) {
	// Create an empty string with all zeros
	std::string str(maxSize, '0');
	
	for (size_t i = 0; i < maxSize; ++i) {
		// Fetch the unsigned integer character from PANDA's memory. We do this
		// by specifiying the CPU state, the address at which we want to read
		// from (equal to starting address + offset), the pointer to which we
		// want to write the value, 1 to indicate we are reading one byte at a 
		// time, and 0 to indicate we are not writing anything to memory.
		uint8_t uiChar = 0;
		panda_virtual_memory_rw(cpu, addr + i, &uiChar, 1, 0);
		
		// Write the character to the string and check if its the null
		// terminator character. If so, trim the string and return.
		str.at(i) = (char)(uiChar);
		if (str.at(i) == '\0') {
			str = str.substr(0, i);
			return str;
		}
	}
	
	return str;
}
