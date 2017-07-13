#ifndef DEPENDENCY_UITLS_H
#define DEPENDENCY_UITLS_H

#include <string>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {
	#include "panda/addr.h"
}

/// <summary>
/// Returns a string fetched from the specified memory address.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="maxSize">
/// The maximum size of the string to be read from memory. If the actual string
/// size exceeds this parameter, only the first maxSize number of characters
/// will be returned. The actual string size may be smaller than this value, as
/// this function will automatically stop when a null terminator character is
/// encountered in memory.
/// </param>
/// <param name="addr">
/// The address from which the string is to be read.
/// </param>
/// <returns>
/// The guest's string at the memory location.
/// </returns>
std::string getGuestString(CPUState *cpu, size_t maxSize, target_ulong addr);

#endif
