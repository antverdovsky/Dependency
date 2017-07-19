#ifndef DEPENDENCY_NETWORK_H
#define DEPENDENCY_NETWORK_H

#include <vector>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "taint2/taint2.h"

extern "C" {
	#include "panda/addr.h"
	
	#include "osi/osi_types.h"
	#include "osi/osi_ext.h"
	#include "osi_linux/osi_linux_ext.h"
	#include "syscalls2/gen_syscalls_ext_typedefs.h"
	#include "taint2/taint2_ext.h"
}

struct Dependency_Network {
	void *plugin_ptr = nullptr;        // The plugin pointer
};

/// <summary>
/// Callback function for the "on_sys_socketcall_enter_t" system call.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="call">
/// The integer ID of the socket call.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments.
/// </param>
void cbf_socketCallEnter(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args);
		
/// <summary>
/// Callback function for the "on_sys_socketcall_return_t" system call.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="call">
/// The integer ID of the socket call.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments.
/// </param>
void cbf_socketCallEnter(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args);
		
/// <summary>
/// Returns a vector of size <paramref="size"> containing the values of T read 
/// from the virtual memory address <paramref="addr">. This method assumes that
/// the values in memory are adjacent to each other (in an array).
/// </summary>
/// <typeparam name="T">
/// The type of values to be read from the memory address.
/// </typeparam>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="addr">
/// The virtual memory address to the start of the T values.
/// </param>
/// <param name="size">
/// The number of arguments to be read in. This is equivalent to the number of
/// elements returned in the vector.
/// </param>
/// <returns>
/// The vector of size <paramref="size"> containing the arguments fetched from
/// <paramref="args">.
/// </returns>
template<typename T>
std::vector<T> getMemoryValues(CPUState *cpu, uint32_t addr, uint32_t size);

extern "C" {
	/// <summary>
	/// Initializes this plugin using the specified plugin pointer.
	/// </summary>
	/// <param name="self">
	/// The plugin pointer passed in from PANDA.
	/// </param>
	/// <returns>
	/// True if the plugin was successfully loaded, false otherwise.
	/// </returns>
	bool init_plugin(void *self);
	
	/// <summary>
	/// Destroys this plugin.
	/// </summary>
	/// <param name="self">
	/// The plugin pointer passed in from PANDA.
	/// </param>
	void uninit_plugin(void *self);
}

Dependency_Network dependency_network;

#endif
