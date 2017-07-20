#ifndef DEPENDENCY_NETWORK_H
#define DEPENDENCY_NETWORK_H

#include <map>
#include <vector>
#include <utility>

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

struct Dependency_Network_Target {
	std::string ip;                    // The IP Address as a string
	unsigned short port;               // The port

	/// <summary>
	/// Compares the specified Dependency_Network_Target instance for equality
	/// to this instance.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are equivalent, false otherwise.
	/// </returns>
	bool operator==(const Dependency_Network_Target &rhs);

	/// <summary>
	/// Compares the specified Dependency_Network_Target instance for inequality
	/// to this instance.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are inequivalent, false otherwise.
	/// </returns>
	bool operator!=(const Dependency_Network_Target &rhs);
};

struct Dependency_Network {
	void *plugin_ptr = nullptr;        // The plugin pointer
	bool debug = false;                // Is running in debug?
	
	Dependency_Network_Target source;  // The source address & port
	Dependency_Network_Target sink;    // The sink address & port
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
/// Callback function for the syscalls2 "on_sys_pread64_return_t" event.
/// </summary>
/// <param name="cpu">
/// The CPU state pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="fd">
/// The file descriptor.
/// </param>
/// <param name="buffer">
/// The virtual memory address of the read buffer.
/// </param>
/// <param name="count">
/// The length of the read buffer.
/// </param>
/// <param name="pos">
/// The position from which the file was read.
/// </param>
void cbf_pread64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_pwrite64_return_t" event.
/// </summary>
/// <param name="cpu">
/// The CPU state pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="fd">
/// The file descriptor.
/// </param>
/// <param name="buffer">
/// The virtual memory address of the read buffer.
/// </param>
/// <param name="count">
/// The length of the read buffer.
/// </param>
/// <param name="pos">
/// The position from which the file was read.
/// </param>
void cbf_pwrite64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_read_return_t" event.
/// </summary>
/// <param name="cpu">
/// The CPU state pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="fd">
/// The file descriptor.
/// </param>
/// <param name="buffer">
/// The virtual memory address of the read buffer.
/// </param>
/// <param name="count">
/// The length of the read buffer.
/// </param>
void cbf_readReturn(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count);

/// <summary>
/// Callback function for the syscalls2 "on_sys_write_return_t" event.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="fd">
/// The file descriptor.
/// </param>
/// <param name="buffer">
/// The virtual memory address of the write buffer.
/// </param>
/// <param name="count">
/// The length of the write buffer.
/// </param>
void cbf_writeReturn(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count);
		
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
/// The vector of size <paramref="size"> containing the values fetched from
/// <paramref="addr">.
/// </returns>
template<typename T>
std::vector<T> getMemoryValues(CPUState *cpu, uint32_t addr, uint32_t size);

/// <summary>
/// Function which should be called when a socket connect() system call is
/// encountered.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments for the connect()
/// system call.
/// </param>
void onSocketConnect(CPUState *cpu, uint32_t args);

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

Dependency_Network dependency_network;     // The Plugin Structure
std::map<                                  // The map of the unions of ASIDs
	std::pair<target_ulong, uint32_t>,     // FDs to the network targets.
	Dependency_Network_Target> targets;

bool sawReadOfSource = false;              // Was source target read from?
bool sawWriteOfSink = false;               // Was sink target written to?

#endif
