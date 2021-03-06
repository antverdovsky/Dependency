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
	/// Compares the specified Dependency_Network_Target instance for 
	/// inequality to this instance.
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
	void *plugin_ptr = nullptr;            // The plugin pointer
	bool debug = false;                    // Is running in debug?
	target_ulong enableTaintAt =           // I# @ which to enable taint
		UINT32_MAX;
	
	Dependency_Network_Target source;      // The source address & port
	Dependency_Network_Target sink;        // The sink address & port
};

Dependency_Network dependency_network;     // The Plugin Structure
std::map<                                  // The map of the unions of ASIDs
	std::pair<target_ulong, uint32_t>,     // FDs to the network targets.
	Dependency_Network_Target> targets;

bool sawReadOfSource = false;              // Was source target read from?
bool sawWriteOfSink = false;               // Was sink target written to?
bool dependency = false;                   // Was dependency seen?

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
/// Taints the contents of the buffer at the specified virtual address and of 
/// the specified length. This function does nothing if taint2 is not currently
/// enabled.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="vAddr">
/// The virtual address of the buffer.
/// </param>
/// <param name="length">
/// The length of the buffer, in bytes.
/// </param>
void labelBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length);

/// <summary>
/// Callback function which can be called before a PANDA block translation.
/// This particular function is used to enable the taint2 plugin if the current
/// instruction count exceeds the enable taint at property of the dependency
/// file plugin.
/// </summary>
/// <param name="cpu">
/// The CPU state pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <returns>
/// Zero always.
/// </returns>
int on_before_block_translate(CPUState *cpu, target_ulong pc);

/// <summary>
/// Callback function for the syscalls2 "on_sys_pread64_return_t" event. This
/// function checks if the file descriptor matches with a taint source, and if
/// so, then the buffer is tainted, and the number of tainted bytes is logged.
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
void on_pread64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_pwrite64_return_t" event. This
/// function checks if the file descriptor matches with a taint sink, and if
/// so, then the buffer is queried for taint, and the number of tainted bytes
/// is logged.
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
void on_pwrite64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_read_return_t" event. This
/// function is equivalent to <see cref="on_pread64_return"> with a zero
/// position argument.
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
void on_read_return(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count);

/// <summary>
/// Callback function for the "on_sys_socketcall_return_t" system call. This
/// function calls the appropriate socket function to handle the socket call.
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
void on_socketcall_return(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_connect_return_t" event. This
/// function gets the file descriptor for which this function was called and
/// maps the ASID and file descriptor to the network target associated with the
/// file descriptor.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments for the connect()
/// system call.
/// </param>
void on_socketcall_connect_return(CPUState *cpu, uint32_t args);

/// <summary>
/// Callback function for the syscalls2 "on_sys_recv_return_t" event. This
/// function gets the IP and port associated with the receive command and if
/// this is a source target, it taints the buffer of this call and outputs the
/// number of tainted bytes.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments for the recv()
/// system call.
/// </param>
void on_socketcall_recv_return(CPUState *cpu, uint32_t args);

/// <summary>
/// Callback function for the syscalls2 "on_sys_send_return_t" event. This
/// function gets the IP and port associated with the send command and if
/// this is a sink target, it queries the buffer of this call for taint and
/// outputs the number of tainted bytes.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments for the send()
/// system call.
/// </param>
void on_socketcall_send_return(CPUState *cpu, uint32_t args);

/// <summary>
/// Callback function for the syscalls2 "on_sys_write_return_t" event. This
/// function is equivalent to <see cref="on_pwrite64_return"> with a zero
/// position argument.
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
void on_write_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count);

/// <summary>
/// Queries the contents of the buffer at the specified virtual address and of
/// the specified length for taint. This function does nothing if taint2 is not
/// currently enabled, and returns a negative integer in this case.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="vAddr">
/// The virtual address of the buffer.
/// </param>
/// <param name="length">
/// The length of the buffer, in bytes.
/// </param>
/// <returns>
/// The number of bytes which are tainted in the buffer, or a negative integer
/// if taint2 is not enabled.
/// </returns>
int queryBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length);

/// <summary>
/// Initializes this plugin using the specified plugin pointer.
/// </summary>
/// <param name="self">
/// The plugin pointer passed in from PANDA.
/// </param>
/// <returns>
/// True if the plugin was successfully loaded, false otherwise.
/// </returns>
extern "C" bool init_plugin(void *self);
	
/// <summary>
/// Destroys this plugin.
/// </summary>
/// <param name="self">
/// The plugin pointer passed in from PANDA.
/// </param>
extern "C" void uninit_plugin(void *self);

#endif
