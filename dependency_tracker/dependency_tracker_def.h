#ifndef DEPENDENCY_TRACKER_H
#define DEPENDENCY_TRACKER_H

#include <map>
#include <memory>
#include <set>
#include <string>
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

#include "dependency_tracker_targets.h"

typedef std::pair<target_ulong, uint32_t> FD_ASID_Pair;

struct Dependency_Tracker {
	void *plugin_ptr = nullptr;                          // The plugin pointer
	uint64_t enableTaintAt = 1;                          // I# to enable taint
	bool debug = false;                                  // Print debug info?
	bool logErrors = false;                              // Print errors?
	
	std::vector<std::unique_ptr<TargetSource>> sources;  // Source Targets
	std::vector<std::unique_ptr<TargetSink>> sinks;      // Sink Targets
	
	std::map<target_ulong, OsiProc> processes;           // { ASID -> Process }
	std::map<FD_ASID_Pair, TargetNetwork> networks;      // { ASID, FD -> Net }
	
};

Dependency_Tracker dependency_tracker;                   // Plugin Reference

/// <summary>
/// Returns a vector of size <paramref="size"/> containing the values of T read 
/// from the virtual memory address <paramref="addr"/>. This method assumes 
/// that the values in memory are adjacent to each other (in an array).
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
/// The vector of size <paramref="size"/> containing the values fetched from
/// <paramref="addr"/>.
/// </returns>
template<typename T>
std::vector<T> getMemoryValues(CPUState *cpu, uint32_t addr, uint32_t size);

/// <summary>
/// Returns a TargetFile with the file name corresponding to the specified file
/// descriptor and ASID. If no such file name is found, the TargetFile returned
/// is invalid.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="asid">
/// The ASID of the process which owns the file referenced by the file
/// descriptor.
/// </param>
/// <param name="fd">
/// The file descriptor for which the file name is to be fetched.
/// </param>
/// <returns>
/// The TargetFile containing the file name. If the file name could not be
/// resolved, the TargetFile returned is invalid.
/// </returns>
TargetFile getTargetFile(CPUState *cpu, target_ulong asid, uint32_t fd);

/// <summary>
/// Returns a TargetNetwork with the IP address and port corresponding to the
/// specified file descriptor and ASID. If no such network target is found, the
/// TargetNetwork returned is invalid.
/// </summary>
/// <param name="asid">
/// The ASID of the process which owns the network target referenced by the
/// socket file descriptor.
/// </param>
/// <param name="fd">
/// The file descriptor for which the network target is to be fetched.
/// </param>
TargetNetwork getTargetNetwork(target_ulong asid, uint32_t fd);

/// <summary>
/// Gets the sink associated with the specified <param ref="target"/>.
/// </summary>
/// <param name="target">
/// The target for which the sink target is to be fetched.
/// </param>
/// <returns>
/// The reference to the target sink.
/// </returns>
/// <exception cref="std::invalid_argument">
/// Thrown if no sink target is associated with the specified target.
/// </exception>
TargetSink& getTargetSink(const Target &target); 

/// <summary>
/// Gets the source associated with the specified <param ref="target"/>.
/// </summary>
/// <param name="target">
/// The target for which the source target is to be fetched.
/// </param>
/// <returns>
/// The reference to the target source.
/// </returns>
/// <exception cref="std::invalid_argument">
/// Thrown if no source target is associated with the specified target.
/// </exception>
TargetSource& getTargetSource(const Target &target); 

/// <summary>
/// Checks if the specified <paramref="target"/> is a sink target.
/// </summary>
/// <param name="target">
/// The target to be checked.
/// </param>
/// <returns>
/// True if <paramref="target"/> is a sink, false otherwise.
/// </returns>
bool isSink(const Target &target);

/// <summary>
/// Checks if the specified <paramref="target"/> is a source target.
/// </summary>
/// <param name="target">
/// The target to be checked.
/// </param>
/// <returns>
/// True if <paramref="target"/> is a source, false otherwise.
/// </returns>
bool isSource(const Target &target);

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
/// <param name="label">
/// The label which should be applied to each address in the buffer.
/// </param>
/// <returns>
/// The number of bytes labeled. Returns zero if taint2 is not enabled.
/// </returns>
int labelBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length,
		uint32_t label);
		
/// <summary>
/// Callback function which can be called before a PANDA block execution. This
/// particular function gets the current process which is about to be executed
/// and adds it to the processes map. If a process with the same ASID already
/// exists, it is overwritten with the new process.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="tB">
/// The Translation Block which is about to be run.
/// </param>
/// <returns>
/// One if successful, zero otherwise.
/// </returns>
int on_before_block_execution(CPUState *cpu, TranslationBlock *tB);

/// <summary>
/// Callback function which can be called before a PANDA block translation.
/// This particular function is used to enable the taint2 plugin if the current
/// instruction count exceeds the enable taint at property of the plugin.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
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
/// function taints the specified buffer, if the target associated with the
/// specified file descriptor is a target source.
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
/// The position from which the file was read from.
/// </param>
void on_pread64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);

/// <summary>
/// Callback function for the syscalls2 "on_sys_pwrite64_return_t" event. This
/// function queries the specified buffer, if the target associated with the
/// specified file descriptor is a target sink.
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
/// The position from which the file was written to.
/// </param>
void on_pwrite64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_read_return_t" event. This
/// function calls the <see cref="on_pread64_return"/> function with a zero
/// argument for the position parameter.
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
/// function gets the Network Target associated with the socket file descriptor
/// argument and current ASID, and inserts the ASID, FD pair into the networks
/// vector, mapped to the corresponding Network Target.
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
/// this is a source target, it taints the buffer of this call, and adds the
/// number of tainted bytes to the TargetSource.
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
/// function gets the IP and port associated with the send command and if this
/// is a sink target, it queries the buffer of this call for taint and adds
/// the number of tainted bytes to the TargetSink.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="args">
/// The virtual memory address to the start of the arguments for the recv()
/// system call.
/// </param>
void on_socketcall_send_return(CPUState *cpu, uint32_t args);

/// <summary>
/// Callback function for the syscalls2 "on_sys_write_return_t" event. This
/// function calls the <see cref="on_pwrite64_return"/> function with a zero
/// argument for the position parameter.
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
/// The length of the write buffer.
/// </param>
void on_write_return(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count);

/// <summary>
/// Parses the specified file, which is assumed to be in CSV format. Returns
/// a vector containing the vectors of the strings parsed on each line.
/// </summary>
/// <param name="fileName">
/// The name of the file which is to be processed.
/// </param>
/// <returns>
/// The vector containing the vectors of the strings parsed on each line. If
/// file could not be opened, an empty vector is returned.
/// </returns>
std::vector<std::vector<std::string>> parseCSV(const std::string &fileName);

/// <summary>
/// Parses the targets from the specified CSV file and returns a vector of the
/// targets parsed.
/// </summary>
/// <param name="file">
/// The name of the CSV file from which to parse the targets.
/// </param>
/// <returns>
/// The vector containing all valid targets which were successfully read in
/// from the file.
/// </returns>
std::vector<std::unique_ptr<Target>> parseTargets(const std::string &file);
		
/// <summary>
/// Queries the contents of the buffer at the specified virtual address and of
/// the specified length for taint. This function does nothing if taint2 is not
/// currently enabled, and returns an empty map if taint2 is not enabled.
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
/// A map of each label found to the number of bytes tainted by that label.
/// </returns>
std::map<uint32_t, uint32_t> queryBufferContents(
		CPUState *cpu, target_ulong vAddr, uint32_t length);

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
/// Destroys this plugin. Outputs information about which sources were tainted
/// and the dependencies between any source and sink targets.
/// </summary>
/// <param name="self">
/// The plugin pointer passed in from PANDA.
/// </param>
extern "C" void uninit_plugin(void *self);

#endif
