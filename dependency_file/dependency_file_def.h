#ifndef DEPENDENCY_FILE_DEF_H
#define DEPENDENCY_FILE_DEF_H

#include <map>
#include <string>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {
	#include "panda/addr.h"
	
	#include "osi/osi_types.h"
	#include "osi/osi_ext.h"
	#include "osi_linux/osi_linux_ext.h"
	#include "syscalls2/gen_syscalls_ext_typedefs.h"
}

struct Dependency_File {
	void *plugin_ptr = nullptr;        // The plugin pointer

	std::string sourceFile = "";       // The source file name (Independent)
	std::string sinkFile = "";         // The sink file name (Dependent)
	bool debug = false;                // Print debug information?
};

/// <summary>
/// Callback function which can be called before a PANDA block execution. This
/// particular function gets the current process which is about to be executed
/// and adds it to the processes map.
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
int cbf_beforeBlockExectuion(CPUState *cpu, TranslationBlock *tB);

/// <summary>
/// Callback function for the syscalls2 "on_sys_pread64_enter_t" event.
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
void cbf_pread64Enter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count, uint64_t pos);

/// <summary>
/// Callback function for the syscalls2 "on_sys_pread64_return_t" event.
/// </summart>
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
/// Callback function for the syscalls2 "on_sys_open_enter_t" event.
/// </summary>
/// <param name="cpu">
/// The CPU state pointer.
/// </param>
/// <param name="pc">
/// The program counter.
/// </param>
/// <param name="fileAddr">
/// The virtual memory address at which the name of the is contained.
/// </param>
/// <param name="flags">
/// The flags used to open the file.
/// </param>
/// <param name="mode">
/// The mode using which the file was opened.
/// </param>
void cbf_openEnter(CPUState *cpu, target_ulong pc, uint32_t fileAddr, int32_t
		flags, int32_t mode);
		
/// <summary>
/// Callback function for the syscalls2 "on_sys_read_enter_t" event.
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
void cbf_readEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count);

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
void cbf_readReturn(CPUState *cpu, target_ulong pc,
        uint32_t fd, uint32_t buf, uint32_t count);
		
/// <summary>
/// Callback function for the syscals2 "on_sys_write_enter_t" event.
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
/// The virtual memory address of the write buffer.
/// </param>
/// <param name="count">
/// The length of the write buffer.
/// </param>
void cbf_writeEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count);

/// <summary>
/// Returns a string with the filename corresponding to the specified file
/// descriptor.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
/// </param>
/// <param name="processes">
/// The map of the ASID to the OSI processes.
/// </param>
/// <param name="fd">
/// The file descriptor for which the file name is to be fetched.
/// </param>
/// <param name="debug">
/// Should errors be logged to the standard error stream? False by default.
/// </param>
/// <returns>
/// The string containing the filename. If the file name could not be fetched,
/// an empty string is returned instead.
/// </returns>
std::string getFileName(CPUState *cpu, 
		std::map<target_ulong, OsiProc>& processes, int fd, bool debug = false);

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

Dependency_File dependency_file;                // The Plugin Structure
std::map<target_ulong, OsiProc> processesMap;   // The Guest Processes

#endif
