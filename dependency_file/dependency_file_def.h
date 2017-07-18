#ifndef DEPENDENCY_FILE_DEF_H
#define DEPENDENCY_FILE_DEF_H

#include <map>
#include <string>

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

struct Dependency_File {
	void *plugin_ptr = nullptr;        // The plugin pointer

	std::string sourceFile = "";       // The source file name (Independent)
	std::string sinkFile = "";         // The sink file name (Dependent)
	bool debug = false;                // Print debug information?
	int enableTaintAt = 1;             // Instruction # @ which to enable taint
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
int cbf_beforeBlockTranslate(CPUState *cpu, target_ulong pc);

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
/// Callback function for the syscalls2 "on_sys_pwrite64_enter_t" event.
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
void cbf_pwrite64Enter(CPUState *cpu, target_ulong pc, uint32_t fd,
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
void cbf_writeEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
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
/// Returns a string with the filename corresponding to the specified file
/// descriptor.
/// </summary>
/// <param name="cpu">
/// The CPU State pointer.
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
std::string getFileName(CPUState *cpu, int fd, bool debug = false);

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
/// Prints a string that a file was interacted with by some system call, if
/// the debug mode of the plugin is enabled, in the following format:
/// "dependency_file: saw $<param ref="event">$ called for file 
/// \"$<param ref="file">$\" at instruction $rr_get_guest_instr_count()$."
/// </summary>
/// <param name="event">
/// The name of the event.
/// </param>
/// <param name="file">
/// The name of the file.
/// </param>
void logFileCallback(const std::string &event, const std::string &file);

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

bool sawReadOfSource = false;                   // Was source file read from?
bool sawWriteOfSink = false;                    // Was sink file written to?
bool dependency = false;                        // Is sink dependent on source?

#endif
