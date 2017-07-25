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

struct Dependency_Tracker {
	void *plugin_ptr = nullptr;                          // The plugin pointer
	target_ulong enableTaintAt = UINT32_MAX;             // I# to enable taint
	bool debug = false;                                  // Print debug info?
	
	std::vector<std::unique_ptr<TargetSource>> sources;  // Source Targets
	std::vector<std::unique_ptr<TargetSink>> sinks;      // Sink Targets
	
	std::map<target_ulong, OsiProc> processes;           // { ASID -> Process }
};

Dependency_Tracker dependency_tracker;                   // Plugin Reference

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
/// <param name="fileName">
/// The name of the CSV file from which to parse the targets.
/// </param>
/// <param name="type">
/// The type of the targets being read in (sources or sinks).
/// </param>
/// <returns>
/// The vector containing all valid targets which were successfully read in
/// from the file.
/// </returns>
std::vector<std::unique_ptr<Target>> parseTargets(const std::string &fileName, 
		const TargetType &type);
		
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
/// A map of the displacement from the <param ref="vAddr"> to the labels
/// applied at that address.
/// </returns>
std::map<uint32_t, std::set<uint32_t>> queryBufferContents(
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
/// Destroys this plugin.
/// </summary>
/// <param name="self">
/// The plugin pointer passed in from PANDA.
/// </param>
extern "C" void uninit_plugin(void *self);

#endif
