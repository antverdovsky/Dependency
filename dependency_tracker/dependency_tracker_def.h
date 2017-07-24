#ifndef DEPENDENCY_TRACKER_H
#define DEPENDENCY_TRACKER_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "dependency_tracker_targets.h"

#include <memory>
#include <string>
#include <vector>

struct Dependency_Tracker {
	void *plugin_ptr = nullptr;                      // The plugin pointer
	
	std::vector<std::unique_ptr<Target>> sources;    // Source Targets
	std::vector<std::unique_ptr<Target>> sinks;      // Sink Targets
};

Dependency_Tracker dependency_tracker; // The Dependency Tracker Structure

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
