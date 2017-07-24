#ifndef DEPENDENCY_TRACKER_H
#define DEPENDENCY_TRACKER_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "dependency_tracker_targets.h"

#include <vector>

struct Dependency_Tracker {
	void *plugin_ptr = nullptr;        // The plugin pointer
	
	std::vector<Target> sources;       // All of the source targets
	std::vector<Target> sinks;         // All of the sink targets
};

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
