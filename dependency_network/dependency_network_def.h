#ifndef DEPENDENCY_NETWORK_H
#define DEPENDENCY_NETWORK_H

struct Dependency_Network {
	void *plugin_ptr = nullptr;        // The plugin pointer
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
bool init_plugin(void *self);

/// <summary>
/// Destroys this plugin.
/// </summary>
/// <param name="self">
/// The plugin pointer passed in from PANDA.
/// </param>
void uninit_plugin(void *self);

#endif
