#ifndef DEPENDENCY_FILE_H
#define DEPENDENCY_FILE_H

struct Dependency_File {
	void *plugin_ptr = NULL;           // The plugin pointer

	std::string sourceFile = "";       // The source file name (Independent)
	std::string sinkFile = "";         // The sink file name (Dependent)
	bool debug = false;                // Print debug information?
};

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

#endif
