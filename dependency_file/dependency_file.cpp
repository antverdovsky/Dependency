#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "dependency_file.h"

bool init_plugin(void *self) {
	plugin_ptr = self;
	printf("Hello World from Dependency_File Plugin.\n");

	return true;
}

void uninit_plugin(void *self) {
	printf("Goodbye World from Dependency_File Plugin.\n");
}
