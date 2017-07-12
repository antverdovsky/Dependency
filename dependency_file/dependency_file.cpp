#include <iostream>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "dependency_file.h"

Dependency_File dependency_file;

bool init_plugin(void *self) {
	std::cout << "Initiailizing dependency_file plugin" << std::endl;
	dependency_file.plugin_ptr = self;
	
	// Parse Arguments:
	// "source" : The source file name, defaults to "source.txt"
	// "sink"   : The sink file name, defaults to "sink.txt"
	// "debug"  : Should debug mode be used? Defaults to false
	auto args = panda_get_args("dependency_file");
	dependency_file.sourceFile = panda_parse_string_opt(args, "source", 
		"source.txt", "source file name");
	dependency_file.sinkFile = panda_parse_string_opt(args, "sink", 
		"sink.txt", "sink file name");
	dependency_file.debug = panda_parse_bool_opt(args, "debug",
		"debug mode");

	std::cout << "Source File: " << dependency_file.sourceFile << std::endl;
	std::cout << "Sink File: " << dependency_file.sinkFile << std::endl;
	std::cout << "Debug: " << dependency_file.debug << std::endl;
	
	std::cout << "Initialized dependency_file plugin" << std::endl;
	return true;
}

void uninit_plugin(void *self) {
	printf("Goodbye World from Dependency_File Plugin.\n");
}
