#include "dependency_file_def.h"

#include <iostream>

#include "utils.h"

Dependency_File dependency_file;

void cbf_openEnter(CPUState *cpu, target_ulong pc, uint32_t fileAddr, int32_t
		flags, int32_t mode) {
	// Get the file name from memory (256 is used for the maximum length since
	// the maximum length of a linux file is 255, plus one for \0).
	std::string fileName = getGuestString(cpu, 256, fileAddr);
	
	std::cout << "Detected File Opened, Name: " << fileName << std::endl;
}

void cbf_readEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	// Since read is just pread which starts at zero, call the callback 
	// function for pread with zero as the starting position.
	cbf_pread64Enter(cpu, pc, fd, buffer, count, 0);
}

void cbf_pread64Enter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count, uint64_t pos) {
	std::string bufferStr = getGuestString(cpu, count, buffer);
	
	std::cout << "Buffer Contents: " << bufferStr << std::endl;
}

bool init_plugin(void *self) {
	dependency_file.plugin_ptr = self;
	
	// Load dependent plugins
	panda_require("osi");
	panda_require("syscalls2");
	panda_require("osi_linux");
	assert(init_osi_api);
	assert(init_osi_linux_api);
	
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
	
	// Register SysCalls2 Callback Functions
	PPP_REG_CB("syscalls2", on_sys_open_enter, cbf_openEnter);
	PPP_REG_CB("syscalls2", on_sys_read_enter, cbf_readEnter);
	PPP_REG_CB("syscalls2", on_sys_pread64_enter, cbf_pread64Enter);
	
	std::cout << "Initialized dependency_file plugin" << std::endl;
	return true;
}

void uninit_plugin(void *self) {
	printf("Goodbye World from Dependency_File Plugin.\n");
}
