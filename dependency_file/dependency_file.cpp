#include "dependency_file_def.h"

#include <iostream>

#include "utils.h"

int cbf_beforeBlockExectuion(CPUState *cpu, TranslationBlock *tB) {
	// Do nothing if PANDA is not in Kernel Mode
	if (!panda_in_kernel(cpu)) return 0;
	
	// Get the current process using OSI and add it to the processes map
	OsiProc *process = get_current_process(cpu);
	target_ulong asid = panda_current_asid(cpu);
	processesMap[asid] = *process;
	
	// Free the OSI process wrapper
	free_osiproc(process);
	return 1;
}

void cbf_pread64Enter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count, uint64_t pos) {
	// Get current ASID from PANDA
	target_ulong asid = panda_current_asid(cpu);

	// If any process has the ASID, we can use it to get the name of the file
	// which this pread64_enter function is being called for.
	std::cout << "ASID: " << asid << std::endl;
	if (processesMap.count(asid) > 0) {
		auto &process = processesMap[asid];

		char *fileNamePtr = osi_linux_fd_to_filename(cpu, &process, fd);
		if (!fileNamePtr) { 
			std::cerr << "osi_linux_fd_to_filename failed." << std::endl;
			return;
		}

		std::string fileName(fileNamePtr);
		std::cout << "File Read Enter: " << fileName << std::endl;
	}
	// Else, we do not know what this process is and so we cannot get the name
	// of the file.
	else {
		std::cerr << "pread64_enter was triggered but asid " << asid <<
			" is not known." << std::endl;
	}
}

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

bool init_plugin(void *self) {
	dependency_file.plugin_ptr = self;
	
	// Load dependent plugins
	panda_require("osi");
	assert(init_osi_api());
	panda_require("osi_linux");
	assert(init_osi_linux_api());
	panda_require("syscalls2");
	
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
	
	// Register the Before Block Execution Functions
	panda_cb pcb;
	pcb.before_block_exec = cbf_beforeBlockExectuion;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	std::cout << "Initialized dependency_file plugin" << std::endl;
	return true;
}

void uninit_plugin(void *self) {
	printf("Goodbye World from Dependency_File Plugin.\n");
}
