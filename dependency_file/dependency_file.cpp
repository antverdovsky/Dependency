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
	std::string fileName = getFileName(cpu, fd, dependency_file.debug);
	logFileCallback("pread64_enter", fileName);
	
	if (fileName == dependency_file.sourceFile) {
		std::cout << "dependency_file: ***saw read of source file***" << 
			std::endl;
		sawReadOfSource = true;
	}
}

void cbf_pread64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	std::string fileName = getFileName(cpu, fd, dependency_file.debug);
	logFileCallback("pread64_return", fileName);
}

void cbf_openEnter(CPUState *cpu, target_ulong pc, uint32_t fileAddr, int32_t
		flags, int32_t mode) {
	std::string fileName = getGuestString(cpu, fileAddr, 256);
	logFileCallback("open_enter", fileName);
}

void cbf_readEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	// Since read is just pread which starts at zero, call the callback 
	// function for pread with zero as the starting position.
	cbf_pread64Enter(cpu, pc, fd, buffer, count, 0);
}

void cbf_readReturn(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	// See cbf_readEnter for explanation
	cbf_pread64Return(cpu, pc, fd, buffer, count, 0);
}

void cbf_writeEnter(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	std::string fileName = getFileName(cpu, fd, dependency_file.debug);
	logFileCallback("write_enter", fileName);
	
	if (fileName == dependency_file.sinkFile) {
		std::cout << "dependency_file: ***saw write of sink file***" << 
			std::endl;
		sawWriteOfSink = true;
	}
}

std::string getFileName(CPUState *cpu, int fd, bool debug) {
	// Get current ASID from PANDA
	target_ulong asid = panda_current_asid(cpu);

	// If any process has the ASID, we can use it to get the name of the file
	if (processesMap.count(asid) > 0) {
		auto &process = processesMap[asid];

		// Get the file name from osi_linux. If failed, print error and 
		// continue with excecution.
		char *fileNamePtr = osi_linux_fd_to_filename(cpu, &process, fd);
		if (!fileNamePtr) {
			if (debug) {
				std::cerr << "dependency_file: osi_linux_fd_to_filename failed"
					<< " for fd " << fd << ", unable to get file name." << 
					std::endl;
			}
			
			return "";
		}

		// If file name pointer is not null, the function worked, return file
		// name as a string.
		return std::string(fileNamePtr);
	}
	// Else, we do not know what this process is and so we cannot get the name
	// of the file.
	if (debug) {
		std::cerr << "dependency_file: no process with asid " << asid << 
			" found, unable to get file name." << std::endl;
	}
	
	return "";
}

void logFileCallback(const std::string &event, const std::string &file) {
	if (dependency_file.debug) {
		std::cout << "dependency_file: " << event << " called for file " <<
			file << "." << std::endl;
	}
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
	PPP_REG_CB("syscalls2", on_sys_read_return, cbf_readReturn);
	PPP_REG_CB("syscalls2", on_sys_pread64_enter, cbf_pread64Enter);
	PPP_REG_CB("syscalls2", on_sys_pread64_return, cbf_pread64Return);
	PPP_REG_CB("syscalls2", on_sys_write_enter, cbf_writeEnter);
	
	// Register the Before Block Execution Functions
	panda_cb pcb;
	pcb.before_block_exec = cbf_beforeBlockExectuion;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	std::cout << "Initialized dependency_file plugin" << std::endl;
	return true;
}

void uninit_plugin(void *self) {
	std::cout << "dependency_file: saw read of source? " << sawReadOfSource <<
		std::endl;
	std::cout << "dependency_file: saw write of sink? " << sawWriteOfSink <<
		std::endl;
}
