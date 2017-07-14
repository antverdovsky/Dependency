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
	if (dependency_file.debug) {
		std::string file = getFileName(cpu, processesMap, fd, true);
		file = file.empty() ? "ERROR FETCHING; SEE ABOVE OUTPUT." : file;
		
		std::string contents = getGuestString(cpu, count, buffer);
		
		std::cout << "dependency_file: pread64_enter triggered at " <<
			rr_get_guest_instr_count() << std::endl;
		std::cout << "File Descriptor: " << fd << std::endl;
		std::cout << "File Name: " << file << std::endl;
		std::cout << "Buffer Count: " << count << std::endl;
		std::cout << "Buffer Contents:\n------\n " << contents << "\n------" <<
			std::endl;
	}
}

void cbf_pread64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	if (dependency_file.debug) {
		std::string file = getFileName(cpu, processesMap, fd, true);
		file = file.empty() ? "ERROR FETCHING; SEE ABOVE OUTPUT." : file;
		
		std::string contents = getGuestString(cpu, count, buffer);
		int actualCount = ((CPUArchState*)cpu->env_ptr)->regs[0];
		
		std::cout << "dependency_file: pread64_return triggered at " <<
			rr_get_guest_instr_count() << std::endl;
		std::cout << "File Descriptor: " << fd << std::endl;
		std::cout << "File Name: " << file << std::endl;
		std::cout << "Buffer Count: " << count << std::endl;
		std::cout << "Actual Buffer Count: " << actualCount << std::endl;
		std::cout << "Buffer Contents:\n------\n " << contents << "\n------" <<
			std::endl;
	}		
}

void cbf_openEnter(CPUState *cpu, target_ulong pc, uint32_t fileAddr, int32_t
		flags, int32_t mode) {
	if (dependency_file.debug) {
		// 256 is used here since max file name length in Linux is 255 + null
		// terminator.
		std::string file = getGuestString(cpu, 256, fileAddr);
		
		std::cout << "dependency_file: open_enter triggered at " <<
			rr_get_guest_instr_count() << std::endl;
		std::cout << "File Name: " << file << std::endl;
		std::cout << "File Flags: " << flags << std::endl;
		std::cout << "File Mode: " << mode << std::endl;
	}
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
	if (dependency_file.debug) {
		std::string file = getFileName(cpu, processesMap, fd, true);
		file = file.empty() ? "ERROR FETCHING; SEE ABOVE OUTPUT." : file;
		
		std::string contents = getGuestString(cpu, count, buffer);
		int actualCount = ((CPUArchState*)cpu->env_ptr)->regs[0];
		
		std::cout << "dependency_file: write_enter triggered at " <<
			rr_get_guest_instr_count() << std::endl;
		std::cout << "File Descriptor: " << fd << std::endl;
		std::cout << "File Name: " << file << std::endl;
		std::cout << "Buffer Count: " << count << std::endl;
		std::cout << "Actual Buffer Count: " << actualCount << std::endl;
		std::cout << "Buffer Contents:\n------\n " << contents << "\n------" <<
			std::endl;
	}
}

std::string getFileName(CPUState *cpu, 
		std::map<target_ulong, OsiProc>& processes, int fd, bool debug) {
	// Get current ASID from PANDA
	target_ulong asid = panda_current_asid(cpu);

	// If any process has the ASID, we can use it to get the name of the file
	if (processes.count(asid) > 0) {
		auto &process = processes[asid];

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
	printf("Goodbye World from Dependency_File Plugin.\n");
}
