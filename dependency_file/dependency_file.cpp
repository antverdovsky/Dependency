#include "dependency_file_def.h"

#include <iostream>

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

int cbf_beforeBlockTranslate(CPUState *cpu, target_ulong pc) {
	// Enable taint if current instruction is g.t. when we are supposed to
	// enable taint.
	int instr = rr_get_guest_instr_count();
	if (!taint2_enabled() && instr > dependency_file.enableTaintAt) {
		if (dependency_file.debug) {
			std::cout << "dependency_file: enabling taint at instruction " <<
				instr << "." << std::endl;
				
		}
		
		taint2_enable_taint();
	}
	
	return 0;
}

void cbf_pread64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	std::string fileName = getFileName(cpu, fd);
	logFileCallback("pread64_return", fileName);
	
	if (fileName == dependency_file.sourceFile) {
		std::cout << "dependency_file: ***saw read return of source file***" <<
			std::endl;
		sawReadOfSource = true;
		
		// The count passed in by on_sys_pread64_enter_t is NOT accurate, the
		// actual buffer length is stored in register EAX (located at index 
		// zero in CPU's registers array).
		int actualCount = ((CPUArchState*)cpu->env_ptr)->regs[0];
		int numTainted = labelBufferContents(cpu, buffer, actualCount);
		if (dependency_file.debug) {
			std::cout << "dependency_file: " << numTainted << 
				" tainted bytes read from \"" << fileName << "\"." << 
				std::endl;
		}
		
		taintedBytesLabeled += numTainted;
	}
}

void cbf_pwrite64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	std::string fileName = getFileName(cpu, fd);
	logFileCallback("pwrite64_return", fileName);
	
	if (fileName == dependency_file.sinkFile) {
		std::cout << "dependency_file: ***saw pwrite enter of sink file***" << 
			std::endl;
		sawWriteOfSink = true;
		
		int numTainted = queryBufferContents(cpu, buffer, count);
		if (dependency_file.debug) {
			std::cout << "dependency_file: " << numTainted << 
				" tainted bytes written to \"" << fileName << "\"." << 
				std::endl;
		}

		taintedBytesQueried += numTainted;
	}
}

void cbf_openEnter(CPUState *cpu, target_ulong pc, uint32_t fileAddr, int32_t
		flags, int32_t mode) {
	std::string fileName = getGuestString(cpu, 256, fileAddr);
	logFileCallback("open_enter", fileName);
	
	// Since open may only contain the file name and not the full directory,
	// we just search for the name of the file in the source file string. Note
	// that this means that we think we have an open called for the source file
	// when we really don't. This is fine since this just means that we will
	// start tainting sooner than necessary.
	if (!fileName.empty() && !sawOpenOfSource &&
			dependency_file.sourceFile.find(fileName) != std::string::npos) {
		std::cout << "dependency_file: ***saw open enter of source file***" << 
			std::endl;
		
		dependency_file.enableTaintAt = rr_get_guest_instr_count();
		sawOpenOfSource = true;
	}
}

void cbf_readReturn(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	cbf_pread64Return(cpu, pc, fd, buffer, count, 0);
}

void cbf_writeReturn(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count) {
	cbf_pwrite64Return(cpu, pc, fd, buffer, count, 0);
}

std::string getFileName(CPUState *cpu, int fd) {
	// Get current ASID from PANDA
	target_ulong asid = panda_current_asid(cpu);

	// If any process has the ASID, we can use it to get the name of the file
	if (processesMap.count(asid) > 0) {
		auto &process = processesMap[asid];

		// Get the file name from osi_linux. If failed, print error and 
		// continue with excecution.
		char *fileNamePtr = osi_linux_fd_to_filename(cpu, &process, fd);
		if (!fileNamePtr) {
			if (dependency_file.debug) {
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
	if (dependency_file.debug) {
		std::cerr << "dependency_file: no process with asid " << asid << 
			" found, unable to get file name." << std::endl;
	}
	
	return "";
}

std::string getGuestString(CPUState *cpu, size_t maxSize, target_ulong addr) {
	// Create an empty string with all zeros
	std::string str(maxSize, '0');

	for (size_t i = 0; i < maxSize; ++i) {
		// Fetch the unsigned integer character from PANDA's memory. We do this
		// by specifiying the CPU state, the address at which we want to read
		// from (equal to starting address + offset), the pointer to which we
		// want to write the value, 1 to indicate we are reading one byte at a 
		// time, and 0 to indicate we are not writing anything to memory.
		uint8_t uiChar = 0;
		panda_virtual_memory_rw(cpu, addr + i, &uiChar, 1, 0);
		
		// Write the character to the string and check if its the null
		// terminator character. If so, trim the string and return.
		str.at(i) = (char)(uiChar);
		if (str.at(i) == '\0') {
			str = str.substr(0, i);
			return str;
		}
	}
	
	return str;
}

int labelBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length) {
	if (!taint2_enabled()) return 0;
	if (dependency_file.debug) {
		std::cout << "dependency_file: labeling " << length << " bytes " <<
			"starting from virtual address " << vAddr << "." << std::endl;
	}
	
	int bytesTainted = 0; // Number of bytes that were tainted
	for (auto i = 0; i < length; ++i) {
		// Convert the virtual address to a physical, assert it is valid, if
		// not skip this byte.
		hwaddr pAddr = panda_virt_to_phys(cpu, vAddr + i);
		if (pAddr == (hwaddr)(-1) && dependency_file.debug) {
			std::cerr << "dependency_file: unable to taint at address: " <<
				vAddr << " (virtual), " << pAddr << " (physical)." << 
				std::endl;
			continue;
		}
		// Else, taint at the physical address specified
		taint2_label_ram(pAddr, 1);
		++bytesTainted;
	}
	
	if (dependency_file.debug) {
		std::cout << "dependency_file: labeled " << bytesTainted << " out of "
			<< length << " bytes at virtual address " << vAddr << std::endl;
	}
	return bytesTainted;
}

void logFileCallback(const std::string &event, const std::string &file) {
	if (dependency_file.debug) {
		std::cout << "dependency_file: " << event << " called for file \"" <<
			file << "\" at instruction " << rr_get_guest_instr_count() << 
			"." << std::endl;
	}
}

int queryBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length) {
	if (!taint2_enabled()) return -1;
	if (dependency_file.debug) {
		std::cout << "dependency_file: querying " << length << " bytes " <<
			"starting from virtual address " << vAddr << "." << std::endl;
	}
	
	int bytesWithTaint = 0; // Number of bytes which were tainted
	for (auto i = 0; i < length; ++i) {
		// Convert the virtual address to a physical, assert it is valid, if
		// not skip this byte.
		hwaddr pAddr = panda_virt_to_phys(cpu, vAddr + i);
		if (pAddr == (hwaddr)(-1) && dependency_file.debug) {
			std::cerr << "dependency_file: unable to query at address: " <<
				vAddr << " (virtual), " << pAddr << " (physical)." << 
				std::endl;
			continue;
		}
		// Else, query the taint, increment counter if tainted
		uint32_t cardinality = taint2_query_ram(pAddr);
		if (cardinality > 0) ++bytesWithTaint;
	}
	
	if (dependency_file.debug) {
		std::cout << "dependency_file: found " << bytesWithTaint << 
			" tainted bytes out of " << length << " at virtual address " <<
			vAddr << std::endl;
	}
	return bytesWithTaint;
}

bool init_plugin(void *self) {
#ifdef TARGET_I386
	dependency_file.plugin_ptr = self;
	
	/// Load dependent plugins
	panda_require("osi");
	assert(init_osi_api());
	
	panda_require("osi_linux");
	assert(init_osi_linux_api());
	
	panda_require("syscalls2");
	
	panda_require("taint2");
	assert(init_taint2_api());
	
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
	std::cout << "Source File: \"" << dependency_file.sourceFile << "\"" <<
		std::endl;
	std::cout << "Sink File: \"" << dependency_file.sinkFile << "\"" <<
		std::endl;
	std::cout << "Debug: " << dependency_file.debug << std::endl;
	
	// Register SysCalls2 Callback Functions
	PPP_REG_CB("syscalls2", on_sys_open_enter, cbf_openEnter);
	PPP_REG_CB("syscalls2", on_sys_pread64_return, cbf_pread64Return);
	PPP_REG_CB("syscalls2", on_sys_pwrite64_return, cbf_pwrite64Return);
	PPP_REG_CB("syscalls2", on_sys_read_return, cbf_readReturn);
	PPP_REG_CB("syscalls2", on_sys_write_return, cbf_writeReturn);
	
	/// Register the Before Block Execution Functions
	panda_cb pcb;
	
	pcb.before_block_translate = cbf_beforeBlockTranslate;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
	
	pcb.before_block_exec = cbf_beforeBlockExectuion;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	return true;
#else
	std::cout << "dependency_file is only supported for i386 targets." << 
		std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
	std::cout << "dependency_file: saw open of source? " << sawOpenOfSource <<
		std::endl;
	std::cout << "dependency_file: saw read of source? " << sawReadOfSource <<
		std::endl;
	std::cout << "dependency_file: saw write of sink? " << sawWriteOfSink <<
		std::endl;
	std::cout << "dependency_file: number of tainted bytes read from source: "
		<< taintedBytesLabeled << std::endl;
	std::cout << "dependency_file: number of tainted bytes written to sink: " 
		<< taintedBytesQueried << std::endl;
	std::cout << "dependency_file: dependency detected? " << 
		(taintedBytesQueried > 0) << std::endl;
}
