#include "dependency_tracker_def.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

std::string getFileName(CPUState *cpu, target_ulong asid, uint32_t fd) {
	if (dependency_tracker.processes.count(asid) > 0) {
		auto &process = dependency_tracker.processes[asid];

		// Get the file name from osi_linux. If failed, print error and 
		// continue with excecution.
		char *fileNamePtr = osi_linux_fd_to_filename(cpu, &process, fd);
		if (!fileNamePtr) {
			if (dependency_tracker.debug) {
				std::cerr << "dependency_tracker: osi_linux_fd_to_filename " <<
					"failed" << " for fd " << fd << ", unable to get file " <<
					"name." << std::endl;
			}
			
			return "";
		}

		// If file name pointer is not null, the function worked, return file
		// name as a string.
		return std::string(fileNamePtr);
	} 

	// If this is reached, then ASID is unknown
	if (dependency_tracker.debug) {
		std::cerr << "dependency_tracker: osi_linux_fd_to_filename failed " <<
			" for fd " << fd << ", because ASID " << asid << " is unknown." <<
			std::endl;
	}
	return "";
}

int labelBufferContents(CPUState *cpu, target_ulong vAddr, uint32_t length,
		uint32_t label) {
	if (!taint2_enabled()) return 0;
	int bytesTainted = 0;               // Total number of bytes tainted
	
	for (auto i = 0; i < length; ++i) {
		// Convert the virtual address to a physical, assert it is valid, if
		// not skip this byte.
		hwaddr pAddr = panda_virt_to_phys(cpu, vAddr + i);
		if (pAddr == (hwaddr)(-1)) continue;
		
		// Else, taint at the physical address specified
		taint2_label_ram(pAddr, label);
		++bytesTainted;
	}
	
	return bytesTainted;
}

int on_before_block_execution(CPUState *cpu, TranslationBlock *tB) {
	// Do nothing if PANDA is not in Kernel Mode
	if (!panda_in_kernel(cpu)) return 0;
	
	// Get the current process using OSI and add it to the processes map
	OsiProc *process = get_current_process(cpu);
	target_ulong asid = panda_current_asid(cpu);
	dependency_tracker.processes[asid] = *process;
	
	// Free the OSI process wrapper
	free_osiproc(process);
	return 1;
}

int on_before_block_translate(CPUState *cpu, target_ulong pc) {
	// Enable taint if current instruction is g.t. when we are supposed to
	// enable taint.
	int instr = rr_get_guest_instr_count();
	if (!taint2_enabled() && instr > dependency_tracker.enableTaintAt) {
		if (dependency_tracker.debug) {
			std::cout << "dependency_tracker: enabling taint at instruction " 
				<< instr << "." << std::endl;
		}
		
		taint2_enable_taint();
	}
	
	return 0;
}

std::vector<std::vector<std::string>> parseCSV(const std::string &fileName) {
	std::vector<std::vector<std::string>> lines;

	// Create the IFS for the file, if failed -> return empty vector
	std::ifstream ifs(fileName);
	if (!ifs.is_open()) return lines;

	// Read the file in line by line
	std::string token;
	std::string line;
	while (std::getline(ifs, line)) {
		std::vector<std::string> tokens;

		// Split the string by quotation marks into tokens
		std::stringstream ssLine(line);		
		while(std::getline(ssLine, token, '"')) {
			std::stringstream ss(token);

			// For each token, split on a comma and add each individual token
			// to the tokens of this line vector.
			while(std::getline(ss, token, ',')) {
				if (!token.empty()) tokens.push_back(token);
			}
			
			// If this token contains a end-quotation mark, add it to the 
			// individual tokens list as well.
			if(std::getline(ssLine, token, '"')) {
				if (!token.empty()) tokens.push_back(token);
			}
		}

		// Add the tokens of this line to the lines list
		if (!tokens.empty()) lines.push_back(tokens);
	}

	return lines;
}

std::vector<std::unique_ptr<Target>> parseTargets(const std::string &file) {
	std::vector<std::unique_ptr<Target>> targets;
	std::vector<std::vector<std::string>> lines = parseCSV(file);

	unsigned int lineNumber = 0;
	for (auto &line : lines) {
		++lineNumber;

		if (line.size() == 2 && line[0] == "f") {
			std::string fileName = line[1];
	
			auto target = std::unique_ptr<TargetFile>(
				new TargetFile(fileName));
			targets.push_back(std::move(target));
		} else if (line.size() == 3 && line[0] == "n") {
			std::string ip = line[1];
			unsigned short port = 0;			

			try {
				port = (unsigned short)(stoi(line[2]));
			} catch (const std::invalid_argument &e) {
				std::cerr << "dependency_tracker: error parsing port of "
					"network target on line " << lineNumber << "." << 
					std::endl;
				continue;
			} catch (const std::out_of_range &e) {
				std::cerr << "dependency_tracker: error parsing port of "
					"network target on line " << lineNumber << "." << 
					std::endl;
				continue;
			}

			auto target = std::unique_ptr<TargetNetwork>(
				new TargetNetwork(ip, port));
			targets.push_back(std::move(target));
		} else {
			std::cerr << "dependency_tracker: unknown target on line " <<
				lineNumber << "." << std::endl;
		}
	}

	return targets;
}

std::map<uint32_t, std::set<uint32_t>> queryBufferContents(
		CPUState *cpu, target_ulong vAddr, uint32_t length) {
	std::map<uint32_t, std::set<uint32_t>> map; // { displacement -> labels }
	if (!taint2_enabled()) return map;
	
	for (auto i = 0; i < length; ++i) {
		// Convert the virtual address to a physical, assert it is valid, if
		// not skip this byte.
		hwaddr pAddr = panda_virt_to_phys(cpu, vAddr + i);
		if (pAddr == (hwaddr)(-1)) continue;
		
		// Get the label set for the physical address and add it to the map
		LabelSetP labelSet = taint2_query_set_ram(pAddr);
		map[i] = *labelSet;
	}
	
	return map;
}

bool init_plugin(void *self) {
#ifdef TARGET_I386
	// Load dependent plugins
	panda_require("osi");
	panda_require("osi_linux");
	panda_require("syscalls2");
	panda_require("taint2");
	
	// Assert dependent plugins were loaded correctly
	assert(init_osi_api());
	assert(init_osi_linux_api());
	assert(init_taint2_api());

	// The paths to the files containing the sources list and the sinks list
	std::string sourcesFile;
	std::string sinksFile;

	// Fetch arguments from PANDA
	auto args = panda_get_args("dependency_tracker");
	sourcesFile = panda_parse_string_opt(args, "sources", "sources",
		"sources file name");
	sinksFile = panda_parse_string_opt(args, "sinks", "sinks",
		"sinks file name");
	dependency_tracker.debug = panda_parse_bool_opt(args, "debug", 
		"debug mode");

	// Read the sources and sinks files, parse data into targets and add to
	// plugin structure.
	auto sourcesPtrs = parseTargets(sourcesFile);
	for (size_t i = 0; i < sourcesPtrs.size(); ++i) {
		TargetSource *t = new TargetSource(std::move(sourcesPtrs[i]), i);
		dependency_tracker.sources.push_back(std::unique_ptr<TargetSource>(t));
	}
	auto sinksPtrs = parseTargets(sinksFile);
	for (size_t i = 0; i < sinksPtrs.size(); ++i) {
		TargetSink *t = new TargetSink(std::move(sinksPtrs[i]), i);
		dependency_tracker.sinks.push_back(std::unique_ptr<TargetSink>(t));
	}
	
	// Register the Panda Block Functions
	panda_cb pcb;
	pcb.before_block_translate = on_before_block_translate;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
	pcb.before_block_exec = on_before_block_execution;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	
	// Print debug info, if available
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: debug mode enabled. " << std::endl;
		std::cout << "dependency_tracker: found " << sourcesPtrs.size() << 
			" sources." << std::endl;
		std::cout << "dependency_tracker: found " << sinksPtrs.size() << 
			" sinks." << std::endl;
	}

	return true;
#else
	std::cout << "dependency_tracker is only supported for i386 targets." <<
		std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
	std::cout << "Goodbye World from Dependency_Tracker Plugin." << std::endl;

	std::cout << "Sources: " << std::endl;
	for (auto &src : dependency_tracker.sources) { 
		std::cout << "\t" << src->getTarget().toString() << std::endl;
	}

	std::cout << "Sinks: " << std::endl;
	for (auto &sink : dependency_tracker.sinks) { 
		std::cout << "\t" << sink->getTarget().toString() << std::endl;
	}
}
