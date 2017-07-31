#include "dependency_tracker_def.h"

#include <fstream>
#include <iostream>
#include <math.h>
#include <sstream>
#include <stdexcept>

#include <linux/net.h>

template<typename T>
std::vector<T> getMemoryValues(CPUState *cpu, uint32_t addr, uint32_t size) {
	std::vector<T> values;
	
	// An array of raw memory bytes. Since we want to fetch T elements from
	// memory and we need enough bytes to store a single instance of T, so the 
	// array's size is equivalent to the size of a single T.
	uint8_t raw[sizeof(T)];
	
	for (auto i = 0; i < size; ++i) {
		// For each value, read the bytes from memory and store them into
		// the raw memory array. Cast the raw memory to T and store in the 
		// values list.
		panda_virtual_memory_rw(cpu, addr + i * sizeof(T), raw, sizeof(T), 0);
		T value = *(reinterpret_cast<T*>(raw));
		values.push_back(value);
	}
	
	return values;
}

TargetFile getTargetFile(CPUState *cpu, target_ulong asid, uint32_t fd) {
	if (dependency_tracker.processes.count(asid) > 0) {
		auto &process = dependency_tracker.processes[asid];

		// Get the file name from osi_linux. If failed, print error and 
		// continue with execution.
		char *fileNamePtr = osi_linux_fd_to_filename(cpu, &process, fd);
		if (!fileNamePtr) {
			if (dependency_tracker.logErrors) {
				std::cerr << "dependency_tracker: osi_linux_fd_to_filename " <<
					"failed" << " for fd " << fd << ", unable to get file " <<
					"name." << std::endl;
			}

			return TargetFile();
		}

		// If file name pointer is not null, the function worked, return file
		// name as a string.
		return TargetFile(std::string(fileNamePtr));
	}

	// If this is reached, then ASID is unknown
	if (dependency_tracker.logErrors) {
		std::cerr << "dependency_tracker: osi_linux_fd_to_filename failed " <<
			" for fd " << fd << ", because ASID " << asid << " is unknown." <<
			std::endl;
	}
	return TargetFile();
}

TargetNetwork getTargetNetwork(target_ulong asid, uint32_t fd) {
	try {
		return dependency_tracker.networks.at(std::make_pair(asid, fd));
	} catch (const std::out_of_range &e) {
		if (dependency_tracker.logErrors) {		
			std::cerr << "dependency_tracker: failed to fetch network for fd " 
				<< fd << " and ASID " << asid << "." << std::endl;
		}

		return TargetNetwork();
	}
}

TargetSink& getTargetSink(const Target &target) {
	for (const auto &sink : dependency_tracker.sinks) {
		if (sink->getTarget() == target) {
			return *sink;
		}
	}
	
	throw std::invalid_argument("no sink exists for specified target");
}

TargetSource& getTargetSource(const Target &target) {
	for (const auto &source : dependency_tracker.sources) {
		if (source->getTarget() == target) {
			return *source;
		}
	}
	
	throw std::invalid_argument("no source exists for specified target");
}

bool isSink(const Target &target) {
	try {
		getTargetSink(target);
		return true;
	} catch (const std::invalid_argument &e) {
		return false;
	}
}

bool isSource(const Target &target) {
	try {
		getTargetSource(target);
		return true;
	} catch (const std::invalid_argument &e) {
		return false;
	}
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
		taint2_label_ram_additive(pAddr, label);
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

void on_pread64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	// For pread64 events, we assume that the target being read is a file or a
	// network, so try finding the TargetFile/TargetNetwork associated with the
	// file descriptor argument.
	TargetFile tF = getTargetFile(cpu, panda_current_asid(cpu), fd);
	TargetNetwork tN = getTargetNetwork(panda_current_asid(cpu), fd);
	
	// For each target type, if it is valid, set the target pointer to it. If
	// no target returned is valid, return because we don't know what this file
	// descriptor corresponds to.
	Target *target = nullptr;
	if (tF)      target = &tF;
	else if (tN) target = &tN;
	else         return;

	// Log that a recognizable target was seen
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: saw read of target \"" << *target << 
			"\"." << std::endl;
	}

	// Get the pointer to the target source associated with the fetched target
	TargetSource *targetSource = nullptr;
	try {
		targetSource = &getTargetSource(*target);
	} catch (const std::invalid_argument &e) {
		return;
	}

	// Get the true buffer length. For files, this is stored in the the EAX
	// register, but for networks the buffer count provided is accurate.
	uint32_t actualCount = count;
	if (tF) 
		actualCount = ((CPUArchState*)cpu->env_ptr)->regs[0];
		
	// Skip if nothing is actually being read from the file
	if (actualCount <= 0) return;
	
	// Label the buffer contents, add number of tainted bytes to the target
	// source.
	uint32_t bytes = labelBufferContents(cpu, buffer, actualCount, 
		targetSource->getIndex());
	targetSource->getLabeledBytes() += bytes;
	
	// Notify Target Source of the read
	targetSource->getTotalBytes() += actualCount;
	targetSource->getTotalReads()++;
	
	// Output that the target source was seen and tainted, if applicable
	std::cout << "dependency_tracker: ***saw read of source target: \"" <<
		*target << "\", tainted " << bytes << "/" << actualCount <<
		" bytes with label " << targetSource->getIndex() << "***" << std::endl;
}

void on_pwrite64_return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	// For pwrite64 events, we assume that the target being read is a file or a
	// network, so try finding the TargetFile/TargetNetwork associated with the
	// file descriptor argument.
	TargetFile tF = getTargetFile(cpu, panda_current_asid(cpu), fd);
	TargetNetwork tN = getTargetNetwork(panda_current_asid(cpu), fd);
	
	// For each target type, if it is valid, set the target pointer to it. If
	// no target returned is valid, return because we don't know what this file
	// descriptor corresponds to.
	Target *target = nullptr;
	if (tF)      target = &tF;
	else if (tN) target = &tN;
	else         return;

	// Log that a recognizable target was seen
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: saw write of target \"" << *target << 
			"\"." << std::endl;
	}
	
	// Get the pointer to the target sink associated with the fetched target
	TargetSink *targetSink = nullptr;
	try {
		targetSink = &getTargetSink(*target);
	} catch (const std::invalid_argument &e) {
		return;
	}
	
	// Skip if nothing is actually being written to the file
	if (count <= 0) return;
	
	// Query the buffer contents, add the results to the labeled bytes
	// property of the sink.
	std::map<uint32_t, uint32_t> bytes = queryBufferContents(
		cpu, buffer, count);
	uint32_t totalTaintBytes = 0;
	for (auto &it : bytes) {
		uint32_t source = it.first;
		uint32_t numTainted = it.second;
		
		// Note here that if source D.N.E. in the labeled bytes map, it will
		// be default constructed with a value of zero.
		targetSink->getLabeledBytes()[source] += numTainted;
		totalTaintBytes += numTainted;
		
		std::cout << "dependency_tracker: ***saw write of sink target \"" <<
			*target << "\", " << numTainted << "/" << count << 
			" bytes written to target with label " << source << "***" << 
			std::endl;
	}
	
	// Notify Target Sink of the write
	targetSink->getTotalBytes() += count;
	targetSink->getTotalTaintBytes() += totalTaintBytes;
	targetSink->getTotalWrites()++;
}

void on_read_return(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	on_pread64_return(cpu, pc, fd, buffer, count, 0);
}

void on_socketcall_return(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args) {
	switch (call) {
	case SYS_CONNECT:
		return on_socketcall_connect_return(cpu, args);
	case SYS_RECV:
	case SYS_RECVFROM:
		return on_socketcall_recv_return(cpu, args);
	case SYS_SEND:
	case SYS_SENDTO:
		return on_socketcall_send_return(cpu, args);
	}
}

void on_socketcall_connect_return(CPUState *cpu, uint32_t args) {
	// Get the arguments from the args virtual memory
	auto arguments = getMemoryValues<uint32_t>(cpu, args, 3);

	// Get the sockaddr structure from the arguments. The virtual memory 
	// address to the sockaddr structure is stored in the second argument of
	// the args passed to connect(). Use that address to get the sockaddr.
	auto sockaddrPtr = arguments[1];
	sockaddr addr = getMemoryValues<sockaddr>(cpu, sockaddrPtr, 1)[0];
	
	// Stores the IP address found and the port number
	char ip[INET6_ADDRSTRLEN] = {0};
	unsigned short port = 0;
	
	// Get the IP address and Port Number using the sockaddr structure. We
	// only process IPv4 and IPv6 connections here.
	auto saFam = addr.sa_family;
	if (saFam == AF_INET) {
		sockaddr_in *sin4 = reinterpret_cast<sockaddr_in*>(&addr);
		
		inet_ntop(AF_INET, &sin4->sin_addr, ip, INET6_ADDRSTRLEN);
		port = sin4->sin_port;
	} else if (saFam == AF_INET6) {
		sockaddr_in6 *sin6 = reinterpret_cast<sockaddr_in6*>(&addr);
		
		inet_ntop(AF_INET6, &sin6->sin6_addr, ip, INET6_ADDRSTRLEN);
		port = sin6->sin6_port;
	} else {
		return;
	}
	
	// Map the current ASID and File Descriptor to the Network Target.
	int sockfd = arguments[0];
	auto asid_fd_pair = std::make_pair(panda_current_asid(cpu), sockfd);
	TargetNetwork target(std::string(ip), port);
	dependency_tracker.networks[asid_fd_pair] = target;

	// Log that a recognizable target was seen
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: saw connect to target \"" << target 
			<< "\"." << std::endl;
	}
	
	// Log connection if this is a source or sink
	if (isSource(target)) {
		std::cout << "dependency_tracker: ***saw connect to source target: \"" 
			<< target << "\"***" << std::endl;
	} else if (isSink(target)) {
		std::cout << "dependency_tracker: ***saw connect to sink target: \"" 
			<< target << "\"***" << std::endl;
	}
}

void on_socketcall_recv_return(CPUState *cpu, uint32_t args) {
	// Get the arguments from the args virtual memory
	auto arguments = getMemoryValues<uint32_t>(cpu, args, 3);
	
	// Retrieve the socket file descriptor, buffer address and buffer length
	// from the arguments.
	uint32_t sockfd = arguments[0];
	uint32_t buffer = arguments[1];
	uint32_t length = arguments[2];
	
	// Skip if nothing is actually being recieved
	if (length <= 0) return;
	
	// We are expecting a Source Network Target here, so we only have to try to
	// get a Network Target.
	TargetNetwork tN = getTargetNetwork(panda_current_asid(cpu), sockfd);
	
	// Check that the target network is valid, if not continue
	Target *target = nullptr;
	if (tN)      target = &tN;
	else         return;

	// Log that a recognizable target was seen
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: saw recv from target \"" << *target 
			<< "\"." << std::endl;
	}
	
	// Get the pointer to the target source associated with the fetched target
	TargetSource *targetSource = nullptr;
	try {
		targetSource = &getTargetSource(*target);
	} catch (const std::invalid_argument &e) {
		return;
	}
	
	// Label the buffer contents, add number of tainted bytes to the target
	// source.
	uint32_t bytes = labelBufferContents(cpu, buffer, length, 
		targetSource->getIndex());
	targetSource->getLabeledBytes() += bytes;
	
	// Notify Target Source of the read
	targetSource->getTotalBytes() += length;
	targetSource->getTotalReads()++;
	
	// Output that the target source was seen and tainted, if applicable
	std::cout << "dependency_tracker: ***saw recv of source target: \"" <<
		*target << "\", tainted " << bytes << "/" << length << 
		" bytes with label " << targetSource->getIndex() << "***" << std::endl;
}

void on_socketcall_send_return(CPUState *cpu, uint32_t args) {
	// Get the arguments from the args virtual memory
	auto arguments = getMemoryValues<uint32_t>(cpu, args, 3);
	
	// Retrieve the socket file descriptor, buffer address and buffer length
	// from the arguments.
	uint32_t sockfd = arguments[0];
	uint32_t buffer = arguments[1];
	uint32_t length = arguments[2];
	
	// Skip if nothing is actually being sent
	if (length <= 0) return;
	
	// We are expecting a Sink Network Target here, so we only have to try to
	// get a Network Target.
	TargetNetwork tN = getTargetNetwork(panda_current_asid(cpu), sockfd);

	// Check that the target network is valid, if not continue
	Target *target = nullptr;
	if (tN)      target = &tN;
	else         return;

		// Log that a recognizable target was seen
	if (dependency_tracker.debug) {
		std::cout << "dependency_tracker: saw send to target \"" << *target << 
			"\"." << std::endl;
	}

	// Get the pointer to the target source associated with the fetched target
	TargetSink *targetSink = nullptr;
	try {
		targetSink = &getTargetSink(*target);
	} catch (const std::invalid_argument &e) {
		return;
	}

	// Query the buffer contents, add the results to the labeled bytes
	// property of the sink.
	std::map<uint32_t, uint32_t> bytes = queryBufferContents(
		cpu, buffer, length);
	uint32_t totalTaintBytes = 0;
	for (auto &it : bytes) {
		uint32_t source = it.first;
		uint32_t numTainted = it.second;
		
		// Note here that if source D.N.E. in the labeled bytes map, it will
		// be default constructed with a value of zero.
		targetSink->getLabeledBytes()[source] += numTainted;
		totalTaintBytes += numTainted;
		
		std::cout << "dependency_tracker: ***saw send of sink target \"" <<
			*target << "\", " << numTainted << "/" << length << 
			" bytes written to target with label " << source << "***" << 
			std::endl;
	}
	
	// Notify Target Sink of the write
	targetSink->getTotalBytes() += length;
	targetSink->getTotalTaintBytes() += totalTaintBytes;
	targetSink->getTotalWrites()++;
}

void on_write_return(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	on_pwrite64_return(cpu, pc, fd, buffer, count, 0);
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

std::map<uint32_t, uint32_t> queryBufferContents(
		CPUState *cpu, target_ulong vAddr, uint32_t length) {
	std::map<uint32_t, uint32_t> map; // { label -> number of bytes tainted }
	if (!taint2_enabled()) return map;
	
	for (auto i = 0; i < length; ++i) {
		// Convert the virtual address to a physical, assert it is valid, if
		// not skip this byte.
		hwaddr pAddr = panda_virt_to_phys(cpu, vAddr + i);
		if (pAddr == (hwaddr)(-1)) continue;
		
		// Initialize the label set to store the sources which tainted this
		// byte. By default, set each source index to a negative number to
		// indicate no source wrote anything to this byte.
		uint32_t labelSetSize = taint2_query_ram(pAddr);
		uint32_t labelSet[labelSetSize];
		for (auto i = 0; i < labelSetSize; ++i) labelSet[i] = -1;

		// Get the label set for the physical address and for each label in
		// the set, increment the number of bytes tainted with it by one.
		taint2_query_set_ram(pAddr, labelSet);
		for (auto label : labelSet) {
			// Occurs if taint2_query_set_ram did not write to this element of
			// the labelSet array.
			if (label == (uint32_t)(-1)) continue;

			++map[label];
		}
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
		"debug mode?");
	dependency_tracker.logErrors = panda_parse_bool_opt(args, "logFail",
		"log failed target fetches?");
	dependency_tracker.enableTaintAt = panda_parse_uint64_opt(args, "taintAt",
		1, "enable taint at instruction number");

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

	// Register SysCalls2 Callback Functions
	PPP_REG_CB("syscalls2", on_sys_socketcall_return, on_socketcall_return);
	PPP_REG_CB("syscalls2", on_sys_pread64_return, on_pread64_return);
	PPP_REG_CB("syscalls2", on_sys_read_return, on_read_return);
	PPP_REG_CB("syscalls2", on_sys_pwrite64_return, on_pwrite64_return);
	PPP_REG_CB("syscalls2", on_sys_write_return, on_write_return);
	
	// Print debug info, if available
	if (dependency_tracker.debug) {
		uint64_t taintAt = dependency_tracker.enableTaintAt;

		std::cout << "dependency_tracker: debug mode enabled. " << std::endl;
		std::cout << "dependency_tracker: found " << sourcesPtrs.size() << 
			" sources." << std::endl;
		std::cout << "dependency_tracker: found " << sinksPtrs.size() << 
			" sinks." << std::endl;
		std::cout << "dependency_tracker: log errors? " << 
			(dependency_tracker.logErrors ? "yes." : "no.") << std::endl;
		std::cout << "dependency_tracker: enabling taint2 at instruction : " <<
			((taintAt == (uint64_t)(-1)) ? "never" : std::to_string(taintAt)) 
			<< "." << std::endl;
	}

	return true;
#else
	std::cout << "dependency_tracker is only supported for i386 targets." <<
		std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
	// Foreach target source, output the name of the target and how many of its
	// bytes were tainted.
	for (auto &source : dependency_tracker.sources) {
		std::cout << "Source: \"" << source->getTarget() << "\": labeled " <<
			source->getLabeledBytes() << "/" << source->getTotalBytes() <<
			std::endl;
	}
	
	std::cout << std::endl;
	
	// Foreach target sink, output the name of the target, and for each source
	// which wrote to that sink, output the name of the source and the number 
	// of tainted bytes written.
	for (auto &sink : dependency_tracker.sinks) {
		// Skip this sink if no tainted bytes were written to it.
		if (sink->getTotalTaintBytes() < 1) continue;
		
		std::cout << "Sink: \"" << sink->getTarget() << "\":" << std::endl;
		std::cout << "\t" << "Total Writes: " << sink->getTotalWrites() <<
			std::endl;
		std::cout << "\t" << "Total Bytes Written: " << 
			sink->getTotalBytes() << std::endl;

		auto &labeledBytes = sink->getLabeledBytes();
		for (auto &it : labeledBytes) {
			// Get the source which wrote to this sink, skip if nothing from 
			// that source was written to the sink.
			uint32_t source = it.first;
			uint32_t numTainted = it.second;
			if (numTainted <= 0) continue;
			
			// Get the source target and output how many of its tainted bytes
			// ended up in this sink.
			TargetSource &targetSource = *dependency_tracker.sources[source];
			const Target &target = targetSource.getTarget();
			std::cout << "\t";
			std::cout << "Source: " << "\"" << target << "\": " << 
				numTainted << "/" << sink->getTotalBytes() << 
				" tainted bytes written to this." << std::endl;
		}
	}
}
