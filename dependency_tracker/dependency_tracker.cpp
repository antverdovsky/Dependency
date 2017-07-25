#include "dependency_tracker_def.h"

#include "taint2/taint2.h"

extern "C" {
	#include "taint2/taint2_ext.h"
}

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

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

std::vector<std::unique_ptr<Target>> parseTargets(const std::string &fileName, 
		const TargetType &type) {
	std::vector<std::unique_ptr<Target>> targets;
	std::vector<std::vector<std::string>> lines = parseCSV(fileName);

	unsigned int lineNumber = 0;
	for (auto &line : lines) {
		++lineNumber;

		if (line.size() == 2 && line[0] == "f") {
			std::string fileName = line[1];
	
			auto target = std::unique_ptr<TargetFile>(
				new TargetFile(fileName, type));
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
				new TargetNetwork(ip, port, type));
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
	// The paths to the files containing the sources list and the sinks list
	std::string sourcesFile;
	std::string sinksFile;

	auto args = panda_get_args("dependency_tracker");
	sourcesFile = panda_parse_string_opt(args, "sources", "sources",
		"sources file name");
	sinksFile = panda_parse_string_opt(args, "sinks", "sinks",
		"sinks file name");

	auto sourcesPtrs = parseTargets(sourcesFile, TargetType::SOURCE);
	for (size_t i = 0; i < sourcesPtrs.size(); ++i) {
		TargetSource *t = new TargetSource(std::move(sourcesPtrs[i]), i);
		dependency_tracker.sources.push_back(std::unique_ptr<TargetSource>(t));
	}

	auto sinksPtrs = parseTargets(sinksFile, TargetType::SINK);
	for (size_t i = 0; i < sinksPtrs.size(); ++i) {
		TargetSink *t = new TargetSink(std::move(sinksPtrs[i]), i);
		dependency_tracker.sinks.push_back(std::unique_ptr<TargetSink>(t));
	}

	return true;
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
