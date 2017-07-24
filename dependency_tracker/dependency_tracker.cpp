#include "dependency_tracker_def.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

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

		for (auto &token : line) {
			std::cout << "\"" << token << "\", ";
		}
		std::cout << std::endl;

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

bool init_plugin(void *self) {
	// The paths to the files containing the sources list and the sinks list
	std::string sourcesFile;
	std::string sinksFile;

	auto args = panda_get_args("dependency_tracker");
	sourcesFile = panda_parse_string_opt(args, "sources", "sources",
		"sources file name");
	sinksFile = panda_parse_string_opt(args, "sinks", "sinks",
		"sinks file name");

	dependency_tracker.sources = parseTargets(sourcesFile, TargetType::SOURCE);
	dependency_tracker.sinks = parseTargets(sinksFile, TargetType::SINK);

	return true;
}

void uninit_plugin(void *self) {
	std::cout << "Goodbye World from Dependency_Tracker Plugin." << std::endl;

	std::cout << "Sources: " << std::endl;
	for (auto &target : dependency_tracker.sources) { 
		std::cout << "\t" << target->toString() << std::endl;
	}

	std::cout << "Sinks: " << std::endl;
	for (auto &target : dependency_tracker.sinks) { 
		std::cout << "\t" << target->toString() << std::endl;
	}
}
