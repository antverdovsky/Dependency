#include "dependency_tracker_def.h"

#include <iostream>

bool init_plugin(void *self) {
	std::cout << "Hello World from Dependency_Tracker Plugin." << std::endl;

	return true;
}

void uninit_plugin(void *self) {
	std::cout << "Goodbye World from Dependency_Tracker Plugin." << std::endl;
}