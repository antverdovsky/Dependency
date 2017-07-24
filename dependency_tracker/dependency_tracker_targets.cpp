#include "dependency_tracker_targets.h"

#include <typeinfo>

Target::Target(const TargetType &type) {
	this->type = type;
}

bool Target::operator==(const Target &rhs) const {
	if (typeid(*this) != typeid(rhs)) return false;

	return this->type == type;
}

bool Target::operator!=(const Target &rhs) const {
	return !this->operator==(rhs);
}

TargetFile::TargetFile(const std::string &name, const TargetType &type) :
		Target(type) {
	this->fileName = name;
}

bool TargetFile::operator==(const Target &rhs) const {
	if (Target::operator!=(rhs)) return false;

	auto rhsTF = static_cast<const TargetFile&>(rhs);
	return this->fileName == rhsTF.fileName;
}

bool TargetFile::operator!=(const Target &rhs) const {
	return !this->operator==(rhs);
}

TargetNetwork::TargetNetwork(const std::string &ip, const unsigned int &port, 
		const TargetType &type) : Target(type) {
	this->ip = ip;
	this->port = port;
}

bool TargetNetwork::operator==(const Target &rhs) const {
	if (Target::operator!=(rhs)) return false;

	auto rhsTN = static_cast<const TargetNetwork&>(rhs);
	return this->ip == rhsTN.ip && this->port == rhsTN.port;
}

bool TargetNetwork::operator!=(const Target &rhs) const {
	return !this->operator==(rhs);
}
