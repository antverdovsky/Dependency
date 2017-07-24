#include "dependency_tracker_targets.h"

#include <typeinfo>

Target::Target(const TargetType &type) {
	this->type = type;
}

std::string Target::toString() const {
	return ("Base Target; Type: " + std::to_string(this->type));
}

bool Target::operator==(const Target &rhs) const {
	if (typeid(*this) != typeid(rhs)) return false;

	return this->type == type;
}

bool Target::operator!=(const Target &rhs) const {
	return !this->operator==(rhs);
}

std::ostream& operator<<(std::ostream &stream, const Target &target) {
	return stream << target.toString();
}

TargetFile::TargetFile(const std::string &name, const TargetType &type) :
		Target(type) {
	this->fileName = name;
}

std::string TargetFile::toString() const {
	return ("File Target; File: \"" + this->fileName + "\", Type: " + 
		std::to_string(this->type));
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

std::string TargetNetwork::toString() const {
	return ("Network Target; IP : \"" + this->ip + 
		"\", Port: " + std::to_string(this->port) + 
		", Type: " + std::to_string(this->type));
}

bool TargetNetwork::operator==(const Target &rhs) const {
	if (Target::operator!=(rhs)) return false;

	auto rhsTN = static_cast<const TargetNetwork&>(rhs);
	return this->ip == rhsTN.ip && this->port == rhsTN.port;
}

bool TargetNetwork::operator!=(const Target &rhs) const {
	return !this->operator==(rhs);
}
