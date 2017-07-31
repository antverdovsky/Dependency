#include "dependency_tracker_targets.h"

#include <typeinfo>

/********************************** TARGET **********************************/
bool Target::operator==(const Target &rhs) const {
	return typeid(*this) == typeid(rhs);
}

bool Target::operator!=(const Target &rhs) const {
	return typeid(*this) != typeid(rhs);
}

std::ostream& operator<<(std::ostream &stream, const Target &target) {
	return stream << target.toString();
}
/********************************** TARGET **********************************/

/******************************* TARGET  SINK *******************************/
TargetSink::TargetSink(std::unique_ptr<Target> target, const size_t &index) {
	this->target = std::move(target);
	this->index = index;
}

const size_t& TargetSink::getIndex() const {
	return this->index;
}

std::map<uint32_t, uint32_t>& TargetSink::getLabeledBytes() {
	return this->labeledBytes;
}

const std::map<uint32_t, uint32_t>& TargetSink::getLabeledBytes() const {
	return this->labeledBytes;
}

const Target& TargetSink::getTarget() const {
	return *this->target;
}

uint32_t& TargetSink::getTotalBytes() {
	return this->totalBytes;
}

const uint32_t& TargetSink::getTotalBytes() const {
	return this->totalBytes;
}

uint32_t& TargetSink::getTotalTaintBytes() {
	return this->totalTaintBytes;
}

const uint32_t& TargetSink::getTotalTaintBytes() const {
	return this->totalTaintBytes;
}

uint32_t& TargetSink::getTotalWrites() {
	return this->totalWrites;
}

const uint32_t& TargetSink::getTotalWrites() const {
	return this->totalWrites;
}

/******************************* TARGET  SINK *******************************/

/****************************** TARGET  SOURCE ******************************/
TargetSource::TargetSource(std::unique_ptr<Target> target, 
		const size_t &index) {
	this->target = std::move(target);
	this->index = index;
	
	this->labeledBytes = 0;
}

const size_t& TargetSource::getIndex() const {
	return this->index;
}

uint32_t& TargetSource::getLabeledBytes() {
	return this->labeledBytes;
}

const uint32_t& TargetSource::getLabeledBytes() const {
	return this->labeledBytes;
}

const Target& TargetSource::getTarget() const {
	return *this->target;
}

uint32_t& TargetSource::getTotalBytes() {
	return this->totalBytes;
}

const uint32_t& TargetSource::getTotalBytes() const {
	return this->totalBytes;
}

uint32_t& TargetSource::getTotalReads() {
	return this->totalReads;
}

const uint32_t& TargetSource::getTotalReads() const {
	return this->totalReads;
}

/****************************** TARGET  SOURCE ******************************/

/******************************* TARGET  FILE *******************************/

TargetFile::TargetFile() : TargetFile("") {

}

TargetFile::TargetFile(const std::string &name) {
	this->fileName = name;
}

std::string TargetFile::toString() const {
	return this->fileName;
}

TargetFile::operator bool() const {
	return !this->fileName.empty();
}

bool TargetFile::operator==(const Target &rhs) const {
	if (Target::operator!=(rhs)) return false;

	auto rhsTF = static_cast<const TargetFile&>(rhs);
	return this->fileName == rhsTF.fileName;
}

bool TargetFile::operator!=(const Target &rhs) const {
	return !(this->operator==(rhs));
}

/******************************* TARGET  FILE *******************************/

/****************************** TARGET NETWORK ******************************/

TargetNetwork::TargetNetwork() : TargetNetwork("", 0) {

}

TargetNetwork::TargetNetwork(const std::string &ip, const unsigned int &port) {
	this->ip = ip;
	this->port = port;
}

std::string TargetNetwork::toString() const {
	return (this->ip + "::" + std::to_string(this->port));
}

TargetNetwork::operator bool() const {
	return !this->ip.empty();
}

bool TargetNetwork::operator==(const Target &rhs) const {
	if (Target::operator!=(rhs)) return false;

	auto rhsTN = static_cast<const TargetNetwork&>(rhs);
	return this->ip == rhsTN.ip && this->port == rhsTN.port;
}

bool TargetNetwork::operator!=(const Target &rhs) const {
	return !(this->operator==(rhs));
}

/****************************** TARGET NETWORK ******************************/
