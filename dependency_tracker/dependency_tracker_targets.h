#ifndef DEPENDENCY_TRACKER_TARGETS
#define DEPENDENCY_TRACKER_TARGETS

#include <ostream>
#include <map>
#include <memory>
#include <string>

/// <summary>
/// Structure which represents a trackable target.
/// </summary>
class Target {
public:
	/// <summary>
	/// Creates a new target.
	/// </summary>
	Target();

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "Base Target".
	/// </returns>
	virtual std::string toString() const;
	
	/// <summary>
	/// Compares the specified Target instance for equality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are equivalent, false otherwise.
	/// </returns>
	virtual bool operator==(const Target &rhs) const;

	/// <summary>
	/// Compares the specified Target instance for inequality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are inequivalent, false otherwise.
	/// </returns>
	virtual bool operator!=(const Target &rhs) const;
};

/// <summary>
/// Appends the toString() return value of the specified target, to the 
/// specified output stream and returns it.
/// </summary>
/// <param name="stream">
/// The stream to which the target's toString() contents are to be appended.
/// </param>
/// <param name="target">
/// The target whose string value is to be appended to the stream.
/// </param>
/// <returns>
/// The string stream after target has been appended to it.
/// </returns>
std::ostream& operator<<(std::ostream &stream, const Target &target);

/// <summary>
/// Class which represents a sink target.
/// </summary>
class TargetSink {
public:
	/// <summary>
	/// Constructs a Target Sink with the specified target. The index should
	/// be equivalent to the index of the Target in its sinks vector.
	/// </summary>
	/// <param name="target">
	/// The unique pointer to the target.
	/// </param>
	/// <param name="index">
	/// The index of this Target in the sinks vector.
	/// </param>
	TargetSink(std::unique_ptr<Target> target, const size_t &index);

	/// <summary>
	/// Copying of Target Source instances is forbidden.
	/// </summary>
	TargetSink(const TargetSink&) = delete;

	/// <summary>
	/// Returns a reference to the index of this target in the sinks vector.
	/// This is expected to never change since targets are not added nor
	/// removed after the plugin is initialized.
	/// </summary>
	const size_t& getIndex() const;

	/// <summary>
	/// Returns a reference to the map which maps the source target index to
	/// how many tainted bytes from said source were written to this sink
	/// target.
	/// </summary>
	/// <returns>
	/// A reference to the value.
	/// </returns>
	std::map<size_t, uint32_t>& getLabeledBytes();

	/// <summary>
	/// Gets a constant reference to the target attached to this sink.
	/// </summary>
	/// <returns>
	/// The constant reference to the target.
	/// </returns>
	const Target& getTarget() const;

	/// <summary>
	/// Assignment of Target Source instances is forbidden.
	/// </summary>
	TargetSink& operator=(const TargetSink&) = delete;
protected:
	std::unique_ptr<Target> target;            // Target attached to this sink
	size_t index;                              // Index of this in sources list

	std::map<size_t, uint32_t> labeledBytes;   // Map of source target index to
	                                           // tainted bytes of said source
	                                           // written to this.
};

/// <summary>
/// Class which represents a source target.
/// </summary>
class TargetSource {
public:
	/// <summary>
	/// Constructs a Target Source with the specified target. The index should
	/// be equivalent to the index of the Target in its sources vector.
	/// </summary>
	/// <param name="target">
	/// The unique pointer to the target.
	/// </param>
	/// <param name="index">
	/// The index of this Target in the sources vector.
	/// </param>
	TargetSource(std::unique_ptr<Target> target, const size_t &index);

	/// <summary>
	/// Copying of Target Source instances is forbidden.
	/// </summary>
	TargetSource(const TargetSource&) = delete;

	/// <summary>
	/// Returns a reference to the index of this target in the sources vector.
	/// This is expected to never change since targets are not added nor
	/// removed after the plugin is initialized.
	/// </summary>
	const size_t& getIndex() const;

	/// <summary>
	/// Returns a reference to the number of labeled bytes of this target.
	/// This should be set when any data of this source target is labeled.
	/// </summary>
	/// <returns>
	/// A reference to the value.
	/// </returns>
	uint32_t& getLabeledBytes();

	/// <summary>
	/// Gets a constant reference to the target attached to this sink.
	/// </summary>
	/// <returns>
	/// The constant reference to the target.
	/// </returns>
	const Target& getTarget() const;

	/// <summary>
	/// Assignment of Target Source instances is forbidden.
	/// </summary>
	TargetSource& operator=(const TargetSource&) = delete;
protected:
	std::unique_ptr<Target> target;        // The target attached to this src
	size_t index;                          // Index of this in sources vector

	uint32_t labeledBytes;                 // Number of tainted bytes of this
};

/// <summary>
/// Structure which represents a trackable file target.
/// </summary>
class TargetFile : public Target {
public:
	/// <summary>
	/// Creates a new trackable file target with the specified name.
	/// </summary>
	/// <param name="name">
	/// The directory and name of the file target.
	/// </param>
	TargetFile(const std::string &name);

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "File Target; File: \"$fileName$\"".
	/// </returns>
	virtual std::string toString() const override;
	
	/// <summary>
	/// Compares the specified Target instance for equality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are equivalent, false otherwise.
	/// </returns>
	virtual bool operator==(const Target &rhs) const override;

	/// <summary>
	/// Compares the specified Target instance for inequality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are inequivalent, false otherwise.
	/// </returns>
	virtual bool operator!=(const Target &rhs) const override;
protected:
	std::string fileName;                      // The File Name of the Target
};

/// <summary>
/// Structure which represents a trackable network target.
/// </summary>
class TargetNetwork : public Target {
public:
	/// <summary>
	/// Creates a new trackable network target with the specified name.
	/// </summary>
	/// <param name="ip">
	/// The IP address of the network target.
	/// </param>
	/// <param name="port">
	/// The port of the network target.
	/// </param>
	TargetNetwork(const std::string &ip, const unsigned int &port);

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "Network Target; IP: \"$ip$\", Port: $port$".
	/// </returns>
	virtual std::string toString() const override;

	/// <summary>
	/// Compares the specified Target instance for equality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are equivalent, false otherwise.
	/// </returns>
	virtual bool operator==(const Target &rhs) const override;

	/// <summary>
	/// Compares the specified Target instance for inequality to this.
	/// </summary>
	/// <param name="rhs">
	/// The right hand side of the operator to which this instance is to be
	/// compared to.
	/// </param>
	/// <returns>
	/// True if the instances are inequivalent, false otherwise.
	/// </returns>
	virtual bool operator!=(const Target &rhs) const override;
protected:
	std::string ip;                            // The IP Address of the Target
	unsigned short port;                       // The Port of the Target
};

#endif
