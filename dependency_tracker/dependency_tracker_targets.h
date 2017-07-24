#ifndef DEPENDENCY_TRACKER_TARGETS
#define DEPENDENCY_TRACKER_TARGETS

#include <ostream>
#include <string>

/// <summary>
/// Represents the type of target this is, either a source or a sink.
/// </summary>
enum TargetType {
	SINK   = 0,
	SOURCE = 1
};

/// <summary>
/// Structure which represents a trackable target.
/// </summary>
class Target {
public:
	/// <summary>
	/// Creates a new target of the specified type.
	/// </summary>
	/// <param name="type">
	/// The type of target (sink or source).
	/// </param>
	Target(const TargetType &type);

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "Base Target; Type: $type$".
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
protected:
	TargetType type;                       // The type of Target
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
	/// <param name="type">
	/// The type of the file target (sink or source).
	/// </param>
	TargetFile(const std::string &name, const TargetType &type);

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "File Target; File: \"$fileName$\", 
	/// Type: $type$".
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
	std::string fileName;                  // The File Name of the Target
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
	/// <param name="type">
	/// The type of the file target (sink or source).
	/// </param>
	TargetNetwork(const std::string &ip, const unsigned int &port, 
			const TargetType &type);

	/// <summary>
	/// Simple method which returns a string representation of this Target.
	/// </summary>
	/// <returns>
	/// The string in format: "Network Target; IP: \"$ip$\", Port: $port$, 
	/// Type: $type$".
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
	std::string ip;                        // The IP Address of the Target
	unsigned short port;                   // The Port of the Target
};

#endif
