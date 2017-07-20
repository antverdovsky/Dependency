#include "dependency_network_def.h"

#include <iostream>
#include <stdexcept>
#include <linux/net.h>

bool Dependency_Network_Target::operator==(
		const Dependency_Network_Target &rhs) {
	return (this->ip == rhs.ip) && (this->port == rhs.port);
}

bool Dependency_Network_Target::operator!=(
		const Dependency_Network_Target &rhs) {
	return (this->ip != rhs.ip) || (this->port != rhs.port);
}

void cbf_socketCallEnter(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args) {
	
}

void cbf_socketCallReturn(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args) {
	if (dependency_network.debug) {
		std::cout << "dependency_network: socket_call triggered at " << 
			"instruction " << rr_get_guest_instr_count() << ", call type: " <<
			call << std::endl;
	}
			
	if (call == SYS_CONNECT) onSocketConnect(cpu, args);
}

void cbf_pread64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	Dependency_Network_Target target;
	try {
		target = targets.at(std::make_pair(panda_current_asid(cpu), fd));
	} catch (const std::out_of_range &e) {
		std::cerr << "dependency_network: pread64_return called, but file"
			<< "descriptor " << fd << " is unknown." << std::endl;
		return;
	}
	
	if (target == dependency_network.source) {
		std::cout << "dependency_network: ***saw read return of source " << 
			"target***" << std::endl;
		sawReadOfSource = true;
	} else {
		if (dependency_network.debug) {
			std::cout << "dependency_network: saw read of file/socket with " <<
				"fd: " << fd << std::endl;
		}
	}
}

void cbf_pwrite64Return(CPUState *cpu, target_ulong pc, uint32_t fd,
		uint32_t buffer, uint32_t count, uint64_t pos) {
	Dependency_Network_Target target;
	try {
		target = targets.at(std::make_pair(panda_current_asid(cpu), fd));
	} catch (const std::out_of_range &e) {
		std::cerr << "dependency_network: pwrite64_return called, but file" <<
			" descriptor " << fd << " is unknown." << std::endl;
		return;
	}
	
	if (target == dependency_network.sink) {
		std::cout << "dependency_network: ***saw write return of sink " << 
			"target***" << std::endl; 
		sawWriteOfSink = true;
	} else {
		if (dependency_network.debug) {
			std::cout << "dependency_network: saw write of file/socket with " <<
				"fd: " << fd << std::endl;
		}
	}
}

void cbf_readReturn(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	cbf_pread64Return(cpu, pc, fd, buffer, count, 0);
}

void cbf_writeReturn(CPUState *cpu, target_ulong pc, uint32_t fd, 
		uint32_t buffer, uint32_t count) {
	cbf_pwrite64Return(cpu, pc, fd, buffer, count, 0);
}

template<typename T>
std::vector<T> getMemoryValues(CPUState *cpu, uint32_t addr, uint32_t size) {
	std::vector<T> arguments;
	
	// An array of raw memory bytes. Since we want to fetch T elements from
	// memory and we need enough bytes to store a single instance of T, so the 
	// array's size is equivalent to the size of a single T.
	uint8_t raw[sizeof(T)];
	
	for (auto i = 0; i < size; ++i) {
		// For each argument, read the bytes from memory and store them into
		// the raw memory array. Cast the raw memory to T and store in the 
		// arguments list.
		panda_virtual_memory_rw(cpu, addr + i * sizeof(T), raw, sizeof(T), 0);
		T argument = *(reinterpret_cast<T*>(raw));
		arguments.push_back(argument);
	}
	
	return arguments;
}

void onSocketConnect(CPUState *cpu, uint32_t args) {
	std::cout << "dependency_network: socket_connect called at " <<
		rr_get_guest_instr_count() << "." << std::endl;
	
	// Get the arguments from the args virtual memory
	auto arguments = getMemoryValues<uint32_t>(cpu, args, 3);

	// Get the sockaddr structure from the arguments. The virtual memory 
	// address to the sockaddr structure is stored in the second argument of
	// the args passed to connect(). Use that address to get the pointer to the
	// sockaddr structure itself.
	auto sockaddrAddress = arguments[1];
	sockaddr addr = getMemoryValues<sockaddr>(cpu, sockaddrAddress, 1)[0];
	
	// Stores the IP address found and the port number
	char ipAddress[INET6_ADDRSTRLEN] = {0};
	unsigned short port = 0;
	
	if (addr.sa_family == AF_INET) {
		sockaddr_in *sin4 = reinterpret_cast<sockaddr_in*>(&addr);
		
		inet_ntop(AF_INET, &sin4->sin_addr, ipAddress, INET6_ADDRSTRLEN);
		port = sin4->sin_port;
		
	} else if (addr.sa_family == AF_INET6) {
		sockaddr_in6 *sin6 = reinterpret_cast<sockaddr_in6*>(&addr);
		
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipAddress, INET6_ADDRSTRLEN);
		port = sin6->sin6_port;
	} else {
		std::cerr << "dependency_network: sockaddr fetched but is of an " <<
			"unknown family." << std::endl;
		return;
	}
	
	// Convert IP address & port to Dependency_Network_Target. Add the Target
	// to the targets map.
	int sockfd = arguments[0];
	Dependency_Network_Target target = { std::string(ipAddress), port };
	targets[std::make_pair(panda_current_asid(cpu), sockfd)] = target;
	
	// Print IP address and port
	if (dependency_network.debug) {
		std::cout << "dependency_network: connect called for target IP: " << 
			target.ip << ", and target port: " << target.port << std::endl;
	}
}

bool init_plugin(void *self) {
#ifdef TARGET_I386
	dependency_network.plugin_ptr = self;
	
	/// Load dependent plugins
	panda_require("osi");
	assert(init_osi_api());
	
	panda_require("osi_linux");
	assert(init_osi_linux_api());
	
	panda_require("syscalls2");
	
	/// Parse Arguments:
	/// "source_ip"   : The source IP address, defaults to "0.0.0.0"
	/// "source_port" : The source port, defaults to "9999"
	/// "sink_ip"     : The sink IP address, defaults to "0.0.0.0"
	/// "sink_port"   : The sink port, defaults to "9999"
	/// "debug"       : Should debug mode be used? Defaults to false
	auto args = panda_get_args("dependency_network");
	dependency_network.source.ip = panda_parse_string_opt(args, 
		"source_ip", "0.0.0.0", "source ip address");
	dependency_network.source.port = (unsigned short)panda_parse_uint32_opt(
		args, "source_port", 9999, "source port number");
	dependency_network.sink.ip = panda_parse_string_opt(args, 
		"sink_ip", "0.0.0.0", "sink ip address");
	dependency_network.sink.port = (unsigned short)panda_parse_uint32_opt(
		args, "sink_port", 9999, "sink port number");
	dependency_network.debug = panda_parse_bool_opt(args, 
		"debug", "debug mode");
	std::cout << "dependency_network: source IP: " << 
		dependency_network.source.ip << std::endl;
	std::cout << "dependency_network: source port: " << 
		dependency_network.source.port << std::endl;
	std::cout << "dependency_network: sink IP: " << 
		dependency_network.sink.ip << std::endl;
	std::cout << "dependency_network: sink port: " << 
		dependency_network.sink.port << std::endl;
	std::cout << "dependency_network: debug: " << 
		dependency_network.debug << std::endl;
	
	// Register SysCalls2 Callback Functions
	PPP_REG_CB("syscalls2", on_sys_socketcall_enter, cbf_socketCallEnter);
	PPP_REG_CB("syscalls2", on_sys_socketcall_return, cbf_socketCallReturn);
	PPP_REG_CB("syscalls2", on_sys_pread64_return, cbf_pread64Return);
	PPP_REG_CB("syscalls2", on_sys_pwrite64_return, cbf_pwrite64Return);
	PPP_REG_CB("syscalls2", on_sys_read_return, cbf_readReturn);
	PPP_REG_CB("syscalls2", on_sys_write_return, cbf_writeReturn);
	
	return true;
#else
	std::cout << "dependency_network is only supported for i386 targets." << 
		std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
	std::cout << "dependency_network: saw read of source? " << 
		sawReadOfSource << std::endl;
	std::cout << "dependency_network: saw write of sink? " << 
		sawWriteOfSink << std::endl;
}
