#include "dependency_network_def.h"

#include <iostream>
#include <linux/net.h>

void cbf_socketCallEnter(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args) {
	std::cout << "dependency_network: socket_call_enter called at " <<
		rr_get_guest_instr_count() << ", call type: " << call << "." << 
		std::endl;
}

void cbf_socketCallReturn(CPUState *cpu, target_ulong pc, int32_t call,
		uint32_t args) {
	std::cout << "dependency_network: socket_call_return called at " <<
		rr_get_guest_instr_count() << ", call type: " << call << "." << 
		std::endl;
		
	if (call == SYS_CONNECT) onSocketConnect(cpu, args);
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
	
	// Get the first and third arguments
	int sockfd = arguments[0];
	socklen_t addrLen = arguments[2]; 
	
	// Get the sockaddr structure from the arguments. The virtual memory 
	// address to the sockaddr structure is stored in the second argument of
	// the args passed to connect(). Use that address to get the pointer to the
	// sockaddr structure itself.
	auto sockaddrAddress = arguments[1];
	sockaddr addr = getMemoryValues<sockaddr>(cpu, sockaddrAddress, 1)[0];
	
	// Stores the IP address found
	char ipAddress[INET6_ADDRSTRLEN] = {0};

	std::cout << "dependency_network: sock_fd: " << sockfd << std::endl;
	std::cout << "dependency_network: addrLen: " << addrLen << std::endl;
	
	if (addr.sa_family == AF_INET) {
		sockaddr_in *sin4 = reinterpret_cast<sockaddr_in*>(&addr);
		inet_ntop(AF_INET, &sin4->sin_addr, ipAddress, INET6_ADDRSTRLEN);
		
		std::cout << "dependency_network: socket connect called with IPv4 " <<
			"socket address. IP: " << std::string(ipAddress) << 
			", port: " << sin4->sin_port << "." << std::endl;
	} else if (addr.sa_family == AF_INET6) {
		sockaddr_in6 *sin6 = reinterpret_cast<sockaddr_in6*>(&addr);
		inet_ntop(AF_INET6, &sin6->sin6_addr, ipAddress, INET6_ADDRSTRLEN);
		
		std::cout << "dependency_network: socket connect called with IPv6 " <<
			"socket address. IP: " << std::string(ipAddress) << 
			", port: " << sin6->sin6_port << "." << std::endl;
	} else {
		std::cerr << "dependency_network: sockaddr fetched but is of an " <<
			"unknown family." << std::endl;
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
	
	// Register SysCalls2 Callback Functions
	PPP_REG_CB("syscalls2", on_sys_socketcall_enter, cbf_socketCallEnter);
	PPP_REG_CB("syscalls2", on_sys_socketcall_return, cbf_socketCallReturn);
	
	return true;
#else
	std::cout << "dependency_network is only supported for i386 targets." << 
		std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
	printf("Goodbye World from Dependency_Network Plugin.");
}
