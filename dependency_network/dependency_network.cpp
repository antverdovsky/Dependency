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
		
	if (call == SYS_CONNECT) {
		std::cout << "dependency_network: saw connect call." << std::endl;
		auto arguments = getMemoryValues<uint32_t>(cpu, args, 3);
		for (auto i : arguments) {
			std::cout << i << std::endl;
		}
	}
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
