#include "dependency_network_def.h"

#include <iostream>

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
