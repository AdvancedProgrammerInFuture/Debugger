#include <unistd.h> 
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h> 
#include <vector>
#include <cstdint> 
#include <iostream> 
#include <array>
#include <algorithm> 	
#include <sys/ptrace.h>
#include "linenoise.h"
#include <string>
#include <sstream>

/*====================== ALL function prototypes ====================================*/
std::vector<std::string> split(const std::string &s, char delimiter);
bool is_prefix(const std::string &s, const std::string &of);

/*====================== main abstract and user-defined data types =========================*/

/*
	Will use only software breakpoints , by means int 3 that cause give access to breakpoint interrupt handler that in kernel OS (user-kernel switch protection mode) 
	this interrupt handler return SIGTRAP: set the breakpoint, continue the program, call waipid until SIGTRAP occurs 
*/

// all real magic happens in enable() and disable()
class breakpoint {
public: 
	breakpoint(pid_t pid, std::intptr_t addr) 
		: m_pid{pid}, m_addr(addr), m_enabled{false}, m_saved_data{} {}
	
	void enable() { 
		auto data = ptrace(PTRACE_PEEKDATA /* for return instruction from this location in process's address space */, m_pid, m_addr, nullptr);
		/* need to replace opcode for use the trap to interrupt breakpoint handler */ 
		m_saved_data = static_cast<uint8_t>(data & 0xff); // opcode   	
		uint64_t int3 = 0xcc; 
		uint64_t data_with_int3 = ((data & ~0xff) | int3); // replace opcode 
		
		ptrace(PTRACE_POKEDATA/* replace int in process address space */ , m_pid, m_addr, data_with_int3);
	
		m_enabled = true;
	}

	void disable() {
		auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
		auto restored_data = ((data & ~0xff) | m_saved_data);
	  	ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);
		
		m_enabled = false;
	} 

	auto is_enabled() -> bool { return m_enabled; } // badly understand this construction, I think this as bool is_enabled() { return is_enabled } 
	auto get_address() -> std::intptr_t { return m_addr; } // I think as std::intptr_t get_address() { return m_addr }
private: 
	pid_t m_pid;
	std::intptr_t m_addr; // intptr_t - can think as merely typedef of pointer
	bool m_enabled;
	uint8_t m_saved_data; 
};

class debugger {
public: 
	debugger (std::string prog_name, pid_t pid) 
		: m_prog_name{std::move(prog_name)}, m_pid{pid} {}

	void continue_execution() {
		ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
		
		int wait_status;
		auto options = 0;
		waitpid(m_pid, &wait_status, options);
	}

	void run() {
		int wait_status;
		int option = 0;
		waitpid(m_pid /* child id that wait */, &wait_status /* how terminate */, option /* no parameters */);
		
		char* line = nullptr;
		while((line = linenoise("minidbg> ")) != nullptr) {
			handle_command(line);
			linenoiseHistoryAdd(line);
			linenoiseFree(line);
		}
	}
	
	void handle_command(const std::string& line) {
		auto args = split(line, ' ');
		auto command = args[0]; 
			
		if (is_prefix(command, "continue")) {
			continue_execution();
		}
		else {
			std::cerr << "Unknown command\n";
		}
	}
private:
	std::string m_prog_name;
	pid_t m_pid;
};
/*=============================== MAIN function ======================================*/

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified"; // cerr for notify about error (no arguments)
        return -1;
    }

    auto prog = argv[1]; // initialize with command-line argument

    auto pid = fork(); // fork for split programm into 2-processes: if in child - 0, in parent - 1
	
    if (pid == 0) {	
	
         ptrace(PTRACE_TRACEME /* allow it parent to trace it */ , 0 /* process id */ , nullptr /* address */ , nullptr /* data */); 
  	 execl(prog, prog, nullptr); // launch programm 

    }
    else if (pid >= 1)  {
  	//parent
   	debugger dbg{prog, pid}; // debugger programm
    	dbg.run();
    }
}
/*=============================== other functions ======================================*/

std::vector<std::string> split(const std::string &s /* can be without & because const and pass by value or pass by reference doesn't matter */, char delimiter) { 
	std::vector<std::string> out{};
	std::stringstream ss{s};
	std::string item;
	
	while (std::getline(ss, item, delimiter)) {
		out.push_back(item);
	}
	
	return out;
}

bool is_prefix(const std::string &s, const std::string &of) {
	if (s.size() != of.size()) return false;
	return std::equal(s.begin(), s.end(), of.begin());
}

