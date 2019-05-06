#include <unistd.h> 
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h> 
#include <vector>
#include <cstdint> 
#include <iostream> 
#include <sys/ptrace.h>
#include "linenoise.h"
#include <string>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <sys/user.h>
#include <stdexcept> 

/*====================== main abstract and user-defined data types =========================*/
/*
	Will use only software breakpoints , by means int 3 that cause give access to breakpoint interrupt handler that in kernel OS (user-kernel switch protection mode) 
	this interrupt handler return SIGTRAP: set the breakpoint, continue the program, call waipid until SIGTRAP occurs 
*/
		
/* registers in x86_64 architecture */

enum class reg { 
	rax/* temp reg */ , rbx	/* callee-saved reg */, rcx /* 4 th pass int arg for fucnc */, rdx, 
	rdi, rsi, rbp, rsp,
    	r8,  r9,  r10, r11, // https://www.uclibc.org/docs/psABI-x86_64.pdf for register's information 
    	r12, r13, r14, r15,
    	rip, rflags,    cs,
    	orig_rax, fs_base,
    	gs_base,
    	fs, gs, ss, ds, es
};

struct reg_descriptor { 
	reg r; 
	int dwarf_r; 
	std::string name; 
}; // as I understand any dwarf register is a usual register but with own dwarf number

constexpr std::size_t n_registers = 27; // size_t as unsigned int and constexpr indicate that is merely const 


const std::array<reg_descriptor, n_registers> g_register_descriptors {{ // for array needed double-brackets  
	{ reg::r15, 15, "r15" },
    	{ reg::r14, 14, "r14" },
    	{ reg::r13, 13, "r13" },
    	{ reg::r12, 12, "r12" },
    	{ reg::rbp, 6, "rbp" },
    	{ reg::rbx, 3, "rbx" },
    	{ reg::r11, 11, "r11" },
    	{ reg::r10, 10, "r10" },
    	{ reg::r9, 9, "r9" },
    	{ reg::r8, 8, "r8" },
    	{ reg::rax, 0, "rax" },
    	{ reg::rcx, 2, "rcx" },
    	{ reg::rdx, 1, "rdx" },
    	{ reg::rsi, 4, "rsi" },
    	{ reg::rdi, 5, "rdi" },
    	{ reg::orig_rax, -1, "orig_rax" },
    	{ reg::rip, -1, "rip" },
    	{ reg::cs, 51, "cs" },
    	{ reg::rflags, 49, "eflags" },
    	{ reg::rsp, 7, "rsp" },
    	{ reg::ss, 52, "ss" },
    	{ reg::fs_base, 58, "fs_base" },
   	{ reg::gs_base, 59, "gs_base" },
    	{ reg::ds, 53, "ds" },
    	{ reg::es, 50, "es" },
    	{ reg::fs, 54, "fs" },
    	{ reg::gs, 55, "gs" },
}};

/*====================== ALL function prototypes ====================================*/
std::vector<std::string> split(const std::string &s, char delimiter);
bool is_prefix(const std::string &s, const std::string &of);
uint64_t get_register_value(pid_t pid, reg r);
uint64_t set_register_value(pid_t pid, reg r, uint64_t value);
uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum);
reg get_register_from_name(const std::string& name);
/* ==================================================================================*/

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

	auto is_enabled() -> bool { return m_enabled; } // badly understand this construction, I think this as: bool is_enabled() { return is_enabled } 
	auto get_address() -> std::intptr_t { return m_addr; } // I think this is as: std::intptr_t get_address() { return m_addr }
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
	
	// auto& - always will be reference and not temporary (as copy) 
	void dump_registers() {
		/* loop iterates over g_register_descriptors and use begin(...), end(...) */
		for (const auto& rd /* const reference to the deduced type */ : g_registor_descriptors) {
			std::cout << rd.name << " 0x" << std::setfill('0') << std::hex << std::
	void set_breakpoint_at_adress(std::intptr_t addr) {
		std::cout << "Set breakpoint at adress 0x " << std::hex << addr << std::endl;
		
		breakpoint bp {m_pid, addr};
		bp.enable();
		m_breakpoints[addr] = bp; 
	}

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
			
		if (is_prefix(command, "cont")) {
			continue_execution();
		}
		else if(command, "break") {
			std::string addr {args[1], 2}; // args[1] as copying data in addr, and 2 - the first character that from that copying in the string going on ( because 0x is formal for user )		 
			set_breakpoint_at_adress(std::stol(addr, 0, 16)); // std::stol for remove whitespaces
		}
		else {
			std::cerr << "Unknown command\n";
		}
	}
private:
	std::string m_prog_name;
	pid_t m_pid;
	std::unordered_map<std::intptr_t, breakpoint> m_breakpoints; // structure for breakpoint storage with address(i.e. we have a trap and go to kernel from user-level process) 
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

/*a bunch of functions to interact with registers (read, write to them, retrieve value from DWARF register number(just as any register but through DWARF number, look up registers by name or dwarf_number)*/

uint64_t get_register_value(pid_t pid, reg r) {
	user_regs_struct regs; // user_regs_struct is the struct from user.h that hold all x86_64 registers 
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs); // with ptrace get all process's registers, g_regs_descriptor in the same order as user_regs_descriptor - special for search 
	
	/* auto&& means that any value regardless lvalue or rvalue preserve constness for them */
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
			[r /* capture copy of external r value */ ](auto&& rd /* will be reg from g_register descriptor */) { return rd.r == r; }); 
	
	return *(reinterpret_cast<uint64_t*>(&regs) /* pointer on first reg in computer system */ + (it /* adress on needed reg */ - begin(g_register_descriptors))); // get pointer on needed registor 
}

uint64_t set_register_value(pid_t pid, reg r, uint64_t value) {
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs); 
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
			[r](auto&& rd){ rd.r == r; });
	*(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value; 
	
	ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}


uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
			[regnum](auto&& rd) { return rd.dwarf_r == regnum; }); // it pointer on begin of reg struct
	if (it == end(g_register_descriptors)) {
		throw std::out_of_range("Unknown dwarf register"); // create processor exception 
	}
	
	return get_register_value(pid, it->reg);
}

std::string get_register_name(reg r) {
	auto it = std::find_if(begin(g_registor_descriptors), end(g_register_descriptors),
			[r](auto&& it) { return rd.r == r; });
	
	return it->name;
}

reg get_register_from_name(const std::string& name) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
			[name](auto&& rd){ return rd.name == name; });
	return it->r;
}


