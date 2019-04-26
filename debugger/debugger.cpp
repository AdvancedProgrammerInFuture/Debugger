#include<unistd.h> 
#include<string>
#include<stdio.h>
#include<sys/types.h>
#include<vector>
#include<cstdint> 
#include<iostream> 
#include<array>
#include<algorithm> 	

/*====================== ALL function prototypes ====================================*/

std::vector<std::string> split(const std::string& s, char delimiter);
bool is_prefix(const std::string& s, const std::string& of);
uint64_t get_register_value(pid_t pid, reg r);
void set_register_value(pid_t pid, reg r, uint64_t value);
uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum);

/*====================== main abstract and user-defined data types =========================*/

class breakpoint {
public: 
	breakpoint(pid_t pid, std::intptr_t addr)
		: m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} 
	{}
	
	void enable();
	void disable();

	auto is_enabled() const -> bool { return m_enabled; } 
	auto get_address() const -> std::intptr_t { return m_addr; }

private: 
	pid_t m_pid;
	std::intptr_t m_addr;
	bool m_enabled;
	uint8_t m_saved_data; // data which used at the breakpoint address 	
};


	
class debugger {
public:
    debugger(std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

	void run();
	void set_breakpoint_at_address(std::intptr_t addr);
	
private:
	std::string m_prog_name;
	pid_t m_pid;
	std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;	
};




enum class reg { 
	rax, rbx, rcx, rdx,
	rdi, rsi, rbp, rsp, 
	r8,  r9,  r10, r11,
	r12, r13, r14, r15,
	rip, rflags,   cs,
	gs_base, 
	fs, gs, ss, ds, es
};

struct reg_descriptor {
	reg r;
	int dwarf_r;
	std::string name;
};

constexpr std::size_t n_registers = 27; 



const std::array<reg_descriptor, n_registers> g_registor_descriptors {{
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



/*=============================== MAIN function ======================================*/
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
         ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
  	 execl(prog, prog, nullptr);

    }
    else if (pid >= 1)  {
  	  //parent
   	debugger dbg{prog, pid};
    	dbg.run();
    }
}
/*=============================== BREAKPOINT member functions ======================================*/

void breakpoint::enable() { 
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
	m_saved_data = static_cast<uint8_t>(data & 0xff) // save bottom byte
	uint64_t int3 = 0xcc;
	uint64_t data_with_int3 = ((data & ~0xff) | int3);
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

	m_enabled = true;
}

void breakpoint::disable() {
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
	auto restored_data = ((data & ~0xff) | m_saved_data);
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

	m_enabled = false;
}

/*================================= DEBUGGER member functions =====================================*/

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl; 
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp; 
}


void debugger::run() {	
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);
	
	char* line = nullptr;
	while((line = linenoise("minidbg> " )) != nullptr) { // linenoise listen user input 
		handle_command(line); // when get a user input 
		linenoiseHistoryAdd(line);
		linenoiseFree(line);
	}
}

void debugger::handle_command(const std::string& line) {
	auto args = split(line, ' ');
	auto command = args[0];
	
	if(is_prefix(command, "cont")) {
		continue_execution();
	}
	else if(is_prefix(command, "break") {
		std::string addr {args[1], 2};
		set_breakpoint_at_address(std::stol(addr, 0, 16);
	} 
	else {
		std::cerr << "Unknown command line \n";
	}
}

void debugger::continue_execution() { 
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);
}

/*=============================== other functions ======================================*/

std::vector<std::string> split(const std::string& s, char delimiter) {
	std::vector<std::string> out{};
	std::streangstream ss{s};
	std::string item; 

	while(std::getline(ss,item,delimiter) {
		out.push_back(item);
	}

	return out;
}

bool is_prefix(const std::string& s, const std::string& of) { 
	if (s.size() > of.size()) return false; 
	return std::equal(s.begin(), s.end(), of.begin());
}

uint64_t get_register_value(pid_t pid, reg r) {
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
	auto it = std::find_if(begin(g_registor_descriptors), end(g_regsitor_descriptors), [r](auto&& rd) { return rd.r = r; }); 
	
	return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_registor_descriptors)));

}

void set_register_value(pid_t pid, reg r, uint64_t value) {
	user_regs_struct regs; 
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) { rd.r == r; });
	
	*(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value;
	ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

}

uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_registor_descriptors), [regnum](auto&& rd)

