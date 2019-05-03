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

