#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>

//Definition of a variable (base on the JSON)
struct Variable {
	std::string name;
	std::string type;
	unsigned int bytes;
	unsigned int address;
};

//Definition of an instruction (based on the JSON)
struct Instruction {
	std::string op;
	unsigned int pos;
	unsigned int address;
	std::map<std::string, std::string> args;
};

//The stack can hold both an address and an variable. Because of that, the stack
//will be divided into 2 maps (<address in the memory>, <value stored>)
struct MemoryStack {
	std::map<unsigned int, Variable> value_variable;
	std::map<unsigned int, unsigned long int> value_address;
};

//Like the stack, the registers can hold both an Variable and an address. So, the
//registers will be also divided in 2 maps (<name of register>, <value stored>)
struct Registers {
	std::map<std::string, Variable> regVariable;
	std::map<std::string, unsigned int> regAddress;
};

//Definition of a vulnerability (based on the JSON)
struct Vulnerability {
	std::string type;
	std::string overflow_var;
	std::string address;
	std::string fnname;
	std::string vuln_function;

	//If doesn't have an overflow of a variable, overflown = NULL
	std::string overflown_var;
};

//Definition of a function (based on the JSON)
struct Function {
	unsigned int n_inst;
	unsigned int currentInst;
	std::vector<Variable> variables;
	std::vector<Instruction> instructions;
};

#endif /* STRUCTDEFINITION_H_ */
