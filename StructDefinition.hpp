#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>

/**
	Variable struct:
		Definition of a variable (based on the JSON).
*/
struct Variable {
	std::string name;
	std::string type;
	unsigned int bytes;
	unsigned int effective_size; //The effective size of the variable
	std::string address;
};

/**
	Instruction struct:
		Definition of an instruction (based on the JSON).
*/
struct Instruction {
	std::string op;
	unsigned int pos;
	std::map<std::string, std::string> args;
	std::string address;
};

/**
	Function struct:
		Definition of an function (based on the JSON).
*/
struct Function{
	std::string name;
	unsigned int Ninstructions;
	std::vector<Variable> variables;
	std::vector<Instruction> instructions;

	unsigned int current_inst;
};

/**
	Vulnerability struct:
		Definition of a vulnerability (based on the JSON)
*/
struct Vulnerability {
	std::string type;
	std::string vuln_function;
	std::string fnname;
	std::string address;
	std::string overflow_var;
	std::tuple<bool, std::string> overflown_var;
	std::tuple<bool, std::string> overflown_addr;
};

/**
 	 Memory Stack struct:
 	 	 Definition how the values are stored on the memory
 */
struct MemoryStack{
	std::map<unsigned int, Variable> var;
	std::map<unsigned int, unsigned int> const_value;
};

#endif /* STRUCTDEFINITION_H_ */
