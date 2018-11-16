#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>
#include <stdint.h>

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

	Variable *merge_var; //If one variable merge with another, this pointer point to the other variable
};

/**
	Instruction struct:
		Definition of an instruction (based on the JSON).
*/
struct Instruction {
	std::string op;
	uint64_t pos;
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
 	 	 Definition of how the values are stored on the memory
 */
struct MemoryStack{
	std::map<uint64_t, Variable> var;
	std::map<uint64_t, int64_t> const_value;
};

#endif /* STRUCTDEFINITION_H_ */
