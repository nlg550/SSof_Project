#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>

/** 
	Variable struct:
		Definition of a variable (base on the JSON).
*/
struct Variable {
	std::string name;
	std::string type;
	unsigned int bytes; //the number of byte used
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
	bool is_var_overflown;
	std::string overflown_var;
};

struct MemoryStack{
	std::map<unsigned int, Variable> var;
	std::map<unsigned int, unsigned int> const_value;
};

#endif /* STRUCTDEFINITION_H_ */
