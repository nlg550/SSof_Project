#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>

//Definition of a variable (base on the JSON)
struct Variable {
	std::string name;
	std::string type;
	unsigned int bytes; //the number of byte used
	unsigned int address;
};

/*//Definition of an argument (base on the JSON)
struct Argument{
	std::string value;
	std::string dest;
	std::string obs;
	std::string fnname;
	unsigned int address;
};*/

//Definition of an instruction (based on the JSON)
struct Instruction {
	std::string op;
	unsigned int pos;
	std::map<std::string, std::string> args;
	std::string address;
};

//Definition of a function
struct Function{
	std::string name;
	unsigned int Ninstructions;
	Variable variables;
	Instruction instructions;

	unsigned int currentInst;
};

//Definition of a vulnerability (based on the JSON)
struct Vulnerability {
	std::string type;
	std::string vuln_function;
	std::string fnname;
	std::string address;
	std::string overflow_var;
	std::string overflown_var;  //If doesn't have an overflow of a variable, overflown = NULL
};

#endif /* STRUCTDEFINITION_H_ */
