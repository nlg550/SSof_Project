#ifndef STRUCTDEFINITION_H_
#define STRUCTDEFINITION_H_
#include <string>
#include <vector>
#include <map>

//Definition of an attribute (base on the JSON)
struct Attribute {
	std::string name;
	std::string type;
	unsigned int size; //the number of byte used
	unsigned int address;
};

//Definition of an instruction (based on the JSON)
struct Instruction {
	std::string op;
	unsigned int pos;
	unsigned int address;
	std::vector<std::string> args;
};

//The stack can hold both an address and an attribute. Because of that, the stack
//will be divided into 2 maps (<address in the memory>, <value stored>)
struct MemoryStack {
	std::map<unsigned int, Attribute> value_attribute;
	std::map<unsigned int, unsigned long int> value_address;
};

//Like the stack, the registers can hold both an attribute and an address. So, the
//registers will be also divided in 2 maps (<name of register>, <value stored>)
struct Registers {
	std::map<std::string, Attribute> regAttribute;
	std::map<std::string, unsigned int> regAddress;
};

//Definition of a vulnerability (based on the JSON)
struct Vunerability{
	std::string type;
	std::string overflow_var;
	std::string address;
	std::string fnname;
	std::string vuln_function;

	//If doesn't have an overflow of a variable, overflown = NULL
	std::string overflown;
};

#endif /* STRUCTDEFINITION_H_ */
