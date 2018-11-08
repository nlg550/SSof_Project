#ifndef FUNCTION_H_
#define FUNCTION_H_

#include <vector>
#include <string>

#include "StructDefinition.hpp"

#define N_DANGEROUS_FUNC 11

class Function {
private:
	//All the dangerous functions to be consider
	static const std::string dangerous_functions[N_DANGEROUS_FUNC];

	//All the vulnerabilities found
	static std::vector<Vulnerability> vulnerabilities;

	//Registers and Memory Stack (Shared between function)
	static MemoryStack stack;
	static Registers regs;

	//Unique Attributes
	std::string name;
	unsigned int n_inst;
	unsigned int currentInst;
	std::vector<Attribute> attributes;
	std::vector<Instruction> instructions;

public:
	Function(std::string f_name, unsigned int n);
	virtual ~Function();
	void addAttribute(Attribute att);
	void addInstruction(Instruction inst);
	bool compareFunctionName (std::string cmp_name);
	std::string execute(); 	//Execute the function. If the instruction "call" is found during the execution,
							//return the name of the function called. Otherwise, returns NULL

};

#endif /* FUNCTION_H_ */
