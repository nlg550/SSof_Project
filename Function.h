#ifndef FUNCTION_H_
#define FUNCTION_H_

#include <vector>
#include <string>

struct Attribute {
	std::string name;
	std::string type;
	unsigned int size; //the number of byte used
	unsigned int address;
};

struct Instruction {
	std::string op;
	unsigned int pos;
	unsigned int address;
	std::vector<std::string> args;
};


class Function {
private:
	std::vector<Attribute> attributes;
	std::vector<Instruction> instructions;

public:
	Function();
	virtual ~Function();
	Attribute getAttribute(unsigned int index);
	Instruction getInstruction(unsigned int index);
	void addAttribute(Attribute att);
	void addInstruction(Instruction inst);

};

#endif /* FUNCTION_H_ */
