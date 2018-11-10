#ifndef REGISTERS_HPP_
#define REGISTERS_HPP_

#include <map>
#include <string>
#include "StructDefinition.hpp"

class Registers {
private:
	std::map<std::string, Variable*> reg_var;
	std::map<std::string, unsigned int> reg_const;

public:
	Registers();
	virtual ~Registers();

	Variable getVarRegister(std::string name);
	unsigned int getConstRegister(std::string name);
	void addRegister(Variable *var, std::string name);
	void addRegister(unsigned int addr, std::string name);
};

#endif /* REGISTERS_HPP_ */
