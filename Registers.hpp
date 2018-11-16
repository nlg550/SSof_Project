#ifndef REGISTERS_HPP_
#define REGISTERS_HPP_

#include <map>
#include <string>
#include <tuple>
#include <stdint.h>
#include "StructDefinition.hpp"

class Registers {
private:
	std::map<std::string, Variable*> reg_var;
	std::map<std::string, uint64_t> reg_const;

public:
	Registers();
	virtual ~Registers();

	std::tuple<bool, Variable*> getVarRegister(std::string name);
	std::tuple<bool, uint64_t> getConstRegister(std::string name);
	void addRegister(Variable *var, std::string name);
	void addRegister(uint64_t const_value, std::string name);
};

#endif /* REGISTERS_HPP_ */
