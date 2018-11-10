#include "Registers.hpp"

Registers::Registers()
{
	reg_var.clear();
	reg_const.clear();

	reg_const.emplace("rip", 0);
	reg_const.emplace("rsp", 0xFFFFFFFF);
	reg_const.emplace("rbp", 0xFFFFFFFF);
}

Registers::~Registers()
{
	reg_var.clear();
	reg_const.clear();
}

Variable Registers::getVarRegister(std::string name)
{
	return reg_var[name];
}

unsigned int Registers::getConstRegister(std::string name)
{
	return reg_const[name];
}

void Registers::addRegister(Variable *var, std::string name)
{
	if(reg_var.find(name) != reg_var.end())
	{
		reg_var[name] = var;

	}else if(reg_const.find(name) != reg_const.end())
	{
		reg_const.erase(name);
		reg_var.emplace(name, var);
	}else
	{
		reg_var.emplace(name, var);
	}
}

void Registers::addRegister(unsigned int addr, std::string name)
{
	if(reg_var.find(name) != reg_var.end())
	{
		reg_var.erase(name);
		reg_const.emplace(name, addr);

	}else if(reg_const.find(name) != reg_const.end())
	{
		reg_const[name] = addr;

	}else
	{
		reg_const.emplace(name, addr);
	}
}
