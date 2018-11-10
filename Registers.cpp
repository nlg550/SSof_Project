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

//Search if the register <name> exist, returning true and the value if the register was found
std::tuple<bool, Variable*> Registers::getVarRegister(std::string name)
{
	if(reg_var.find(name) != reg_var.end())
		{
			return std::make_tuple(true, reg_var[name]);
		}else
		{
			return std::make_tuple(false, nullptr);
		}
}

//Search if the register <name> exist, returning true and the value if the register was found
std::tuple<bool, unsigned int> Registers::getConstRegister(std::string name)
{
	if(reg_const.find(name) != reg_const.end())
	{
		return std::make_tuple(true, reg_const[name]);
	}else
	{
		return std::make_tuple(false, NULL);
	}
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

void Registers::addRegister(unsigned int const_value, std::string name)
{
	if(reg_var.find(name) != reg_var.end())
	{
		reg_var.erase(name);
		reg_const.emplace(name, const_value);

	}else if(reg_const.find(name) != reg_const.end())
	{
		reg_const[name] = const_value;

	}else
	{
		reg_const.emplace(name, const_value);
	}
}
