/*
 * Registers.cpp
 *
 *  Created on: 10 Nov 2018
 *      Author: Nicolas
 */

#include "Registers.hpp"

Registers::Registers()
{
	reg_var.clear();
	reg_addr.clear();

	reg_addr.emplace("rip", 0);
	reg_addr.emplace("rsp", 0xFFFFFFFF);
	reg_addr.emplace("rbp", 0xFFFFFFFF);
}

Registers::~Registers()
{
	reg_var.clear();
	reg_addr.clear();
}

Variable Registers::getVarRegister(std::string name)
{
	return reg_var[name];
}

unsigned int Registers::getAddrRegister(std::string name)
{
	return reg_addr[name];
}

void Registers::addRegister(Variable var, std::string name)
{
	if(reg_var.find(name) != reg_var.end())
	{
		reg_var[name] = var;

	}else if(reg_addr.find(name) != reg_addr.end())
	{
		reg_addr.erase(name);
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
		reg_addr.emplace(name, addr);

	}else if(reg_addr.find(name) != reg_addr.end())
	{
		reg_addr[name] = addr;

	}else
	{
		reg_addr.emplace(name, addr);
	}
}
