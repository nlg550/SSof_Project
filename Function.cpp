#include "Function.h"

Function::Function()
{
	attributes.clear();
	instructions.clear();
}

Function::~Function()
{
	attributes.clear();
	instructions.clear();
}

Attribute Function::getAttribute(unsigned int index)
{
	return attributes[index];
}

Instruction Function::getInstruction(unsigned int index)
{
	return instructions[index];
}

void Function::addAttribute(Attribute att)
{
	attributes.emplace_back(att);
}

void Function::addInstruction(Instruction inst)
{
	instructions.emplace_back(inst);
}
