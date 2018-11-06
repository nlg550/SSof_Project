#include "Function.h"

//Initialisation of static class member
const std::string dangerous_functions[N_DANGEROUS_FUNC] = { "gets", "strcpy", "strcat", "sprintf",
		"scanf", "fscanf", "fgets", "strncpy", "strncat", "snprintf", "read" };
std::vector<Vunerability> vulnerabilities(0);
MemoryStack stack = []()
{
	MemoryStack *tmp = new MemoryStack;
	tmp->value_address.clear();
	tmp->value_attribute.clear();

	return *tmp;
}();

Registers regs = []()
{
	Registers *tmp = new Registers;
	tmp->regAddress.clear();
	tmp->regAttribute.clear();

	tmp->regAddress("RBP", 0xFFFFFFFF);

	return *tmp;
}();

Function::Function(std::string f_name, unsigned int n)
{
	attributes.resize(0);
	instructions.resize(0);
	name = f_name;
	n_inst = n;
	currentInst = 0;
}

Function::~Function()
{
	attributes.clear();
	instructions.clear();
}

void Function::addAttribute(Attribute att)
{
	attributes.emplace_back(att);
}

void Function::addInstruction(Instruction inst)
{
	instructions.emplace_back(inst);
}

bool Function::compareFunctionName(std::string cmp_name)
{
	if(name == cmp_name)
	{
		return true;
	}
	else
	{
		return false;
	}
}

std::string Function::execute()
{

}
