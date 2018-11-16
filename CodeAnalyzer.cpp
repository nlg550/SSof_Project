#include "CodeAnalyzer.hpp"

const std::string CodeAnalyzer::vuln_functions[N_DANGEROUS_FUNC] = {"strcpy", "strcat", "sprintf",
		"fscanf", "fgets", "strncpy", "strncat", "snprintf", "read", "gets" , "scanf"};

/**
 Constructor of CodeAnalyzer Class
 */
CodeAnalyzer::CodeAnalyzer(const std::string filename)
{
	readJSON(filename);
	std::cout << "Read from JSON - OK" << std::endl;
	analyze();
	std::cout << "Analysis - OK" << std::endl;
	writeJSON(filename);
	std::cout << "Write to JSON - OK" << std::endl;
}

/**
 Destructor of CodeAnalyzer Class
 */
CodeAnalyzer::~CodeAnalyzer()
{
	vulnerabilities.clear();
	functions.clear();
}

/**
 readJSON Function:
 This function is responsible to read a JSON file
 */
void CodeAnalyzer::readJSON(const std::string filename)
{
	json input;
	std::ifstream input_file;
	input_file.open(filename);
	if (input_file.is_open())
	{
		input_file >> input;
	} else
	{
		std::cout << "Erro na abertura do arquivo" << std::endl;
	}
	jsonToStruct(input);
}

/**
 jsonToStruct Function:
 This function is responsible to transform a json variable in a struct variable
 */
void CodeAnalyzer::jsonToStruct(json input)
{
	for (json::iterator it = input.begin(); it != input.end(); ++it)
	{  //First iteration to select the function
		Function function_;
		function_.name = it.key();
		json js_ = *it;
		for (json::iterator it2 = js_.begin(); it2 != js_.end(); ++it2)
		{ // Iteration inside the function
			if (it2.key() == "Ninstructions")
			{
				function_.Ninstructions = it2.value();
			} else if (it2.key() == "variables")
			{
				json var_ = it2.value();
				std::vector<Variable> variables_;
				for (json::iterator it_Var = var_.begin(); it_Var != var_.end(); ++it_Var)
				{ // Iteration on function's variables
					Variable v_;
					json var_intern = it_Var.value();
					var_intern.at("name").get_to(v_.name);
					var_intern.at("type").get_to(v_.type);
					var_intern.at("bytes").get_to(v_.bytes);
					var_intern.at("address").get_to(v_.address);
					v_.effective_size = 0;
					v_.merge_var = nullptr;
					variables_.push_back(v_);
				}
				function_.variables = variables_;
			} else if (it2.key() == "instructions")
			{
				json ins_ = it2.value();
				std::vector<Instruction> instructions_;
				for (json::iterator it_Ins = ins_.begin(); it_Ins != ins_.end(); ++it_Ins)
				{ //Iteration on the function's instructions
					Instruction i_;
					std::map<std::string, std::string> args_map;
					json ins_intern = it_Ins.value();
					ins_intern.at("op").get_to(i_.op);
					ins_intern.at("pos").get_to(i_.pos);
					ins_intern.at("address").get_to(i_.address);
					for (json::iterator it_args = ins_intern.begin(); it_args != ins_intern.end(); ++it_args)
					{ //Iteration to select the instruction arguments
						json ins_args = it_args.value();
						if (it_args.key() == "args")
						{
							for (json::iterator it_args_inside = ins_args.begin(); it_args_inside != ins_args.end();
									++it_args_inside)
							{ //Iteration to move each argument to the map
								json ins_args_map = it_args_inside.value();
								std::string key = it_args_inside.key();
								std::string value = it_args_inside.value();
								args_map.insert(std::pair<std::string, std::string>(key, value));
							}
						}
						i_.args = args_map;
					}
					instructions_.push_back(i_);
				}
				function_.instructions = instructions_;
			} else
			{
				std::cout << "Error in converting the JSON to Function struct" << std::endl;
			}
		}

		function_.current_inst = 0;
		functions.insert(std::make_pair(function_.name, function_));
	}

}

/**
 writeJSON Function:
 This function is responsible to write in a JSON file the vulnerabilities found.
 */
void CodeAnalyzer::writeJSON(const std::string filename)
{
	json output = json::array();
	std::ofstream file;
	std::string file_write = filename;
	file_write.erase(file_write.length() - 5, file_write.length());
	file_write += ".output.json";
	file.open(file_write);

	for (auto &p : vulnerabilities)
		structToJson(output, p);

	file << output.dump(4) << std::endl;
	file.close();
}

/**
 structToJson Function:
 This function is responsible to transform a struct variabl in a JSON variable.
 */
void CodeAnalyzer::structToJson(json& output, const Vulnerability& vuln)
{
	if (std::get<0>(vuln.overflown_var) == true && vuln.type == "VAROVERFLOW")
	{
		output += json { { "vulnerability", vuln.type }, { "vuln_function", vuln.vuln_function }, { "fnname",
				vuln.fnname }, { "address", vuln.address }, { "overflow_var", vuln.overflow_var }, { "overflown_var",
				std::get<1>(vuln.overflown_var) } };
	} else if (std::get<0>(vuln.overflown_addr) == true && (vuln.type == "INVALIDACC" || vuln.type == "SCORRUPTION"))
	{
		output += json { { "vulnerability", vuln.type }, { "vuln_function", vuln.vuln_function }, { "fnname",
				vuln.fnname }, { "address", vuln.address }, { "overflow_var", vuln.overflow_var }, { "overflown_addr",
				std::get<1>(vuln.overflown_addr) } };
	} else
	{
		output += json { { "vulnerability", vuln.type }, { "vuln_function", vuln.vuln_function }, { "fnname",
				vuln.fnname }, { "address", vuln.address }, { "overflow_var", vuln.overflow_var } };
	}
}

// Allocate the memory stack and the register for the function <func>
void CodeAnalyzer::allocFunction(Function& func, uint64_t return_addr)
{
	uint64_t sp = std::get<1>(reg.getConstRegister("rsp"));

	mem_stack.const_value.emplace(sp - 8, return_addr); //Insert the return address on the stack
	mem_stack.const_value.emplace(sp - 16, std::get<1>(reg.getConstRegister("rbp"))); //Insert the base pointer address in the stack
	reg.addRegister(sp - 8, "rsp"); //Update the stack pointer
	reg.addRegister(sp - 16, "rbp"); //Update the base pointer
	reg.addRegister(std::stoull(func.instructions[0].address, nullptr, 16), "rsi"); //Change the register rsi to the address of the new function

	for (auto &p : func.variables)
	{
		std::string reg_name = p.address.substr(0, 3);
		int64_t relative_pos = std::stoull(p.address.substr(3, p.address.length()), nullptr, 16);
		mem_stack.var.emplace(std::get<1>(reg.getConstRegister(reg_name)) + relative_pos, p);
	}
}

// Desallocate the memory used by the function, and restore the values of registers rbp, rsp and rsi
void CodeAnalyzer::desallocFunction(Function& func)
{
	unsigned int ebp = std::get<1>(reg.getConstRegister("rbp"));

	reg.addRegister(ebp + 16, "rsp");
	reg.addRegister(mem_stack.const_value[ebp], "rbp");
	reg.addRegister(mem_stack.const_value[ebp + 8], "rsi");

	mem_stack.const_value.erase(mem_stack.const_value.begin(), mem_stack.const_value.upper_bound(ebp - 8));
	mem_stack.var.erase(mem_stack.var.begin(), mem_stack.var.upper_bound(ebp - 8));
}

// Analyze the overflow, and what information is overflown
void CodeAnalyzer::analyzeOverflow(Function* func, std::string func_name, Variable* arg, int overflow)
{
	if (overflow <= 0) return; //if there isn't any overflow, return

	Vulnerability vuln;
	vuln.address = func->instructions[func->current_inst].address;
	vuln.fnname = func_name;
	vuln.overflow_var = arg->name;
	vuln.vuln_function = func->name;

	auto base_arg = arg->address.substr(0, 3);
	int64_t pos_arg = std::stoull(arg->address.substr(3, arg->address.length()), nullptr, 16); //Relative position of the arg
	auto addr = std::get<1>(reg.getConstRegister(base_arg)) + pos_arg;
	auto size = arg->bytes;
	auto it = mem_stack.var.upper_bound(addr);
	auto rbp = std::get<1>(reg.getConstRegister("rbp"));

	while (it != mem_stack.var.end() && it->first < rbp)
	{
		vuln.overflown_addr = std::make_tuple(false, "");
		vuln.overflown_var = std::make_tuple(false, "");

		int mem_space = it->first - addr - size;

		if (mem_space > 0)
		{
			//Invalid Access
			vuln.type = "INVALIDACC";
			vuln.overflown_addr = std::make_tuple(true, [](int pos)
			{
				std::stringstream ss;
				if (pos < 0) ss << "rbp-" << std::hex << std::showbase << std::abs(pos);
				else ss <<"rbp+" << std::hex << std::showbase << pos;
				return ss.str();
			}(addr - std::get<1>(reg.getConstRegister("rbp")) + size));

			vulnerabilities.emplace_back(vuln);
		}

		if (overflow > mem_space)
		{
			//Overflow of local variable
			vuln.type = "VAROVERFLOW";
			vuln.overflown_var = std::make_tuple(true, it->second.name);
			vulnerabilities.emplace_back(vuln);
			overflow -= (it->second.bytes + mem_space); //Subract from the overflow the number of bytes used by the variable
														//(including the empty space)

		} else
		{
			return;
		}

		addr = it->first;
		size = it->second.bytes;
		it = mem_stack.var.upper_bound(it->first);
	}

	vuln.overflown_var = std::make_tuple(false, "");
	vuln.overflown_addr = std::make_tuple(false, "");

	if (overflow > 0)
	{
		//Overflow of the rbp
		vuln.type = "RBPOVERFLOW";
		vulnerabilities.emplace_back(vuln);
		overflow -= 8;
	}

	if (overflow > 0)
	{
		//Overflow of the return address
		vuln.type = "RETOVERFLOW";
		vulnerabilities.emplace_back(vuln);
		overflow -= 8;
	}

	if (overflow > 0)
	{
		vuln.type = "SCORRUPTION";
		vuln.overflown_addr = std::make_tuple(true, "rbp+0x10");
		vulnerabilities.emplace_back(vuln);
	}
}

//Verify if the dangerous functions is actually vulnerable
void CodeAnalyzer::analyzeVulnFunction(Function *func, std::string func_name)
{

	if (func_name.find("fgets") != std::string::npos) //fgets(buf1, num)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));  //buf1
		auto arg2 = std::get<1>(reg.getConstRegister("rsi")); //num

		arg1->merge_var = nullptr; //Because of the /0 termination, the variables are not longer concatenated

		arg1->effective_size = arg2;
		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	}else 	if (func_name.find("gets") != std::string::npos) //gets(buf1)
	{
		auto arg = std::get<1>(reg.getVarRegister("rdi")); //buf1

		analyzeOverflow(func, func_name, arg, 100000);

	}

	else if (func_name.find("strcpy") != std::string::npos) //strcpy(buf1, buf2)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //buf1
		auto arg2 = std::get<1>(reg.getVarRegister("rsi")); //buf2

		arg1->merge_var = nullptr;

		//If <arg2> are merge with another variable, update the effective size of the <arg2>
		if (arg2->merge_var != nullptr && arg2->effective_size != arg2->bytes + arg2->merge_var->effective_size)
		{
			arg2->effective_size = arg2->bytes + arg2->merge_var->effective_size;
		}

		arg1->effective_size = arg2->effective_size;
		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	} else if (func_name.find("strcat") != std::string::npos) //strcat(buf1, buf2)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //buf1
		auto arg2 = std::get<1>(reg.getVarRegister("rsi")); //buf2

		arg1->merge_var = nullptr;

		if (arg2->merge_var != nullptr && arg2->effective_size != arg2->bytes + arg2->merge_var->effective_size)
		{
			arg2->effective_size = arg2->bytes + arg2->merge_var->effective_size;
		}

		arg1->effective_size += arg2->effective_size;
		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	} else if (func_name.find("strncpy") != std::string::npos) //strncpy(buf1, buf2, num)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //buf1
		auto arg2 = std::get<1>(reg.getVarRegister("rsi")); //buf2
		auto arg3 = std::get<1>(reg.getConstRegister("rdx")); //num

		if (arg2->merge_var != nullptr && arg2->effective_size != arg2->bytes + arg2->merge_var->effective_size)
		{
			arg2->effective_size = arg2->bytes + arg2->merge_var->effective_size;
		}

		if (arg2->effective_size > arg3) //If the buf2 is bigger than num, the /0 is not included!
		{
			auto base = arg1->address.substr(0, 3);
			int64_t relative_pos = std::stoull(arg1->address.substr(3, arg1->address.length()), nullptr, 16);
			auto addr = std::get<1>(reg.getConstRegister(base)) + relative_pos;
			auto it = mem_stack.var.upper_bound(addr);

			if (it->first == addr + arg3) //If there is another variable in the adjacent position, the buf1 is concatenated
			{							  //with the adjacent variable
				arg1->effective_size = arg3 + it->second.effective_size;
				arg1->merge_var = &it->second;

			} else
			{
				arg1->effective_size = arg3;
			}

		} else
		{
			arg1->effective_size = arg3;
		}

		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	} else if (func_name.find("strncat") != std::string::npos) //strncat(buf1, buf2, num)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //buf1
		auto arg2 = std::get<1>(reg.getVarRegister("rsi")); //buf2
		auto arg3 = std::get<1>(reg.getConstRegister("rdx")); //num

		arg1->merge_var = nullptr;

		if (arg2->merge_var != nullptr && arg2->effective_size != arg2->bytes + arg2->merge_var->effective_size)
		{
			arg2->effective_size = arg2->bytes + arg2->merge_var->effective_size;
		}

		if (arg3 > arg2->effective_size)
		{
			arg1->effective_size += arg2->effective_size;

		} else
		{
			arg1->effective_size += arg3;
		}

		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	} else if (func_name.find("read") != std::string::npos) //read(FILE, buf1, num)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rsi"));
		auto arg2 = std::get<1>(reg.getConstRegister("rdx"));

		arg1->merge_var = nullptr;

		arg1->effective_size = arg2;
		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

	}  else if (func_name.find("fscanf") != std::string::npos) //fscanf(FILE, format, ...) -- Our simplified model consider only %s
	{								 //(only 1 buffer) or %s%s (2 buffers) as the format
		auto arg3_exist = std::get<0>(reg.getVarRegister("rdx")); //buf1 exist?
		auto arg4_exist = std::get<0>(reg.getVarRegister("rcx")); //buf2 exist?

		if (arg3_exist)
		{
			analyzeOverflow(func, func_name, std::get<1>(reg.getVarRegister("rdx")), 100000);
		}

		if (arg4_exist)
		{
			analyzeOverflow(func, func_name, std::get<1>(reg.getVarRegister("rcx")), 100000);
		}

	} else if (func_name.find("scanf") != std::string::npos) //scanf(format, ...) -- Our simplified model consider only %s
	{								 //(only 1 buffer) or %s%s (2 buffers) as the format
		auto arg2_exist = std::get<0>(reg.getVarRegister("rsi")); //buf1 exist?
		auto arg3_exist = std::get<0>(reg.getVarRegister("rdx")); //buf2 exist?

		if (arg2_exist)
		{
			analyzeOverflow(func, func_name, std::get<1>(reg.getVarRegister("rsi")), 100000);
		}

		if (arg3_exist)
		{
			analyzeOverflow(func, func_name, std::get<1>(reg.getVarRegister("rdx")), 100000);
		}

	}else if (func_name.find("sprintf") != std::string::npos) 	//sprintf(dest_buffer, format, ...) -- Our simplified model consider only %s
	{								 	//(only 1 buffer) or %s%s (2 buffers) as the format
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //destination
		auto arg3_exist = std::get<0>(reg.getVarRegister("rdx")); //buff1 exist?
		auto arg4_exist = std::get<0>(reg.getVarRegister("rcx")); //buff2 exist?

		if(arg3_exist && arg4_exist)
		{
			auto arg3 = std::get<1>(reg.getVarRegister("rdx"));
			auto arg4 = std::get<1>(reg.getVarRegister("rcx"));

			arg1->effective_size = arg3->effective_size + arg4->effective_size;
			analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);

		}else if(arg3_exist)
		{
			auto arg3 = std::get<1>(reg.getVarRegister("rdx"));

			arg1->effective_size = arg3->effective_size;
			analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);
		}

	}else if (func_name.find("snprintf") != std::string::npos) //snprintf(dest_buffer, num, format, ...)
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi")); //destination
		auto arg2 = std::get<1>(reg.getConstRegister("rsi")); //num

		arg1->effective_size = arg2;
		analyzeOverflow(func, func_name, arg1, arg1->effective_size - arg1->bytes);
	}
}

//Analyze the function defined by <func>
void CodeAnalyzer::analyzeFunction(Function *func, std::stack<Function*> &stack_func)
{
	Instruction current_inst;
	bool leave = false;

	while (func->current_inst < func->Ninstructions) //iterate through all instructions specified in <func>
	{
		current_inst = func->instructions[func->current_inst];

		if (!leave)
		{
			if (current_inst.op == "mov")
			{
				std::string dest = current_inst.args["dest"];
				std::string value = current_inst.args["value"];

				auto pos = dest.find("["); //the pointer is indicated by []

				if (pos != std::string::npos) //The destination is a pointer
				{
					dest = dest.substr(pos + 1, dest.length() - 2);
					std::string reg_name = dest.substr(0, 3);
					int64_t relative_pos = std::stoull(dest.substr(3, dest.length()), nullptr, 16);
					auto mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

					if (value[0] == '0' && value[1] == 'x') //mov [pointer], number
					{
						//Put the number on the memory stack
						if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
						{
							mem_stack.const_value[mem_pos] = std::stoull(value, nullptr, 16);

						} else
						{
							mem_stack.const_value.emplace(mem_pos, std::stoull(value, nullptr, 16));
						}
					} else //mov [pointer], reg
					{
						auto is_x86 = false;

						if (value[0] == 'e')
						{
							value = "r" + value.substr(1, value.length());
							is_x86 = true;
						}

						auto reg_value_const = reg.getConstRegister(value);

						//Verify if the value stored in the register is const
						if (std::get<0>(reg_value_const))
						{
							if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
							{
								if (is_x86)
								{
									mem_stack.const_value[mem_pos] = std::get<1>(reg_value_const) & 0xFFFFFFFF;
								} else
								{
									mem_stack.const_value[mem_pos] = std::get<1>(reg_value_const);
								}

							} else
							{
								if (is_x86)
								{
									mem_stack.const_value.emplace(mem_pos, std::get<1>(reg_value_const) & 0xFFFFFFFF);
								} else
								{
									mem_stack.const_value.emplace(mem_pos, std::get<1>(reg_value_const));
								}
							}
						} else //If the value isn't a const, is a variable
						{
							auto reg_value = reg.getVarRegister(value);

							if (std::get<0>(reg_value))
							{
								if (mem_stack.var.find(mem_pos) != mem_stack.var.end())
								{
									mem_stack.var[mem_pos] = *(std::get<1>(reg_value));

								} else
								{
									mem_stack.var.emplace(mem_pos, *(std::get<1>(reg_value)));
								}
							}
						}
					}
				} else //The destinantion is a register
				{
					auto is_x86_dest = false;

					if (dest[0] == 'e')
					{
						dest = "r" + dest.substr(1, dest.length());
						is_x86_dest = true;
					}

					if (value[0] == '0' && value[1] == 'x') //mov reg, number
					{
						reg.addRegister(std::stoull(value, nullptr, 16), dest);

					} else
					{
						auto pos = value.find("[");

						if (pos != std::string::npos) //mov reg, [pointer]
						{
							if (current_inst.args.find("obs") == current_inst.args.end()) //Ignore stdin
							{
								value = value.substr(pos + 1, value.length() - 2);
								std::string reg_name = value.substr(0, 3);
								int64_t relative_pos = std::stoull(value.substr(3, value.length()), nullptr, 16);
								auto mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

								//Find the value pointed by the pointer and puts it on the destination register
								if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
								{
									if (is_x86_dest)
									{
										reg.addRegister(mem_stack.const_value[mem_pos] & 0xFFFFFFFF, dest);
									} else
									{
										reg.addRegister(mem_stack.const_value[mem_pos], dest);
									}
								} else if (mem_stack.var.find(mem_pos) != mem_stack.var.end())
								{
									reg.addRegister(&(mem_stack.var[mem_pos]), dest);
								}
							}

						} else //mov reg, reg
						{
							auto is_x86_value = false;

							if (value[0] == 'e')
							{
								value = "r" + value.substr(1, value.length());
								is_x86_value = true;
							}

							auto reg_value_const = reg.getConstRegister(value);

							if (std::get<0>(reg_value_const))
							{
								if (is_x86_value || is_x86_dest)
								{
									reg.addRegister(std::get<1>(reg_value_const) && 0xFFFFFFFF, dest);
								} else
								{
									reg.addRegister(std::get<1>(reg_value_const), dest);
								}
							} else
							{
								auto reg_value = reg.getVarRegister(value);

								if (std::get<0>(reg_value))
								{
									reg.addRegister(std::get<1>(reg_value), dest);
								}
							}

						}
					}
				}
			} else if (current_inst.op == "lea") //lea reg, [pointer]
			{
				std::string dest = current_inst.args["dest"];
				std::string value = current_inst.args["value"];

				auto pos = value.find("[");
				value = value.substr(pos + 1, value.length() - 2);
				std::string reg_name = value.substr(0, 3);
				int64_t relative_pos = std::stoull(value.substr(3, value.length()), nullptr, 16);
				auto mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

				if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
				{
					reg.addRegister(mem_stack.const_value[mem_pos], dest);

				} else if (mem_stack.var.find(mem_pos) != mem_stack.var.end())
				{
					reg.addRegister(&(mem_stack.var[mem_pos]), dest);
				}

			} else if (current_inst.op == "add")
			{
				std::string dest = current_inst.args["dest"];
				std::string value = current_inst.args["value"];

				if (dest == "rsp" || dest == "rbp") //Arithmetic opertaions only valid on rsp and rbp
				{
					reg.addRegister(
							std::get<1>(reg.getConstRegister(dest))
									+ static_cast<int64_t>(std::stoull(value, nullptr, 16)), dest);
				}

			} else if (current_inst.op == "sub")
			{
				std::string dest = current_inst.args["dest"];
				std::string value = current_inst.args["value"];

				if (dest == "rsp" || dest == "rbp")
				{
					reg.addRegister(
							std::get<1>(reg.getConstRegister(dest))
									- static_cast<int64_t>(std::stoull(value, nullptr, 16)), dest);
				}
			} else if (current_inst.op == "call") //call <fnname>
			{
				std::string func_name = current_inst.args["fnname"];
				func_name = func_name.substr(1, func_name.length() - 2); //Remove <> from the function name

				if (functions.find(func_name) != functions.end()) //Verify if the function exist on the JSON
				{
					stack_func.emplace(&functions[func_name]); //Add the function to the stack
					func->current_inst++;
					allocFunction(functions[func_name],
							std::stoull(func->instructions[func->current_inst].address, nullptr, 16));

					return;
				} else
				{
					func_name = func_name.substr(0, func_name.find("@"));

					//Verify is the function called is dangerous
					auto is_vuln = [](const std::string vuln[N_DANGEROUS_FUNC], std::string name)
					{
						for(auto &p : vuln_functions) if(name.find(p)) return true;
						return false;
					}(vuln_functions, func_name);

					if (is_vuln)
					{
						analyzeVulnFunction(func, func_name);
					}
				}
			} else if (current_inst.op == "nop")
			{
				//Do nothing
			} else if (current_inst.op == "push")
			{
				reg.addRegister(std::get<1>(reg.getConstRegister("rsp")) - 8, "rsp");
				auto sp = std::get<1>(reg.getConstRegister("rsp"));

				std::string value = current_inst.args["value"];
				auto pos = value.find("[");

				if (value == "rbp")
				{
					//Do nothing (the reg rbp is already in the stack)
				} else if (pos != std::string::npos) //push [pointer]
				{
					value = value.substr(pos + 1, value.length() - 2);
					std::string reg_name = value.substr(0, 3);
					int64_t relative_pos = std::stoull(value.substr(3, value.length()), nullptr, 16);
					auto mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

					if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
					{
						if (mem_stack.const_value.find(sp) != mem_stack.const_value.end())
						{
							mem_stack.const_value[sp] = mem_stack.const_value[mem_pos];

						} else
						{
							mem_stack.const_value.emplace(sp, mem_stack.const_value[mem_pos]);
						}

					} else if (mem_stack.var.find(mem_pos) != mem_stack.var.end())
					{
						if (mem_stack.var.find(sp) != mem_stack.var.end())
						{
							mem_stack.var[sp] = mem_stack.var[mem_pos];

						} else
						{
							mem_stack.var.emplace(sp, mem_stack.var[mem_pos]);
						}
					}
				} else
				{
					if (value[0] == '0' && value[1] == 'x') //push number
					{
						if (mem_stack.const_value.find(sp) != mem_stack.const_value.end())
						{
							mem_stack.const_value[sp] = std::stoull(value, nullptr, 16);

						} else
						{
							mem_stack.const_value.emplace(sp, std::stoull(value, nullptr, 16));
						}
					} else //push reg
					{
						auto reg_value = reg.getVarRegister(value);

						if (std::get<0>(reg_value))
						{
							if (mem_stack.var.find(sp) != mem_stack.var.end())
							{
								mem_stack.var[sp] = *(std::get<1>(reg_value));

							} else
							{
								mem_stack.var.emplace(sp, *(std::get<1>(reg_value)));
							}
						} else
						{
							auto is_x86 = false;

							if (value[0] == 'e')
							{
								value = "r" + value.substr(1, value.length());
								is_x86 = true;
							}

							auto reg_value_const = reg.getConstRegister(value);

							if (std::get<0>(reg_value_const))
							{
								if (mem_stack.const_value.find(sp) != mem_stack.const_value.end())
								{
									if (is_x86)
									{
										mem_stack.const_value[sp] = std::get<1>(reg_value_const) & 0xFFFFFFFF;
									} else
									{
										mem_stack.const_value[sp] = std::get<1>(reg_value_const);
									}
								} else
								{
									mem_stack.const_value.emplace(sp, std::get<1>(reg_value_const));
								}
							}
						}
					}
				}
			} else if (current_inst.op == "leave")
			{
				desallocFunction(*func);
				stack_func.pop();
				leave = true;
			}

			func->current_inst++;

		} else
		{
			if (current_inst.op == "ret")
			{
				return;
			}
		}
	}
}

//Analyze all the code
void CodeAnalyzer::analyze()
{
	Function *current_func;
	std::stack<Function*> func_stack;

	func_stack.emplace(&functions["main"]);
	allocFunction(functions["main"], 0);
	current_func = func_stack.top();

	while (!func_stack.empty())
	{
		if (current_func != func_stack.top())
		{
			current_func = func_stack.top();
		}

		analyzeFunction(current_func, func_stack);
	}

}

