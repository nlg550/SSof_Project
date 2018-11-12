#include "CodeAnalyzer.hpp"

const std::string CodeAnalyzer::vuln_functions[N_DANGEROUS_FUNC] = { "gets", "strcpy", "strcat", "sprintf", "scanf",
		"fscanf", "fgets", "strncpy", "strncat", "snprintf", "read" };

/** 
 Constructor of CodeAnalyzer Class
 */
CodeAnalyzer::CodeAnalyzer(const std::string filename)
{
	readJSON(filename);
	std::cout << "Read from JSON - OK" << std::endl;

	analyze();
	std::cout << "Analysis - OK" << std::endl;

<<<<<<< HEAD
	//---------------------- TESTE --------------------
	/*	std::map<std::string, Function>::iterator it = functions.begin();
	 std::cout << "Functions:\n";
	 std::map<std::string, std::string>::iterator ti = it->second.instructions[0].args.begin();
	 for (it = functions.begin(); it != functions.end(); ++it)
	 std::cout << it->first << " : " << "- " << ti->first << " : " << ti->second << '\n';*/
	//-----------------------------------------------------
=======
>>>>>>> d86fc24ffb5357137036f067be6e31d518f1adaf
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
			}
			else if(it2.key()=="variables")
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
					variables_.push_back(v_);
				}
				function_.variables = variables_;
			}
			else if(it2.key() == "instructions")
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
	int cont = 0;
	std::ofstream file;
	std::string file_write = filename;
	file_write.erase(file_write.length() - 5, file_write.length());
	file_write += ".output.json";
	file.open(file_write);

<<<<<<< HEAD
//  --------------  TESTE --------------
	/*	Vulnerability test;
	 test.type = "type";
	 test.fnname = "fnname";
	 vulnerabilities.push_back(test);
	 vulnerabilities.push_back(test);
	 vulnerabilities.push_back(test);*/
// 	------------------------------------
=======
>>>>>>> d86fc24ffb5357137036f067be6e31d518f1adaf
	while (vulnerabilities.size() != cont)
	{
		structToJson(output, vulnerabilities.at(cont));
		cont++;
	}
	file << output.dump(4) << std::endl;
	file.close();
}

/** 
 structToJson Function:
 This function is responsible to transform a struct variabl in a JSON variable.
 */
void CodeAnalyzer::structToJson(json& output, const Vulnerability& vuln)
{
	output += json { { "type", vuln.type }, { "vuln_function", vuln.vuln_function }, { "fnname", vuln.fnname }, {
			"address", vuln.address }, { "overflow_var", vuln.overflow_var }, { "overflown_var", vuln.overflown_var } };
}

// Allocate the memory stack and the register for the function <func>
void CodeAnalyzer::allocFunction(Function& func, unsigned int return_addr)
{
	unsigned int sp = std::get<1>(reg.getConstRegister("rsp"));

	mem_stack.const_value.emplace(sp - 8, return_addr); //Insert the return address on the stack
	reg.addRegister(sp - 8, "rsp"); //Update register rsp
	reg.addRegister(std::stoul(func.instructions[0].address, nullptr, 16), "rsi"); 	//Change the register rsi to the address of the new function

	for (auto &p : func.variables)
	{
		std::string reg_name = p.address.substr(0, 2);
		int relative_pos = std::stoi(p.address.substr(3, p.address.length()), nullptr, 16);
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
<<<<<<< HEAD
	std::cout << overflow << std::endl;
=======
	/*

	1-(Basic Analysis) what is the vulnerability, either VAROVERFLOW, RBPOVERFLOW, RETOVERFLOW;
	2-(Advanced Analysis) what is the vulnerability, either INVALIDACCS, SCORRUPTION;
	3-the dangerous function/instruction that causes the vulnerability;
	4-which function of your program is vulnerable,
	5-what is the address where the dangerous function/instruction is called;
	6-(Basic Analysis) the overflowing buffer. In the case of VAROVERFLOW it should also state the overflown variable.
	7-(Advanced Analysis) the overflowing buffer and the first address of the block(s) that is(are) overflown.
	
	(updated) Basic: gets, strcpy, strcat, fgets, strncpy, strncat
	*/
	if (func_name == "gets")
	{
		auto arg = std::get<1>(reg.getVarRegister("rdi"));
>>>>>>> d86fc24ffb5357137036f067be6e31d518f1adaf

	Vulnerability vuln;
	vuln.address = func->instructions[func->current_inst].address;
	vuln.fnname = func_name;
	vuln.overflow_var = arg->name;
	vuln.vuln_function = func->name;
	vuln.type = "VAROVERFLOW";

	int arg_relative_pos = std::stoi(arg->address.substr(3, arg->address.length()), nullptr, 16);
	int relative_pos;

	//Find all possible local variables that can be overflown
	for (auto &p : func->variables)
	{
		if (overflow > 0)
		{
			relative_pos = std::stoi(p.address.substr(3, p.address.length()), nullptr, 16);

			if (arg_relative_pos < relative_pos)
			{
				vuln.is_var_overflown = true;
				vuln.overflown_var = p.name;
				vulnerabilities.emplace_back(vuln);
				overflow -= p.bytes;
			}
		} else
		{
			return;
		}
	}

	vuln.is_var_overflown = false;

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
}

//Verify if the dangerous functions is actually vulnerable
void CodeAnalyzer::analyzeVulnFunction(Function *func, std::string func_name)
{
	if (func_name == "gets")
	{
		auto arg = std::get<1>(reg.getVarRegister("rdi"));

		analyzeOverflow(func, func_name, arg, 100000);

	} else if (func_name == "fgets")
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));
		auto arg2 = std::get<1>(reg.getConstRegister("esi"));

		int overflow = arg2 - arg1->bytes;

		if (overflow > 0)
		{
			analyzeOverflow(func, func_name, arg1, overflow);
		}

		arg1->bytes = arg2;

	} else if (func_name == "strcpy")
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));
		auto arg2 = std::get<1>(reg.getVarRegister("rsi"));

		int overflow = arg2->bytes - arg1->bytes;

		std::cout << arg1->bytes << std::endl;
		std::cout << arg2->bytes << std::endl;
		std::cout << overflow << std::endl;

		if (overflow > 0)
		{
			analyzeOverflow(func, func_name, arg1, overflow);
		}

		arg1->bytes = arg2->bytes;

	} else if (func_name == "strcat")
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));
		auto arg2 = std::get<1>(reg.getVarRegister("rsi"));

		int overflow = arg2->bytes - arg1->bytes;

		if (overflow > 0)
		{
			analyzeOverflow(func, func_name, arg1, overflow);
		}

		arg1->bytes += arg2->bytes;

	} else if (func_name == "strncpy")
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));
		auto arg3 = std::get<1>(reg.getConstRegister("rdx"));

		int overflow = arg3 - arg1->bytes;

		if (overflow > 0)
		{
			analyzeOverflow(func, func_name, arg1, overflow);
		}

		arg1->bytes = arg3;

	} else if (func_name == "strncat")
	{
		auto arg1 = std::get<1>(reg.getVarRegister("rdi"));
		auto arg3 = std::get<1>(reg.getConstRegister("rdx"));

		int overflow = arg3 - arg1->bytes;

		if (overflow > 0)
		{
			analyzeOverflow(func, func_name, arg1, overflow);
		}

		arg1->bytes = arg3;
	}
	else if(func_name == "strcpy")
	{


	}
	else if(func_name =="strcat")
	{

	}
	else if(func_name =="strncpy")
	{

	}
	else if(func_name =="strncat")
	{

	}


	/*
	(updated) Advanced: sprintf, scanf, fscanf, snprintf, read
	*/
	else if(func_name =="sprintf")
	{
		std::cout << "Segunda etapa da implementação." << std::endl;
	}
	else if(func_name =="scanf")
	{
		std::cout << "Segunda etapa da implementação." << std::endl;
	}
	else if(func_name =="fscanf")
	{
		std::cout << "Segunda etapa da implementação." << std::endl;
	}
	else if(func_name =="snprintf")
	{
		std::cout << "Segunda etapa da implementação." << std::endl;
	}
	else if(func_name =="read")
	{
		std::cout << "Segunda etapa da implementação." << std::endl;
	}
	else{
		std::cout << "Erro nenhuma função conhecida foi chamada." << std::endl;
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
					dest = dest.substr(pos + 1, dest.length() - 1);
					std::string reg_name = dest.substr(0, 2);
					int relative_pos = std::stoi(dest.substr(3, dest.length()), nullptr, 16);
					unsigned int mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

//				if(mem_pos > std::get<1>(reg.getConstRegister("rsp")) || mem_pos <= std::get<1>(reg.getConstRegister("rbp")))
//				{
//
//				}

					if (value[0] == '0' && value[1] == 'x') //mov [pointer], number
					{
						//Put the number on the memory stack
						if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
						{
							mem_stack.const_value[mem_pos] = std::stoul(value, nullptr, 16);

						} else
						{
							mem_stack.const_value.emplace(mem_pos, std::stoul(value, nullptr, 16));
						}
					} else //mov [pointer], reg
					{
						auto reg_value_const = reg.getConstRegister(value);

						//Verify if the value stored in the register is const
						if (std::get<0>(reg_value_const))
						{
							if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
							{
								mem_stack.const_value[mem_pos] = std::get<1>(reg_value_const);

							} else
							{
								mem_stack.const_value.emplace(mem_pos, std::get<1>(reg_value_const));
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
					if (value[0] == '0' && value[1] == 'x') //mov reg, number
					{
						reg.addRegister(std::stoul(value, nullptr, 16), dest);
					} else
					{
						auto pos = value.find("[");

						if (pos != std::string::npos) //mov reg, [pointer]
						{
							if (current_inst.args.find("obs") == current_inst.args.end()) //Ignore stdin
							{
								value = value.substr(pos + 1, value.length() - 1);
								std::string reg_name = value.substr(0, 2);
								int relative_pos = std::stoi(value.substr(3, value.length()), nullptr, 16);
								unsigned int mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

								//Find the value pointed by the pointer and puts it on the destination register
								if (mem_stack.const_value.find(mem_pos) != mem_stack.const_value.end())
								{
									reg.addRegister(mem_stack.const_value[mem_pos], dest);

								} else if (mem_stack.var.find(mem_pos) != mem_stack.var.end())
								{
									reg.addRegister(&(mem_stack.var[mem_pos]), dest);
								}
							}

						} else //mov reg, reg
						{
							auto reg_value_const = reg.getConstRegister(value);

							if (std::get<0>(reg_value_const))
							{
								reg.addRegister(std::get<1>(reg_value_const), dest);

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
				value = value.substr(pos + 1, value.length() - 1);
				std::string reg_name = value.substr(0, 2);
				int relative_pos = std::stoi(value.substr(3, value.length()), nullptr, 16);
				unsigned int mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

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
					reg.addRegister(std::get<1>(reg.getConstRegister(dest)) + std::stoul(value, nullptr, 16), dest);
				}

			} else if (current_inst.op == "sub")
			{
				std::string dest = current_inst.args["dest"];
				std::string value = current_inst.args["value"];

				if (dest == "rsp" || dest == "rbp")
				{
					reg.addRegister(std::get<1>(reg.getConstRegister(dest)) - std::stoul(value, nullptr, 16), dest);
				}
			} else if (current_inst.op == "call") //call <fnname>
			{
				std::string func_name = current_inst.args["fnname"];
				func_name = func_name.substr(1, func_name.length() - 2); //Remove <> from the function name

				if (functions.find(func_name) != functions.end()) //Verify if the function exist on the JSON
				{
					stack_func.emplace(&functions[func_name]); //Add the function to the stack
					func->current_inst++;
					return;
				} else
				{
					func_name = func_name.substr(0, func_name.find("@"));

					//Verify is the function called is dangerous
					auto is_vuln = [](const std::string vuln[N_DANGEROUS_FUNC], std::string name)
					{
						for(auto &p : vuln_functions) if(name == p) return true;
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

				if (pos != std::string::npos) //push [pointer]
				{
					value = value.substr(pos + 1, value.length() - 1);
					std::string reg_name = value.substr(0, 2);
					int relative_pos = std::stoi(value.substr(3, value.length()), nullptr, 16);
					unsigned int mem_pos = std::get<1>(reg.getConstRegister(reg_name)) + relative_pos;

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
							mem_stack.const_value[sp] = std::stoul(value, nullptr, 16);

						} else
						{
							mem_stack.const_value.emplace(sp, std::stoul(value, nullptr, 16));
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
							auto reg_value_const = reg.getConstRegister(value);

							if (std::get<0>(reg_value_const))
							{
								if (mem_stack.const_value.find(sp) != mem_stack.const_value.end())
								{
									mem_stack.const_value[sp] = std::get<1>(reg_value_const);

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
				leave = true;
			}

			func->current_inst++;

		} else
		{
			if (current_inst.op == "ret")
			{
				desallocFunction(*func);
				stack_func.pop();
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

