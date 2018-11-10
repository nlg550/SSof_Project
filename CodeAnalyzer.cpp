#include "CodeAnalyzer.hpp"

/** 
	Constructor of CodeAnalyzer Class 
*/
CodeAnalyzer::CodeAnalyzer(const std::string filename)
{
	readJSON(filename);
	std::cout << "readJSON - OK" << std::endl;

	//---------------------- TESTE --------------------
	std::map<std::string,Function>::iterator it = functions.begin();
	std::cout << "Functions:\n";
	std::map<std::string,std::string>::iterator ti = it->second.instructions[0].args.begin();
	for (it = functions.begin(); it != functions.end(); ++it)
		std::cout << it->first << " : " << "- " << ti->first << " : " << ti->second << '\n';
	//-----------------------------------------------------



	writeJSON(filename);
	std::cout << "writeSON - OK" << std::endl;
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
	if (input_file.is_open()){
		input_file >> input;
	}else{
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
	for (json::iterator it = input.begin(); it != input.end(); ++it) {  //Primeira interação para selecionar a funçao (main, fun)
  		Function function_;
		function_.name = it.key();
		json js_ = *it; 
		for (json::iterator it2 = js_.begin(); it2 != js_.end(); ++it2) { // Interção dentro da função
			if(it2.key() == "Ninstructions"){
				function_.Ninstructions = it2.value();
			}
			if(it2.key()=="variables"){
				json var_ = it2.value();
				std::vector<Variable> variables_;
				for (json::iterator it_Var = var_.begin(); it_Var != var_.end(); ++it_Var) { // Interação dentro das estruturas de variables
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
			if(it2.key() == "instructions"){
				json ins_ = it2.value();
				std::vector<Instruction> instructions_;
				for (json::iterator it_Ins = ins_.begin(); it_Ins != ins_.end(); ++it_Ins) { //Primeira Interaçao dentro das estrutura de Instructions (blocos)
					Instruction i_;
					std::map<std::string, std::string> args_map;
					json ins_intern = it_Ins.value();
					ins_intern.at("op").get_to(i_.op);
					ins_intern.at("pos").get_to(i_.pos);
					ins_intern.at("address").get_to(i_.address);
					for (json::iterator it_args = ins_intern.begin(); it_args != ins_intern.end(); ++it_args) { //Segunda interação, fazendo com que o ponteiro aponte para cara elemento de Intruction (elementos)
						json ins_args = it_args.value();
						if( it_args.key() == "args"){
							for (json::iterator it_args_inside = ins_args.begin(); it_args_inside != ins_args.end(); ++it_args_inside) { //Segunda interação, fazendo com que o ponteiro aponte para cara elemento de Intruction (elementos)
								json ins_args_map = it_args_inside.value();
								std::string key = it_args_inside.key();
								std::string value = it_args_inside.value(); 
								args_map.insert(std::pair<std::string,std::string>(key,value));
							}
						}
						i_.args = args_map;
					}
					instructions_.push_back(i_);
				}
				function_.instructions = instructions_;
			}
			else{
				std::cout << "Error na transformação da variavel JSON para struct Function" << std::endl;
			}
		}
		functions.insert(std::pair<std::string,Function>(function_.name,function_));
	}

}

void CodeAnalyzer::allocFunction(Function& func, unsigned int return_addr)
{
	unsigned int stack_addr = reg.getAddrRegister("rsp");

	mem_stack.addr.emplace(stack_addr + 8, return_addr);
	mem_stack.addr.emplace(stack_addr + 16, reg.getAddrRegister("rbp"));

	reg.addRegister(stack_addr + 16, "rbp");
	reg.addRegister(func_addr, "rsi");

	for(unsigned int i = 0; i < func.variables.size(); i++)
	{
		std::string reg_name = func.variables[i].address.substr(0, 2);
		int relative_pos = std::stoi(func.variables[i].address.substr(3, func.variables[i].address.length()), nullptr, 16);



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
	file_write.erase(file_write.length()-5,file_write.length() );
	file_write += ".output.json";
	file.open(file_write);

//  --------------  TESTE --------------
	Vulnerability test;
	test.type = "type";
	test.fnname = "fnname";
	vulnerabilities.push_back(test);
	vulnerabilities.push_back(test);
	vulnerabilities.push_back(test);
// 	------------------------------------

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
	output += json { {"type",vuln.type},
					{"vuln_function",vuln.vuln_function},
					{"fnname",vuln.fnname},
					{"address",vuln.address},
					{"overflow_var",vuln.overflow_var},
					{"overflown_var",vuln.overflown_var}};
}

void CodeAnalyzer::analyze()
{
}
/*
*
	backtrackValue Function:
		Backtrack the instructions (beginning with i_inst) of the function func,
		to find the value of a register or position in the memory defined by the
		variable tracking. If is successful, return true and the value. Otherwise,
		return false and last tracking position

std::tuple<bool, std::string> backtrackValue(Function &func, unsigned int i_inst, std::string tracking)
{
	

	Instruction current;

	while (i_inst > 0)
	{
		current = func.instructions[i_inst];

		if (current.op == "mov")
		{
			if (current.args["dest"] == tracking)
			{
				if (current.args["value"][0] == '0' && current.args["value"][1] == 'x')
				{
					return std::make_tuple(true, current.args["value"]); //The value is numeric
				} else
				{
					tracking = current.args["value"]; //Keep backtracking
				}
			}
		} else if (current.op == "lea")
		{
			if (current.args["dest"] == tracking)
			{
				std::string tmp = current.args["value"].substr(1, current.args["value"].length());

				//Verify if the address in the memory stores a variable
				auto is_variable = [](std::vector<Variable> &vars, std::string pos)
				{
					for(auto &p : vars) if(p.address == pos) return true;
					return false;
				}(func.variables, tmp);

				if (is_variable)
				{
					return std::make_tuple(true, current.args["value"]); //The value is a variable on the stack
				} else
				{
					tracking = current.args["value"]; //Keep backtracking
				}
			}
		}

		i_inst--;
	}

	return std::make_tuple(false, tracking);
}


*
	backtrackingVar Function:
		This function is responsible 

Variable* CodeAnalyzer::backtrackingVar(std::stack<Function*> f_stack, std::string tracking)
{
	std::tuple<bool, std::string> backtrack;
	Function *current_func;

	while (!f_stack.empty())
	{
		current_func = f_stack.top();
		f_stack.pop();

		backtrack = backtrackValue(*current_func, current_func->current_inst + 1, "RDI");

		if (std::get<0>(backtrack))
		{
			std::string pos = std::get<1>(backtrack).substr(1, std::get<1>(backtrack).length() - 1);

			//Get the variable from the position on the stack
			return [](std::vector<Variable> &vars, std::string pos)
			{	for(auto &p : vars) if(p.address == pos) return &p;}(current_func->variables, pos);
		}
	}

	return nullptr;
}


*
	backtrakingConst Function:
		This function is responsible

int CodeAnalyzer::backtrackingConst(std::stack<Function*> f_stack, std::string tracking)
{
	std::tuple<bool, std::string> backtrack;
	Function *current_func;

	while (!f_stack.empty())
	{
		current_func = f_stack.top();
		f_stack.pop();

		backtrack = backtrackValue(*current_func, current_func->current_inst + 1, "RDI");

		if (std::get<0>(backtrack))
		{
			//Get the variable from the position on the stack
			return std::stoi(std::get<1>(backtrack), nullptr, 16);
		}
	}

	return 0;
}


*
	analyzer Function:
		This function is responsible to analyzer the JSON file.

void CodeAnalyzer::analyze()
{
	Function *current_func;
	std::stack<Function*> func_stack;
	std::stack<std::string> name_func_stack;

	func_stack.emplace(&functions["main"]);
	name_func_stack.emplace("main");

	while (!func_stack.empty())
	{
		current_func = func_stack.top();

		//Search for the next call instruction on the current function
		auto found = [](Function &func)
		{
			while(func.current_inst < func.Ninstructions)
			{
				if(func.instructions[func.current_inst].op == "call")
				{
					return true;
				}
				func.current_inst += 1;
			}
			return false;
		}(*current_func);

		if (found)
		{
			std::string func_name;

			func_name = current_func->instructions[current_func->current_inst].args["fnname"];
			func_name = func_name.substr(1, func_name.length() - 1); //Remove <> from the function name

			if (functions.find(func_name) != functions.end()) //Verify if the function exist on the JSON
			{
				func_stack.emplace(&functions[func_name]); //Add the function to the stack
				name_func_stack.emplace(func_name);

			} else if (func_name.find("gets") != std::string::npos)
			{
				auto arg = backtrackingVar(func_stack, "RDI");

				if (arg != nullptr)
				{
					Vulnerability vuln;
					vuln.address = current_func->instructions[current_func->current_inst].address;
					vuln.fnname = "gets";
					vuln.overflow_var = arg->name;
					vuln.vuln_function = name_func_stack.top();
					vuln.type = "VAROVERFLOW";

					int arg_relative_pos = std::stoi(arg->address.substr(3, arg->address.length()), nullptr, 16);
					int relative_pos;

					//Find all possible local variables that can be overflown
					for (auto &p : current_func->variables)
					{
						relative_pos = std::stoi(p.address.substr(3, p.address.length()), nullptr, 16);

						if (arg_relative_pos < relative_pos)
						{
							vuln.is_var_overflown = true;
							vuln.overflown_var = p.name;
							vulnerabilities.emplace_back(vuln);
						}
					}

					vuln.is_var_overflown = false;
					vuln.type = "RBPOVERFLOW";
					vulnerabilities.emplace_back(vuln);

					vuln.type = "RETOVERFLOW";
					vulnerabilities.emplace_back(vuln);
				}

			} else if (func_name.find("fgets") != std::string::npos)
			{
				auto arg1 = backtrackingVar(func_stack, "RDI");
				auto arg2 = backtrackingConst(func_stack, "RSI");

				if (arg1 != nullptr && arg1->bytes < arg2)
				{
					Vulnerability vuln;
					vuln.address = current_func->instructions[current_func->current_inst].address;
					vuln.fnname = "gets";
					vuln.overflow_var = arg1->name;
					vuln.vuln_function = name_func_stack.top();
					vuln.type = "VAROVERFLOW";

					int arg_relative_pos = std::stoi(arg1->address.substr(3, arg1->address.length()), nullptr, 16);
					int relative_pos;

					//Find all possible local variables that can be overflown
					for (auto &p : current_func->variables)
					{
						relative_pos = std::stoi(p.address.substr(3, p.address.length()), nullptr, 16);

						if (arg_relative_pos < relative_pos)
						{
							vuln.is_var_overflown = true;
							vuln.overflown_var = p.name;
							vulnerabilities.emplace_back(vuln);
						}
					}

					vuln.is_var_overflown = false;
					vuln.type = "RBPOVERFLOW";
					vulnerabilities.emplace_back(vuln);

					vuln.type = "RETOVERFLOW";
					vulnerabilities.emplace_back(vuln);
				}
			}
		}
	}

}
*/



