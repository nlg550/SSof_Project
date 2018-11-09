#include "CodeAnalyzer.hpp"

CodeAnalyzer::CodeAnalyzer()
{
}

CodeAnalyzer::~CodeAnalyzer()
{
	vulnerabilities.clear();
	functions.clear();
}

void CodeAnalyzer::readJSON(const std::string filename)
{
	/*json input;
	 std::ifstream input_file;
	 input_file.open(filename);
	 if (input_file.is_open())
	 {
	 input_file >> input;
	 }
	 else
	 {
	 std::cout << "Erro na abertura do arquivo" << std::endl;
	 }

	 jsonToStruct(input, this->functions);

	 /*
	 Vulnerability vuln;

	 jsonToStruct(input, vuln);
	 std::cout <<"2 - " << input.dump(4) << std::endl;
	 std::cout <<"3 - " <<"Vulnerabilidades: " << vuln.type << " - "<< input.size() << std::endl;
	 std::vector<Vulnerability> test;
	 test.push_back(vuln);
	 std::string f = filename + "_output";
	 this->writeJSON(f,test);
	 */
}

void CodeAnalyzer::jsonToStruct(const json& input, std::vector<Function>& functions)
{

	int size = input.size();
	std::cout << size << std::endl;
	/*if(size > 1){
	 for(int i = 0; i < size; ++i ){
	 Function func
	 {
	 input[i].get<std::string>()
	 };
	 }
	 }
	 else
	 {
	 Function func
	 {
	 input[0]["main"].get<std::string>()
	 };
	 }
	 */
	/*
	 Vulnerability v {
	 input[0]["vulnerability"].get<std::string>(),
	 input[0]["vuln_function"].get<std::string>(),
	 input[0]["address"].get<std::string>(),
	 input[0]["fnname"].get<std::string>(),
	 input[0]["overflow_var"].get<std::string>(),
	 input[0]["overflown_var"].get<std::string>(),
	 };
	 vuln = v;
	 */
}

void CodeAnalyzer::writeJSON(const std::string filename)
{
	json output;
	int cont = 0;
	std::ofstream file;
	std::string file_write = filename + ".output.json";
	file.open(filename);

	while (vulnerabilities.size() != cont)
	{
		structToJson(output, vulnerabilities.at(cont));
		file << output.dump(4) << std::endl;
		cont++;
	}
	file.close();
}

void CodeAnalyzer::structToJson(json& output, const Vulnerability& vuln)
{
}

//Backtrack the instructions (beginning with i_inst) of the function func, to find the value of a register or position in the memory
//defined by the variable tracking. If is successful, return true, type of value (0 - const, 1 - var) and the value.
//Otherwise, return false;
std::tuple<bool, unsigned int, std::string> backtrackValue(Function &func, unsigned int i_inst,
		std::string tracking)
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
					return std::make_tuple(true, 0, current.args["value"]); //The value is numeric
				}
				else
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
				auto is_variable = [&func, &tmp]()
				{
					for(auto &p : func.variables) if(p.address == tmp) return true;
					return false;
				};

				if (is_variable)
				{
					return std::make_tuple(true, 1, current.args["value"]); //The value is a variable on the stack
				}
				else
				{
					tracking = current.args["value"]; //Keep backtracking
				}
			}
		}

		i_inst--;
	}

	return std::make_tuple(false, 0, "");
}

void CodeAnalyzer::analyze()
{
	Function *current_func;
	std::stack<Function*> func_stack;
	std::stack<std::string> name_func_stack;
	std::stack<Function*> tmp_func_stack;

	func_stack.emplace(&functions["main"]);
	name_func_stack.emplace("main");

	while (!func_stack.empty())
	{
		current_func = func_stack.top();

		//Search for the next call instruction on the current function
		auto found = [&current_func] ()
		{
			while(current_func->current_inst < current_func->Ninstructions)
			{
				if(current_func->instructions[current_func->current_inst].op == "call")
				{
					return true;
				}

				current_func->current_inst += 1;
			}

			return false;
		};

		if (found)
		{
			std::string func_name;
			std::tuple<bool, unsigned int, std::string> backtrack;

			func_name = current_func->instructions[current_func->current_inst].args["fnname"];
			func_name = func_name.substr(1, func_name.length() - 1); //Remove <> from the function name

			if (functions.find(func_name) != functions.end()) //Verify if the function exist on the JSON
			{
				func_stack.emplace(&functions[func_name]); //Add the function to the stack
				name_func_stack.emplace(func_name);

			} else if (func_name.find("gets") != std::string::npos)
			{
				backtrack = backtrackValue(*current_func, current_func->current_inst + 1, "RDI");

				if (std::get<0>(backtrack))
				{
					if (std::get<1>(backtrack) == 1)
					{
						//Get the variable from the position on the stack
						Variable arg =
								[&current_func, &backtrack]()
								{	for(auto &p : current_func->variables) if(p.address == std::get<2>(backtrack)) return p;};

						Vulnerability vuln;
						vuln.address = current_func->instructions[current_func->current_inst].address;
						vuln.fnname = "gets";
						vuln.overflow_var = arg.name;
						vuln.vuln_function = name_func_stack.top();
						vuln.type = "VAROVERFLOW";

						int arg_relative_pos = std::stoi(arg.address.substr(3, arg.address.length()), nullptr, 16);
						int relative_pos;

						//Find all possible local variables that can be overflown
						for (auto &p : current_func->variables)
						{
							relative_pos = std::stoi(p.address.substr(3, p.address.length()), nullptr, 16);

							if(arg_relative_pos < relative_pos)
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

			}else
			{

			}
		}
	}

}

