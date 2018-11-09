#include "CodeAnalyzer.hpp"

CodeAnalyzer::CodeAnalyzer(const std::string filename)
{
	std::vector<Vulnerability> vulnerabilities(0);
	//this->readJSON(filename);
	//analyze();
	//this->writeJSON(filename);
}

CodeAnalyzer::~CodeAnalyzer()
{
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
//defined by the variable tracking. If is successful, return true and the value. Otherwise, return false;
std::tuple<bool, std::string> backtrackValue(Function &func, unsigned int i_inst,
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
					return std::make_tuple(true, current.args["value"]); //The value is numeric
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
				if (current.args["value"].find("rbp") != std::string::npos)
				{
					return std::make_tuple(true, current.args["value"]); //The value is a variable on the stack
				}
			}
		}

		i_inst--;
	}

	return std::make_tuple(false, "");

}

void CodeAnalyzer::analyze()
{
	Function *current_func;
	std::stack<Function*> func_stack;
	std::stack<Function*> tmp_func_stack;
	std::vector<Variable> var_args;
	std::vector<int> const_arg;

	func_stack.emplace(&functions["main"]);

	while (!func_stack.empty())
	{
		current_func = func_stack.top();

		//search the current function for all function calls, and return the indexes
		/*std::stack<unsigned int> index =
				[current_func]
				{
					std::stack<unsigned int> *tmp = new std::stack<unsigned>(0);
					for(unsigned int i = 0; i < current_func->Ninstructions; i++) if (current_func->instructions[i].op == "call") tmp->emplace_back(i);
					return *tmp;
				};*/

		/*if (!index.empty())
		{

		}*/

	}

}

