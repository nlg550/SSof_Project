#include "CodeAnalyzer.hpp"

using json = nlohmann::json;

//namespace custom {
//void to_json(json& j, const Attribute& att)
//{
//	j = json { { "name", p.name }, { "address", p.address }, { "age", p.age } };
//}
//
//void from_json(const json& j, person& p)
//{
//	j.at("name").get_to(p.name);
//
//}
//
//}  // namespace custom

CodeAnalyzer::CodeAnalyzer()
{
	functions.resize(0, Function("", 0));
}

CodeAnalyzer::~CodeAnalyzer()
{
	functions.clear();
}

void CodeAnalyzer::readJSON(const std::string filename)
{
	/*json input;
	std::ifstream input_file;

	//Temporary variables
	std::string tstring;
	unsigned int tmp;
	Attribute att;
	Instruction inst;

	input_file.open(filename);

	if (input_file.is_open())
	{
		input_file >> input;
	}

	for (auto &p : input)
	{
		std::cout << p << std::endl;
	}*/

}

void CodeAnalyzer::writeJSON(const std::string filename)
{
}

void CodeAnalyzer::analyze()
{
	/*std::string func_name;
		std::string tmp;
		std::vector<std::string> token;
		bool leave = false;

		while (currentInst < n_inst)
		{
			if (!leave)
			{
				if (instructions[currentInst].op == "call")
				{
					//Search for the name of function called
					func_name = instructions[currentInst].args["fnname"];

					//Search if the function called is consider dangerous
					auto is_dangerous =
							[func_name, &dangerous_functions]
							{	for(auto &p : dangerous_functions) if(p.find(func_name) != std::string::npos) return p;
								return false;};

					if (is_dangerous)
					{

					}
					else
					{
						//Verify if the function called is not from a library
						if (func_name.find("@") == std::string::npos)
						{
							stack.value_address.emplace(regs.regAddress["RSP"] + 4,
									instructions[currentInst + 1].address); // Save the return address on the stack
							stack.value_address.emplace(regs.regAddress["RSP"] + 8,
									regs.regAddress["RBP"]);  				// Save the RBP on the stack

							//Move the RSP e RBP to the next block of the stack
							regs.regAddress["RBP"] = regs.regAddress["RSP"] + 8;
							regs.regAddress["RSP"] = regs.regAddress["RSP"] + 8;

							//Jump to the function called
							regs.regAddress["RIP"] = instructions[currentInst].args["address"];

							currentInst++;
							return std::make_tuple(false, func_name);
						}
					}
				} else if (instructions[currentInst].op == "nop")
				{
					//Do nothing

				} else if (instructions[currentInst].op == "leave")
				{
					leave = true;

				} else if (instructions[currentInst].op == "push")
				{
					regs.regAddress["RSP"] -= 4;

					token.clear();
					tmp = instructions[currentInst].args["value"];

					if (tmp == '[')
					{
						tmp.substr(1, tmp.length() - 1);

						token.emplace_back(tmp.substr(0, 2));
						token.emplace_back(tmp.substr(3, tmp.length()));

						stack.value_address[regs.regAddress["RSP"]] =
						stack.value_address[regs.regAddress[token[0] + std::stoi(token[1])]];
					}

				}

			} else if (leave && instructions[currentInst].op == "ret")
			{

				regs.regAddress["RIP"] = stack.value_address[regs.regAddress["RBP"] + 4]; //Move the return address to instruction counter
				regs.regAddress["RBP"] = stack.value_address[regs.regAddress["RBP"]]; //Restore the value of RBP from the stack
				regs.regAddress["RSP"] = stack.value_address[regs.regAddress["RBP"] + 8]; //Restore the value of RSP from the stack

				//Remove from the stack all value lower than RSP + 4
				auto it_addr = stack.value_address.lower_bound(regs.regAddress["RBP"] + 4);
				stack.value_address.erase(stack.value_address.begin(), it_addr);
				auto it_attr = stack.value_attribute.lower_bound(regs.regAddress["RBP"] + 4);
				stack.value_attribute.erase(stack.value_attribute.begin(), it_attr);

				return std::make_tuple(true, "");
			}
		}

		return std::make_tuple(true, "");*/
}
