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
	json input;
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
	}
	
	Vulnerability vuln;
	jsonToStruct(input, vuln);

	std::cout <<"Vulnerabilidades: \n" << vuln.type << std::endl;
	
}

void CodeAnalyzer::jsonToStruct(const json& input, Vulnerability& vuln )
{
	input.at("vulnerability").get_to(vuln.type);
	input.at("vuln_function").get_to(vuln.vuln_function);
	input.at("address").get_to(vuln.address);
	input.at("fnname").get_to(vuln.fnname);
	input.at("overflow_var").get_to(vuln.overflow_var);
	input.at("overflown_var").get_to(vuln.overflown_var);
} 

void CodeAnalyzer::writeJSON(const std::string filename, std::vector<Vulnerability> vuln)
{
	json output;
	int cont = 0;
	std::ofstream file;
	file.open(filename);

	while (vuln.size() != cont)
  	{
    	structToJson(output, vuln.at(cont)); 
    	//vuln.erase(cont);
		file << output << std::endl;
		cont++;
 	}
	file.close();
}


void CodeAnalyzer::structToJson(json& output, const Vulnerability vuln)
{
	output = json {	{"vulnerability", vuln.type},
					{"vuln_function", vuln.vuln_function},
					{"address", vuln.address},
					{"fnname",vuln.fnname},
					{"overflow_var", vuln.overflow_var},
					{"overflown_var", vuln.overflown_var}};
}

void CodeAnalyzer::analyze()
{
}
