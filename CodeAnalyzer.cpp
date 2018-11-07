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
	functions.resize(0, Function(NULL, 0));
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
}
