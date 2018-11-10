#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <iostream>
#include <stack>
#include <tuple>

#include "json.hpp" //JSON Library
#include "StructDefinition.hpp"
#include "Registers.hpp"

using json = nlohmann::json;

class CodeAnalyzer {
private:
	MemoryStack mem_stack;
	Registers reg;

	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

	void structToJson(json& output, const Vulnerability& vuln);
	void jsonToStruct(json input);

	void allocFunction (Function &func, unsigned int return_addr);

public:
	CodeAnalyzer(const std::string filename);
	virtual ~CodeAnalyzer();
	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void analyze();
};

#endif /* CODEANALYZER_H_ */
