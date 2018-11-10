#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <map>
#include <string>
#include <vector>
#include <stack>
#include <iostream>
#include <fstream>

#include "json.hpp" //JSON Library
#include "Registers.hpp"
#include "StructDefinition.hpp"

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
	unsigned int desallocFunction (Function &func);
	void analyzeFunction(Function *func, std::stack<Function*> &stack_func);

public:
	CodeAnalyzer(const std::string filename);
	virtual ~CodeAnalyzer();
	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void analyze();
};

#endif /* CODEANALYZER_H_ */
