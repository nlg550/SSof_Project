#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <map>
#include <string>
#include <vector>
#include <stack>
#include <iostream>
#include <fstream>
#include <tuple>

#include "json.hpp" //JSON Library
#include "Registers.hpp"
#include "StructDefinition.hpp"

#define N_DANGEROUS_FUNC 11

using json = nlohmann::json;

class CodeAnalyzer {
private:
	//All the dangerous functions to be consider
	static const std::string vuln_functions[N_DANGEROUS_FUNC];

	MemoryStack mem_stack;
	Registers reg;

	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

	void allocFunction (Function &func, unsigned int return_addr);
	void desallocFunction (Function &func);

	void analyze();
	void analyzeFunction(Function *func, std::stack<Function*> &stack_func);
	void analyzeVulnFunction(Function *func, std::string func_name);

	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void structToJson(json& output, const Vulnerability& vuln);
	void jsonToStruct(json input);

public:
	CodeAnalyzer(const std::string filename);
	virtual ~CodeAnalyzer();
};

#endif /* CODEANALYZER_H_ */
