#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <map>
#include <string>
#include <vector>
#include <stack>
#include <iostream>
#include <fstream>
#include <tuple>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdint.h>

#include "json.hpp" //JSON Library
#include "Registers.hpp"
#include "StructDefinition.hpp"

#define N_DANGEROUS_FUNC 11

using json = nlohmann::json;

class CodeAnalyzer {
private:
	MemoryStack mem_stack;
	Registers reg;

	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

	void allocFunction(Function &func, uint64_t return_addr);
	void desallocFunction(Function &func);
	void analyze();
	void analyzeFunction(Function *func, std::stack<Function*> &stack_func);
	void analyzeCalledFunction(Function *func, std::string func_name);
	void analyzeOverflow(Function *func, std::string func_name, Variable *arg, int overflow);

	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void structToJson(json& output, const Vulnerability& vuln);
	void jsonToStruct(json input);

public:
	CodeAnalyzer(const std::string filename);
	virtual ~CodeAnalyzer();
};

#endif /* CODEANALYZER_H_ */
