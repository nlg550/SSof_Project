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

using json = nlohmann::json;

class CodeAnalyzer {
private:
	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

	Variable* backtrackingVar(std::stack<Function*> f_stack, std::string tracking);
	int backtrackingConst(std::stack<Function*> f_stack, std::string tracking);
	void structToJson(json& output, const Vulnerability& vuln);
	void jsonToStruct(const json& input, std::vector<Function>& functions);

public:
	CodeAnalyzer();
	virtual ~CodeAnalyzer();
	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void analyze();


};

#endif /* CODEANALYZER_H_ */
