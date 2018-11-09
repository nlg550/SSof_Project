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

#define N_VULN_FUNC 11

using json = nlohmann::json;

class CodeAnalyzer {
private:
	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

public:
	CodeAnalyzer();
	virtual ~CodeAnalyzer();

	void jsonToStruct(const json& input, std::vector<Function>& functions);
	void readJSON(const std::string filename);
	void structToJson(json& output, const Vulnerability& vuln);
	void writeJSON(const std::string filename);
	void analyze();

};

#endif /* CODEANALYZER_H_ */
