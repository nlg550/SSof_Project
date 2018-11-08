#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <iostream>

#include "json.hpp" //JSON Library
#include "Function.hpp"

class CodeAnalyzer {
private:
	std::vector<Function> functions;

public:
	CodeAnalyzer();
	virtual ~CodeAnalyzer();

	void jsonToStruct(const json& input, Vulnerability& vuln);
	void readJSON(const std::string filename);
	void structToJson(json& output, const Vulnerability vuln);
	void writeJSON(const std::string filename, std::vector<Vulnerability> vuln);
	void analyze();

};

#endif /* CODEANALYZER_H_ */
