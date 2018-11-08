#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <iostream>

#include "json.hpp" //JSON Library
#include "StructDefinition.hpp"

class CodeAnalyzer {
private:
	const std::string dangerous_functions[] = { "gets", "strcpy", "strcat", "sprintf",
			"scanf", "fscanf", "fgets", "strncpy", "strncat", "snprintf", "read" };

	MemoryStack stack;
	Registers regs;

	std::map<std::string, Function> functions;
	std::vector<Vulnerability> vulnerabilities;

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
