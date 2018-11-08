#ifndef CODEANALYZER_H_
#define CODEANALYZER_H_

#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <iostream>

#include "json.hpp" //JSON Library
#include "StructDefinition.hpp"
<<<<<<< Updated upstream

class CodeAnalyzer {
private:
	const std::string dangerous_functions[] = { "gets", "strcpy", "strcat", "sprintf",
			"scanf", "fscanf", "fgets", "strncpy", "strncat", "snprintf", "read" };

	MemoryStack stack;
	Registers regs;

	std::map<std::string, Function> functions;
=======

using json = nlohmann::json;

class CodeAnalyzer {
private:
	std::vector<Function> functions;
	//All the vulnerabilities found
>>>>>>> Stashed changes
	std::vector<Vulnerability> vulnerabilities;

public:
	CodeAnalyzer(const std::string filename);
	virtual ~CodeAnalyzer();

	void jsonToStruct(const json& input, std::vector<Function>& functions);
	void readJSON(const std::string filename);
	void structToJson(json& output, const Vulnerability& vuln);
	void writeJSON(const std::string filename);
	void analyze();

};

#endif /* CODEANALYZER_H_ */
