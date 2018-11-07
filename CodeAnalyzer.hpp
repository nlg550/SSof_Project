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

	void readJSON(const std::string filename);
	void writeJSON(const std::string filename);
	void analyze();

};

#endif /* CODEANALYZER_H_ */
