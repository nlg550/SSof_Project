# SSof_Project

The project was developed in C++ 14, using Eclipse Oxygen. To compile manually the code use the following commands:

g++ -std=c++1y -O0 -g3 -Wall -c -fmessage-length=0 -o CodeAnalyzer.o "..\\CodeAnalyzer.cpp" 
g++ -std=c++1y -O0 -g3 -Wall -c -fmessage-length=0 -o Registers.o "..\\Registers.cpp" 
g++ -std=c++1y -O0 -g3 -Wall -c -fmessage-length=0 -o main.o "..\\main.cpp" 
g++ -o SSof_Project.exe CodeAnalyzer.o Registers.o main.o 

To execute the program, use ./SSof_Project <name of the JSON (with the .json)>. The executable is on the Debug folder.
The output JSON will be created in the same folder and will have .output in the name.