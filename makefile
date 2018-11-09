CC = g++
VERSION = -std=c++1y
INC = -I. 
DEPS = CodeAnalyzer.hpp
OBJ = main.cpp CodeAnalyzer.cpp

main: main.o
	$(CC) $(VERSION) -o main $(OBJ) $(INC)
