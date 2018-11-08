CC = g++
VERSION = -std=c++1y
INC = -I. 
DEPS = CodeAnalyzer.hpp
OBJ = main.o CodeAnalyzer.o

%.o: %.c $(DEPS)
	$(CC) $(VERSION) -c -o $@ $< $(INC)

main: $(OBJ)
	$(CC) $(VERSION) -o $@ $^ $(INC)
