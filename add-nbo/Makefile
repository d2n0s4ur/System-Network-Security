# Makefile
CXX	= g++
CXXFLAGS= -Wall -Wextra -Werror
NAME	= add-nbo

all	: $(NAME)

$(NAME) : add.o main.o
	$(CXX) $(CXXFLAGS) add.o main.o -o $(NAME)

add.o	: add.cpp add-nbo.h
	g++ -o add.o -c add.cpp

main.o	: main.cpp add-nbo.h
	g++ -o main.o -c main.cpp

clean:
	rm -f add.o main.o
	rm -f $(NAME)

re:
	make clean
	make all

.PHONY : all clean re
