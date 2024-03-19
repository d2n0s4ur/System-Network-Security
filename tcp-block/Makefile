CXX		= 	g++
# CXX	=	g++-12 # on macbook
CXXFLAGS= 	-std=c++11 #-Wall -Wextra -Werror
SRCS	= 	main.cpp ip.cpp iphdr.cpp tcphdr.cpp ethhdr.cpp mac.cpp
NAME	=	tcp-block
HEADERS	=	tcp-block.h ip.h iphdr.h tcphdr.h ethhdr.h mac.h
OBJS	=	$(SRCS:.cpp=.o)
RM		=	rm -f

$(NAME) : $(OBJS) $(HEADERS)
			$(CXX) -o $(NAME) $(CXXFLAGS) $(OBJS) -lpcap

all	: $(NAME)

clean:
	$(RM) $(OBJS)
	$(RM) $(NAME)

re:
	$(MAKE) clean
	$(MAKE) all

.PHONY : all clean re
