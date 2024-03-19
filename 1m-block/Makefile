CXX		= 	g++
# CXX		=	g++-12 # on macbook
CXXFLAGS= 	#-Wall -Wextra -Werror
SRCS	= 	main.cpp
NAME	=	1m-block
HEADERS	=	1m-block.h
OBJS	=	$(SRCS:.cpp=.o)
RM		=	rm -f

$(NAME) : $(OBJS) $(HEADERS)
			$(CXX) -o $(NAME) $(CXXFLAGS) $(OBJS) -lnetfilter_queue

all	: $(NAME)

clean:
	$(RM) $(OBJS)
	$(RM) $(NAME)

re:
	$(MAKE) clean
	$(MAKE) all

.PHONY : all clean re

