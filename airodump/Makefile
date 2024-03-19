CXX		= 	g++
# CXX	=	g++-12 # on macbook
CXXFLAGS= 	-std=c++11 #-Wall -Wextra -Werror
SRCS	= 	airodump.cpp radiotaphdr.cpp mac.cpp dot11hdr.cpp
NAME	=	airodump
HEADERS	=	airodump.h radiotaphdr.h mac.h dot11hdr.h
OBJS	=	$(SRCS:.cpp=.o)
RM		=	rm -f

$(NAME) : $(OBJS) $(HEADERS)
			$(CXX) -o $(NAME) $(CXXFLAGS) $(OBJS) -lpcap -lpthread

all	: $(NAME)

clean:
	$(RM) $(OBJS)
	$(RM) $(NAME)

re:
	$(MAKE) clean
	$(MAKE) all

.PHONY : all clean re
