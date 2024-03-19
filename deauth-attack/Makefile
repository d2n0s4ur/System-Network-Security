CXX		= 	g++
# CXX	=	g++-12 # on macbook
CXXFLAGS= 	-std=c++11 #-Wall -Wextra -Werror
SRCS	= 	deauth.cpp mac.cpp beaconhdr.cpp dot11hdr.cpp radiotaphdr.cpp
NAME	=	deauth-attack
HEADERS	=	deauth.h mac.h beaconhdr.h dot11hdr.h radiotaphdr.h
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
