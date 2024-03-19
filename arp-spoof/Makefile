CXX		= 	g++
# CXX		=	g++-12 # on macbook
CXXFLAGS= 	-std=c++11 #-Wall -Wextra -Werror
SRCS	= 	ft_list.cpp arphdr.cpp ethhdr.cpp ip.cpp mac.cpp iphdr.cpp main.cpp
NAME	=	arp-spoof
HEADERS	=	arp_spoof.h arphdr.h ethhdr.h ip.h mac.h iphdr.h
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
