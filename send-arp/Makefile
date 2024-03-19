CXX		= 	g++
# CXXFLAGS= 	-Wall -Wextra -Werror
SRCS	= 	arphdr.cpp ethhdr.cpp ip.cpp mac.cpp utils.cpp main.cpp
NAME	=	send-arp
HEADERS	=	send_arp.h arphdr.h ethhdr.h ip.h mac.h
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