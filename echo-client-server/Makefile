CC			= gcc
CFLAGS		= -pthread # -Wall -Werror -Wextra
RM			= rm -f

UTIL_SRCS	= utils.cpp
SERVER_SRCS	= $(UTIL_SRCS) server.cpp
CLIENT_SRCS	= $(UTIL_SRCS) client.cpp
SERVER_OBJS	= $(SERVER_SRCS:.cpp=.o)
CLIENT_OBJS	= $(CLIENT_SRCS:.cpp=.o)

SERVER		= echo-server
CLIENT		= echo-client

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(SERVER_OBJS) -o $(SERVER)

$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(CLIENT_OBJS) -o $(CLIENT)

clean:
	$(RM) $(SERVER_OBJS) $(CLIENT_OBJS)

fclean: clean
	$(RM) $(SERVER) $(CLIENT)

re: fclean all

.PHONY: all clean fclean re