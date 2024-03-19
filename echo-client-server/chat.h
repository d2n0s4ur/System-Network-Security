#ifndef CHAT_H
# define CHAT_H

# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <sys/un.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <unistd.h>
# include <stdlib.h>
# include <errno.h>
# include <string.h>
# include <pthread.h>
# include <stdio.h>

# define BUFFER_SIZE 2048
# define MAX_CLIENT 10

typedef struct	s_socket {
	int					socket_fd;
	struct sockaddr_in	socket_addr;
}	t_socket;

int		create_socket(void);
void	print_connection(struct sockaddr_in info);
void	set_sock(struct sockaddr_in *socket, in_addr_t addr, u_short port);

#endif