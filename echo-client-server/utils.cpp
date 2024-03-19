#include "chat.h"

int	create_socket(void)
{
	int	ret;

	ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret == -1) // detecting error when create socket
		fprintf(stderr, "Error occured while creating socket : %s\n", strerror(errno));
	return (ret);
}

void	print_connection(struct sockaddr_in info)
{
	printf("Connection from %s:%u\n", inet_ntoa(info.sin_addr), info.sin_port);
}

void	set_sock(struct sockaddr_in *socket, in_addr_t addr, u_short port)
{
	memset(socket, 0, sizeof(*socket));
	socket->sin_family = AF_INET;
	socket->sin_addr.s_addr = addr;
	socket->sin_port = port;
}
