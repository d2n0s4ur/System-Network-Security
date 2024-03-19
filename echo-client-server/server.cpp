#include "chat.h"

t_socket 			server;
int					client_cnt = 0;
t_socket			client[MAX_CLIENT];
struct sockaddr_in	client_addr;
int					client_len = sizeof(struct sockaddr_in);
pthread_mutex_t		mutex;
int					is_echo, is_broadcast;

void	remove_client(int fd)
{
	//calc client index
	int index = 0;
	while (client[index].socket_fd != fd)
		index++;

	// Critical section
	pthread_mutex_lock(&mutex);
	while (index < client_cnt - 1)
	{
		client[index] = client[index + 1];
		index++;
	}
	client_cnt--;
	pthread_mutex_unlock(&mutex);
}

void	send_msg(char *str, int from)
{
	int i;

	i = 0;
	printf("%s", str); // print msg to std output

	if (is_echo)
		send(from, str, strlen(str) + 1, 0); // echo msg to client(from)
	if (!is_broadcast)
		return ;
	// Critical section
    pthread_mutex_lock(&mutex);
    while (i < client_cnt)
	{
		if (client[i].socket_fd != from)
        	send(client[i].socket_fd, str, strlen(str) + 1, 0); // broadcast msg except fd(except)
		i++;
	}
    pthread_mutex_unlock(&mutex);
}

void	*recvRoutine(void *arg)
{
	t_socket	argclient = *((t_socket *)arg);
	char		recv_buffer[BUFFER_SIZE + 1];
	int			recv_size;
	char		send_buffer[BUFFER_SIZE + 20];
	
	// broadcast client connect info
	sprintf(send_buffer, "%s:%u is connected.\n", inet_ntoa(argclient.socket_addr.sin_addr), argclient.socket_addr.sin_port);
	send_msg(send_buffer, argclient.socket_fd);

	// recv msg until "QUIT" recved
	while(1)
	{
		memset(recv_buffer, 0, BUFFER_SIZE + 1); // initialization buffer

		recv_size = recv(argclient.socket_fd, recv_buffer, BUFFER_SIZE, 0); // recv msg from client

		if (recv_size <= 0 || (strncmp(recv_buffer, "QUIT\n", 5) == 0 && recv_size == 6)) // when recv "QUIT" or detect error(ex. Ctrl-C) -> disconnect
		{
			// broadcast client disconnect info except client
			sprintf(send_buffer, "%s:%u is disconnected.\n", inet_ntoa(argclient.socket_addr.sin_addr), argclient.socket_addr.sin_port);
			send_msg(send_buffer, argclient.socket_fd);

			remove_client(argclient.socket_fd); // remove client fd from client fd arr
			close(argclient.socket_fd); // close client socket fd
			return (NULL);
		}
		sprintf(send_buffer, "%s:%u : %s", inet_ntoa(argclient.socket_addr.sin_addr), argclient.socket_addr.sin_port, recv_buffer);
		send_msg(send_buffer, argclient.socket_fd);
	}
	return (NULL);
}

int	main(int argc, char *argv[])
{
	pthread_t	recv_threadID;
	int			fd;

	if (argc < 2 || argc > 4)
	{
		fprintf(stderr, "syntax : %s <port> [-e[-b]]\nsample : echo-server 1234 -e -b\n", argv[0]);
		return (1);
	}

	// check options
	for (int i = 2; i < argc; i++)
	{
		if (!strcmp(argv[i], "-e"))
			is_echo = 1;
		else if (!strcmp(argv[i], "-b"))
			is_broadcast = 1;
		else
		{
			fprintf(stderr, "syntax : %s <port> [-e[-b]]\nsample : echo-server 1234 -e -b\n", argv[0]);
			return (1);
		}
	}

	// Create Socket
	server.socket_fd = create_socket();
	set_sock(&(server.socket_addr), htonl(INADDR_ANY), (u_short)atoi(argv[1]));

	// Bind Socket
	if (bind(server.socket_fd, (struct sockaddr *)&(server.socket_addr), sizeof(server.socket_addr)) == -1)
	{
		fprintf(stderr, "Error occured while bind socket : %s\n", strerror(errno));
		return (1);
	}
	// Make socket as usable. set pending connection queue length
	if (listen(server.socket_fd, MAX_CLIENT) == -1)
	{
		fprintf(stderr, "Error occured while listen socket : %s\n", strerror(errno));
		return (1);
	}

	// mutext init -> for critical section
	pthread_mutex_init(&mutex, NULL);
	while (1)
	{
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		// accept client's connect requset
		fd = accept(server.socket_fd, (struct sockaddr *)(&client_addr), (socklen_t *)(&client_len));
		if (client_cnt >= MAX_CLIENT) // when client count over MAX_CLIENT(5)
		{
			close(fd); // close
			continue;
		}
		if (fd == -1) // wrong accept
		{
			fprintf(stderr, "Error occured while accept socket : %s\n", strerror(errno));
			break;
		}
		print_connection(client_addr); // print client's IP & Port

		// Critical section - add client info to client arr
		pthread_mutex_lock(&mutex);
		memcpy(&client[client_cnt].socket_addr, &client_addr, sizeof(struct sockaddr_in));
		client[client_cnt++].socket_fd = fd;
		pthread_mutex_unlock(&mutex);
		
		// recv Thread Create
		if (pthread_create(&recv_threadID, NULL, recvRoutine, (void *)&client[client_cnt - 1]) < 0)
		{
			fprintf(stderr, "Error occured while create thread : %s\n", strerror(errno));
			break;
		}

		//thread detach -> when thread end, return resources
		pthread_detach(recv_threadID);
	}
	// mutext distroy
	pthread_mutex_destroy(&mutex);

	return (0);
}
