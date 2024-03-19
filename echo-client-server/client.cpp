#include "chat.h"

int			recv_size, send_size;
t_socket	client;
char		send_buffer[BUFFER_SIZE + 1], recv_buffer[BUFFER_SIZE + 1];
pthread_t	send_threadID, recv_threadID;
void		*send_ret, *recv_ret;

void	*sendRoutine(void *arg)
{
	// loop while send QUIT msg
	while (1)
	{
		// initailize buffer as 0(NULL)
		memset(send_buffer, 0, BUFFER_SIZE + 1);

		// get data from std input
		send_size = read(0, send_buffer, BUFFER_SIZE);

		if (send_size <= 0) // error occurs at std input -> thread end
		{
			pthread_cancel(recv_threadID); // cancel recv thread before close socket fd
			close(client.socket_fd); // close socket fd
			fprintf(stderr, "Error occured while std input : %s\n", strerror(errno)); // error msg print
			return (NULL);
		}
		if (send(client.socket_fd, send_buffer, send_size + 1, 0) == -1) // error occurs when sending data
		{
			pthread_cancel(recv_threadID); // cancel recv thread before close socket fd
			close(client.socket_fd); // close socket fd
			fprintf(stderr, "Error occured while sending data : %s\n", strerror(errno)); // error msg print
			return (NULL);
		}
		if (strncmp(send_buffer, "QUIT\n", 5) == 0 && send_size == 5) // when send "QUIT" -> disconnect
		{
			printf("disconnected\n"); // print disconnect msg to std output
			pthread_cancel(recv_threadID); // cancel recv thread before close socket fd
			close(client.socket_fd); // close socket fd
			return (NULL);
		}
	}
}

void	*recvRoutine(void *arg)
{
	while (1)
	{
		// initialize buffer as 0(NULL)
		memset(recv_buffer, 0, BUFFER_SIZE + 1);

		// recv data from server
		recv_size = recv(client.socket_fd, recv_buffer, BUFFER_SIZE, 0);

		// detect error when recv data from server
		if (recv_size < 0) // error occurs at recv data
		{
			pthread_cancel(send_threadID); // cancel send thread before close socket fd
			close(client.socket_fd); // close socket fd
			fprintf(stderr, "Error occured while recv data : %s\n", strerror(errno)); // error msg print
			return (NULL);
		}

		// print recved data to std output
		printf("%s", recv_buffer);
	}
}

int	main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "syntax: %s <ip> <port>\nsmaple: echo-client 192.168.10.2 1234\n", argv[0]);
		return (1);
	}

	client.socket_fd = create_socket();
	if (client.socket_fd == -1)
		return (1);
	set_sock(&(client.socket_addr), inet_addr(argv[1]), (u_short)atol(argv[2]));

	// Connect socket
	if (connect(client.socket_fd, (struct sockaddr *)(&(client.socket_addr)), sizeof(client.socket_addr)) < 0)
	{
		fprintf(stderr, "Error occured while connect to server : %s\n", strerror(errno));
		return (1);
	}

	// send Thread Create
	if (pthread_create(&send_threadID, NULL, sendRoutine, NULL) != 0)
	{
		fprintf(stderr, "Error occured while create thread : %s\n", strerror(errno));
		return (1);
	}
	// recv Thread Create
	if (pthread_create(&recv_threadID, NULL, recvRoutine, NULL) != 0)
	{
		fprintf(stderr, "Error occured while create thread : %s\n", strerror(errno));
		return (1);
	}

	// thread join -> when thread ends, send_ret & recv_ret set.
	pthread_join(send_threadID, &send_ret);
	pthread_join(recv_threadID, &recv_ret);

	// when thread cancled (it means somthing wrong while connection)
	if (send_ret == PTHREAD_CANCELED || recv_ret == PTHREAD_CANCELED)
		return (1);

	return (0);
}