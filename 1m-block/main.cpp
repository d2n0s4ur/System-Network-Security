#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include "1m-block.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <set> // for site list(BST)
std::set<std::string> site_list;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph; 

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	return id;
}
	
// callback function
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");

	// check if the packet is from or to host
	unsigned char	*packet_data;
	int				len;

	len = nfq_get_payload(nfa, &packet_data);
	if (len >= 0)
	{
		IpHdr *ip_hdr = (IpHdr *)packet_data;
		// check IPv4 and TCP
		if (ip_hdr->v() == 4 && ip_hdr->proto() == IpHdr::TCP)
		{
			// check http packet
			TcpHdr *tcp_hdr = (TcpHdr *)(packet_data + ip_hdr->hl() * 4);
			if (tcp_hdr->sport() == 80 || tcp_hdr->dport() == 80)
			{
				unsigned char *http_data = (unsigned char *)tcp_hdr + tcp_hdr->off() * 4;
				int http_len = len - ip_hdr->hl() * 4 - tcp_hdr->off() * 4;

				// check host
				if (http_len > 0)
				{
					if (strstr((char *)http_data, "Host: "))
					{
						char *packet_host = strstr((char *)http_data, "Host: ") + 6;
						// remove \r\n
						int i = 0;
						while (*(packet_host + i))
						{
							if (*(packet_host + i) == '\r' || *(packet_host + i) == '\n')
							{
								*(packet_host + i) = 0;
								break ;
							}
							i++;
						}
						// check if the host is in the site list
						if (site_list.find(packet_host) != site_list.end())
						{
							printf("blocked site: %s\n", packet_host);
							return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
						}
						else
							printf("host: [%s]\n", packet_host);
					}
				}
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
		fprintf(stderr, "Sample: %s top-1m.txt\n", argv[0]);
		exit(1);
	}

	// read site list file
	FILE *fp = fopen(argv[1], "r");
	if (!fp)
	{
		fprintf(stderr, "Error: cannot open file %s\n", argv[1]);
		exit(1);
	}
	// read line by line
	char line[256];
	memset(line, 0, sizeof(line));
	while (fgets(line, sizeof(line), fp))
	{
		// remove \n
		line[strlen(line) - 1] = '\0';
		site_list.insert(strchr(line, ',') + 1);
		memset(line, 0, sizeof(line));
	}
	fclose(fp);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);
	site_list.clear(); // memory free

	exit(0);
}
