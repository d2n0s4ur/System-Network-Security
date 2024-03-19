#ifndef TCP_BLOCK_H
# define TCP_BLOCK_H

# include <stdio.h>
# include <unistd.h>
# include <pcap.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include "iphdr.h"
# include "ip.h"
# include "ethhdr.h"
# include "mac.h"
# include "tcphdr.h"
# include <pthread.h>
# include <sys/socket.h>
# include <linux/if_packet.h>
# include <net/ethernet.h>

#pragma pack(push, 1)
typedef struct EthIpTcpHdr final
{
	EthHdr	ethHdr_;
	IpHdr	ipHdr_;
	TcpHdr	tcpHdr_;
}	EthIpTcpHdr;
#pragma pack(pop)

typedef struct s_info {
	Mac	mac;
	Ip	ip;
	int sock;
	// struct ifreq if_idx;
}	t_info;

#endif