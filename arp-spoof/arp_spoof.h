#ifndef ARP_SPOOF_H
# define ARP_SPOOF_H

# include <stdio.h>
# include <unistd.h>
# include <pcap.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include "arphdr.h"
# include "ethhdr.h"
# include "iphdr.h"
# include "ip.h"
# include "mac.h"
# include <pthread.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

typedef struct s_info {
	Mac	mac;
	Ip	ip;
}	t_info;

typedef struct s_spoof {
	pcap_t			*handle;
	t_info			Attacker;
	t_info			Sender;
	t_info			Target;
	pthread_t		thread;
}	t_spoof;

typedef struct s_list {
	t_spoof			content;
	struct s_list	*next;
}	t_list;

t_list	*ft_lstnew(t_spoof *content);
void	ft_lstadd(t_list **lst, t_list *node);
void	ft_lstclear(t_list **lst);

#endif