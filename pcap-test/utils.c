#include <stdio.h>
#include "pcap-test.h"

void	print_mac_addr(void *addr)
{
	uint8_t	*mac_addr;

	mac_addr = (uint8_t *)addr;
	printf("%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

void	print_ip_addr(t_ip_addr ip)
{
	printf("%u:%u:%u:%u", ip.byte[0], ip.byte[1], ip.byte[2], ip.byte[3]);
}

void	print_payload(const unsigned char *addr, int len)
{
	int	cnt;

	cnt = 10;
	if (len == 0)
	{
		printf("None");
		return ;
	}
	if (len < 10) cnt = len;
	while (*addr && cnt > 0)
	{
		printf("%02x ", *addr);
		cnt--;
		addr++;
	}
	if (len > 10) printf("...");
}
