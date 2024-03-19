#include "iphdr.h"

uint16_t	IpHdr::calcCheckSum(IpHdr *ipHdr)
{
	uint16_t	*buf = (uint16_t *)ipHdr;
	uint32_t	sum = 0;

	for (int i = 0; i < ipHdr->hl() * 2; i++)
		sum += ntohs(buf[i]);

	sum -= ipHdr->sum();
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return uint16_t(~sum);
}