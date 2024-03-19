#include "iphdr.h"
#include "tcphdr.h"

uint16_t	TcpHdr::calcCheckSum(IpHdr *ipHdr, TcpHdr *tcpHdr)
{
	uint16_t	*buf = (uint16_t *)tcpHdr;
	uint32_t	sum = 0;
	uint32_t	tlen = ipHdr->tlen() - ipHdr->hl() * 4;

	for (int i = 0; i < tlen / 2; i++)
		sum += ntohs(buf[i]);

	if (tlen % 2)
		sum += (*(uint8_t *)(buf + (tlen / 2)) << 8);

	sum -= tcpHdr->sum();
	sum += ipHdr->sip() >> 16;
	sum += ipHdr->sip() & 0x0000ffff;
	sum += ipHdr->dip() >> 16;
	sum += ipHdr->dip() & 0x0000ffff;
	sum += ipHdr->proto();
	sum += tlen;

	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return uint16_t(~sum);
}
