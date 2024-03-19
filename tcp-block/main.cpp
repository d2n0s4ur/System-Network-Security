#include "tcp-block.h"

t_info	MyInfo;

// for dump packet
void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

int	getMyInfo(t_info *MyInfo, char *dev)
{
	struct ifreq	data;
   	int				fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(data.ifr_name, dev);
	// get MAC addr
	if (!ioctl(fd, SIOCGIFHWADDR, &data))
		MyInfo->mac = Mac((uint8_t *)data.ifr_hwaddr.sa_data);
	else
		return (1);
	if (!ioctl(fd, SIOCGIFADDR, &data))
		MyInfo->ip = Ip(ntohl(((struct sockaddr_in*)&data.ifr_addr)->sin_addr.s_addr));
	else
		return (1);
	printf("[INFO] My mac addr: %s\n", std::string(MyInfo->mac).data());
	printf("[INFO] My ip  addr: %s\n", std::string(MyInfo->ip).data());
	close(fd);

	return (0);
}


char	*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	size_t	i;
	size_t	j;
	size_t	offset;

	if (strlen(needle) == 0)
		return ((char *)haystack);
	i = 0;
	while (haystack[i] != '\0' && i < len)
	{
		if (haystack[i] == needle[0])
		{
			offset = i;
			j = 0;
			while (haystack[i + j] != '\0' && haystack[i + j] == needle[j] \
				&& i + j < len)
				j++;
			if (j == strlen(needle))
				return ((char *)haystack + offset);
		}
		i++;
	}
	return (0);
}

int	isTCP(const u_char *packet)
{
	EthHdr	*ethHdr = (EthHdr *)packet;
	if (ethHdr->type() != EthHdr::Ip4)
		return (0);
	IpHdr	*ipHdr = (IpHdr *)(packet + sizeof(EthHdr));
	if (ipHdr->proto() != IpHdr::TCP)
		return (0);
	TcpHdr	*tcpHdr = (TcpHdr *)(packet + sizeof(EthHdr) + ipHdr->hl() * 4);
	return (1);
}

int	isBlock(const u_char *packet, const char *pattern)
{
	EthIpTcpHdr	*ethIpTcpHdr = (EthIpTcpHdr *)packet;
	char	*data = (char *)(packet + sizeof(EthHdr) + ethIpTcpHdr->ipHdr_.hl() * 4 + ethIpTcpHdr->tcpHdr_.off() * 4);
	int		dataLen = ethIpTcpHdr->ipHdr_.tlen() - ethIpTcpHdr->ipHdr_.hl() * 4 - ethIpTcpHdr->tcpHdr_.off() * 4;

	if (dataLen <= 0)
		return (0);
	if (ethIpTcpHdr->ipHdr_.sip() != MyInfo.ip || ethIpTcpHdr->tcpHdr_.dport() != 80)
		return (0);
	if (ft_strnstr(data, pattern, dataLen))
		return (1);
	return (0);
};

int	SendForwardPacket(pcap_t *handle, const u_char *old_packet, unsigned int packet_len)
{
	EthIpTcpHdr *org_packet = (EthIpTcpHdr *)old_packet;
	int	dataLen = org_packet->ipHdr_.tlen() - org_packet->ipHdr_.hl() * 4 - org_packet->tcpHdr_.off() * 4;
	// printf("dataLen: %d\n", dataLen);

	// make new packet
	u_char	*new_packet = (u_char *)malloc(packet_len);
	if (!new_packet)
	{
		fprintf(stderr, "Error: malloc failed\n");
		exit(1);
	}
	memcpy(new_packet, old_packet, packet_len);
	// set forward packet
	EthIpTcpHdr *fwd_packet = (EthIpTcpHdr *)new_packet;

	// ethernet header
	fwd_packet->ethHdr_.smac_ = MyInfo.mac;
	// ip header
	fwd_packet->ipHdr_.tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
	// tcp header
	fwd_packet->tcpHdr_.seq_ = htonl(org_packet->tcpHdr_.seqno() + dataLen);
	fwd_packet->tcpHdr_.off_ = (sizeof(TcpHdr) / 4) << 4;
	fwd_packet->tcpHdr_.flags_ = TcpHdr::RST | TcpHdr::ACK;
	fwd_packet->tcpHdr_.flags_ &= ~TcpHdr::SYN;

	// checksum
	fwd_packet->ipHdr_.sum_ = htons(IpHdr::calcCheckSum(&(fwd_packet->ipHdr_)));
	fwd_packet->tcpHdr_.sum_ = htons(TcpHdr::calcCheckSum(&(fwd_packet->ipHdr_), &(fwd_packet->tcpHdr_)));

	// send forward packet

	int result = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(fwd_packet), sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));
	if (result != 0)
	{
		fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", result, pcap_geterr(handle));
		free(new_packet);
		return (0);
	}
	free(new_packet);
	return (1);
}

int	SendBackwardPacket(pcap_t *handle, const u_char *old_packet, unsigned int packet_len)
{
	char	redirection_data[80];
	memset(redirection_data, 0, 80);
	memcpy(redirection_data, "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr/i1.html\r\n\r\n", 66);

	EthIpTcpHdr *org_packet = (EthIpTcpHdr *)old_packet;
	int	dataLen = org_packet->ipHdr_.tlen() - org_packet->ipHdr_.hl() * 4 - org_packet->tcpHdr_.off() * 4;

	// make new packet
	u_char	*new_packet = (u_char *)malloc(packet_len);
	if (!new_packet)
	{
		fprintf(stderr, "Error: malloc failed\n");
		exit(1);
	}
	memcpy(new_packet, old_packet, packet_len);

	// set backward packet
	EthIpTcpHdr *bwd_packet = (EthIpTcpHdr *)new_packet;
	// ethernet header
	bwd_packet->ethHdr_.smac_ = MyInfo.mac;
	bwd_packet->ethHdr_.dmac_ = org_packet->ethHdr_.smac_;
	// ip header
	bwd_packet->ipHdr_.tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr) + strlen(redirection_data));
	bwd_packet->ipHdr_.ttl_ = 128;
	bwd_packet->ipHdr_.dip_ = org_packet->ipHdr_.sip_;
	bwd_packet->ipHdr_.sip_ = org_packet->ipHdr_.dip_;
	// tcp header
	bwd_packet->tcpHdr_.sport_ = org_packet->tcpHdr_.dport_;
	bwd_packet->tcpHdr_.dport_ = org_packet->tcpHdr_.sport_;
	bwd_packet->tcpHdr_.seq_ = org_packet->tcpHdr_.ack_;
	bwd_packet->tcpHdr_.ack_ = htonl(org_packet->tcpHdr_.seqno() + (uint32_t)dataLen);
	bwd_packet->tcpHdr_.off_ = (sizeof(TcpHdr) / 4) << 4;
	bwd_packet->tcpHdr_.flags_ |= TcpHdr::FIN | TcpHdr::ACK;
	bwd_packet->tcpHdr_.flags_ &= ~TcpHdr::SYN;

	// data
	memcpy((char *)(new_packet + sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)), redirection_data, strlen(redirection_data));

	// checksum
	bwd_packet->ipHdr_.sum_ = htons(IpHdr::calcCheckSum(&(bwd_packet->ipHdr_)));
	bwd_packet->tcpHdr_.sum_ = htons(TcpHdr::calcCheckSum(&(bwd_packet->ipHdr_), &(bwd_packet->tcpHdr_)));

	// send backward packet using raw socket
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = bwd_packet->tcpHdr_.dport_;
	sin.sin_addr.s_addr = bwd_packet->ipHdr_.dip_;

	// DumpHex(new_packet, packet_len);
	// printf("seq: %u, ack: %u\n", bwd_packet->tcpHdr_.seqno(), bwd_packet->tcpHdr_.ackno());
	// pcap_sendpacket(handle, new_packet, sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr) + strlen(redirection_data) + 1);
	int result = sendto(MyInfo.sock, &(bwd_packet->ipHdr_), bwd_packet->ipHdr_.tlen(), 0, (struct sockaddr *)&sin, sizeof(sin));
	if (result < 0)
	{
		fprintf(stderr, "Error: sendto return %d error=%s\n", result, strerror(errno));
		free(new_packet);
		return (0);
	}
	free(new_packet);
	return (1);
}

int	doBlock(pcap_t *handle, const u_char *old_packet, unsigned int packet_len)
{
	int result1 = SendForwardPacket(handle, old_packet, packet_len);
	int result2 = SendBackwardPacket(handle, old_packet, packet_len);

	if (!result1 || !result2)
		return (0);
	return (1);
}

int	main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "syntax : %s <interface> <pattern>\nsample : tcp-block wlan0 \"Host: test.gilgil.net\"", argv[0]);
		return (1);
	}
	char	*dev = argv[1];
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!handle)
	{
		fprintf(stderr, "Error: Couldn't open device %s(%s)\n", dev, errbuf);
		return (1);
	}
	if (getMyInfo(&MyInfo, dev))
	{
		fprintf(stderr, "Error: getMyInfo failed\n");
		return (1);
	}

	// create raw socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
	{
		fprintf(stderr, "Error: socket failed\n");
		exit(1);
	}
	// set socket option
	int optval = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (int *)&optval, sizeof(int));
	MyInfo.sock = sock;

	// receive packet
	struct pcap_pkthdr	*header;
	const u_char		*packet;

	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			continue;
		}
		if (!isTCP(packet))
			continue;
		if (!isBlock(packet, argv[2]))
			continue;
		printf("Try Block...\n");
		if (doBlock(handle, packet, header->caplen))
			printf("Block Packet by pattern:[%s]\n", argv[2]);
		else
			printf("Block Fail\n");
	}
	pcap_close(handle);
	close(sock);

	return (0);
}