#include "airodump.h"

std::map<Mac, t_beacon_info>	beacon_map;
std::map<Mac, t_data_info>		data_map;
time_t							start_time = time(NULL);
// mutex
pthread_mutex_t					mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t					mutex2 = PTHREAD_MUTEX_INITIALIZER;

void	print_header()
{
	// get current time
	time_t		now = time(NULL);
	struct tm	*tm_now = localtime(&now);
	char		str_now[26];
	strftime(str_now, 26, "%Y-%m-%d %H:%M:%S", tm_now);
	
	// print header

	// TODO: channel hopping
	// printf("[ CH%3d ][ Elapsed: %d s ][ %s ]\n", 1, now - start_time, str_now);
	printf("\n[ CH ?? ][ Elapsed: %d s ][ %s ]\n\n", now - start_time, str_now);

	printf(" %17s %6s %8s %5s %10s %10s %9s  %s\n\n", "BSSID", "PWR", "Beacons", "CH", "ENC", "CIPHER", "AUTH", "ESSID");
}

void	print_header2()
{
	// BSSID, STATION, PWR, Rate, Lost, Frames, Notes, Probe
	printf("%17s %17s %5s %5s %5s %5s\n", "BSSID", "STATION", "PWR", "Rate", "Frames", "Probes");
}

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

int	isBeacon(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);

	if (dot11hdr->type() != Dot11Hdr::TYPE::MANAGEMENT || dot11hdr->subtype() != Dot11Hdr::SUBTYPE::BEACON)
		return (0);
	return (1);
}

int	isProbReq(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);

	if (dot11hdr->type() != Dot11Hdr::TYPE::MANAGEMENT || dot11hdr->subtype() != Dot11Hdr::SUBTYPE::PROBE_REQUEST)
		return (0);
	return (1);
}

int	isQosData(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);

	// printf("type: %d, subtype: %d\n", dot11hdr->type(), dot11hdr->subtype());
	if (dot11hdr->type() != Dot11Hdr::TYPE::DATA || dot11hdr->subtype() != Dot11Hdr::SUBTYPE::QOS_DATA)
		return (0);
	return (1);
}

void	*get_tags_from_beacon(BeaconHdr *beacon, int len, int tag, int *tag_len)
{
	u_char	*ptr = (u_char *)beacon + sizeof(BeaconHdr);
	
	while (ptr < (u_char *)beacon + len)
	{
		if (*ptr == tag)
		{
			*tag_len = *(ptr + 1);
			return (ptr + 2);
		}
		ptr = ptr + *(ptr + 1) + 2;
	}
	*tag_len = 0;
	return (0);
}

void	update_probreq(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);
	BeaconHdr	*beaconhdr = (BeaconHdr *)(packet + rtaphdr->len_ + sizeof(Dot11Hdr));
	int			beacon_len = len - rtaphdr->len_ + sizeof(Dot11Hdr) + sizeof(BeaconHdr);

	// get bssid
	Mac bssid_ = dot11hdr->addr3_;
	Mac station_ = dot11hdr->addr2_;
	// printf("bssid: %s, station: %s\n", std::string(bssid_).data(), std::string(station_).data());

	// check probreq is exist
	pthread_mutex_lock(&mutex2);
	if (data_map.find(station_) != data_map.end())
	{
		// update probreq count;
		data_map[station_].frames_++;
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				data_map[station_].power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				data_map[station_].power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}
		// update bssid if it is not breoadcast
		if (!bssid_.isBroadcast())
			data_map[station_].bssid_ = bssid_;
		// update prob
		int		prob_len = 0;
		u_char	*prob = (u_char *)get_tags_from_beacon(beaconhdr, beacon_len, 0, &prob_len);
		if (prob)
		{
			memset(data_map[station_].probs_, 0, 32);
			strncpy(data_map[station_].probs_, (char *)prob, prob_len);
		}
		pthread_mutex_unlock(&mutex2);
	}
	else
	{
		pthread_mutex_unlock(&mutex2);
		// create new probreq
		t_data_info	new_probreq;
		void *attr = 0; int attr_len = 0;
		memset(&new_probreq, 0, sizeof(t_data_info));

		new_probreq.frames_ = 1;
		new_probreq.bssid_ = bssid_;
		new_probreq.station_ = station_;
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				new_probreq.power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				new_probreq.power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}
		// rate
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::RATE)
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				new_probreq.rate_ = *(int8_t *)((u_char *)rtaphdr + 24 + 1);
			else
				new_probreq.rate_ = *(int8_t *)((u_char *)rtaphdr + 16 + 1);
		}
		// probs
		attr = get_tags_from_beacon(beaconhdr, beacon_len, 0, &attr_len);
		if (attr && attr_len > 0)
		{
			memset(new_probreq.probs_, 0, 32);
			memcpy(new_probreq.probs_, attr, attr_len);
		}
		// insert prob_req
		pthread_mutex_lock(&mutex2);
		data_map.insert(std::pair<Mac, t_data_info>(station_, new_probreq));
		pthread_mutex_unlock(&mutex2);
	}
}

void	update_qosdata(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);
	BeaconHdr	*beaconhdr = (BeaconHdr *)(packet + rtaphdr->len_ + sizeof(Dot11Hdr));
	int			beacon_len = len - rtaphdr->len_ + sizeof(Dot11Hdr) + sizeof(BeaconHdr);

	// get bssid
	Mac bssid_ = dot11hdr->addr2_;
	Mac station_ = dot11hdr->addr1_;
	// printf("bssid: %s, station: %s\n", std::string(bssid_).data(), std::string(station_).data());

	// check qos is exist
	pthread_mutex_lock(&mutex2);
	if (data_map.find(station_) != data_map.end())
	{
		// update qos count;
		data_map[station_].frames_++;
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				data_map[station_].power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				data_map[station_].power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}
		// update bssid if it is not breoadcast
		if (!bssid_.isBroadcast())
			data_map[station_].bssid_ = bssid_;
		// update prob
		int		prob_len = 0;
		u_char	*prob = (u_char *)get_tags_from_beacon(beaconhdr, beacon_len, 0, &prob_len);
		if (prob)
		{
			memset(data_map[station_].probs_, 0, 32);
			strncpy(data_map[station_].probs_, (char *)prob, prob_len);
		}
		pthread_mutex_unlock(&mutex2);
	}
	else
	{
		pthread_mutex_unlock(&mutex2);
		// create new qos
		t_data_info	new_qos;
		memset(&new_qos, 0, sizeof(t_data_info));

		new_qos.bssid_ = bssid_;
		new_qos.station_ = station_;
		new_qos.frames_ = 1;
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				new_qos.power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				new_qos.power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}

		// insert qos
		pthread_mutex_lock(&mutex2);
		data_map.insert(std::pair<Mac, t_data_info>(station_, new_qos));
		pthread_mutex_unlock(&mutex2);
	}
}

void	update_beacon(u_char *packet, int len)
{
	RadioTapHdr *rtaphdr = (RadioTapHdr *)packet;
	Dot11Hdr	*dot11hdr = (Dot11Hdr *)(packet + rtaphdr->len_);
	BeaconHdr	*beaconhdr = (BeaconHdr *)(packet + rtaphdr->len_ + sizeof(Dot11Hdr));
	int			beacon_len = len - rtaphdr->len_ + sizeof(Dot11Hdr) + sizeof(BeaconHdr);
	
	// get bssid
	Mac	bssid = dot11hdr->addr3_;
	// check beacon is exist
	pthread_mutex_lock(&mutex);
	if (beacon_map.find(bssid) != beacon_map.end())
	{
		// update beacon count;
		beacon_map[bssid].beacon_cnt_++;
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				beacon_map[bssid].power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				beacon_map[bssid].power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}
		pthread_mutex_unlock(&mutex);
	} else {
		pthread_mutex_unlock(&mutex);
		t_beacon_info	new_beacon;
		memset(&new_beacon, 0, sizeof(t_beacon_info));
		int				attr_len;
		void			*attr;

		new_beacon.bssid_ = bssid;
		new_beacon.beacon_cnt_ = 1;
		// dbm atenna signal
		// check antenna signal is present
		if (rtaphdr->present_ & RadioTapHdr::PRESENT::DBM_ANTENNA_SIGNAL)
		
		{
			// check if present is extended
			if (rtaphdr->present_ & RadioTapHdr::PRESENT::EXT)
				new_beacon.power_ = *(int8_t *)((u_char *)rtaphdr + 24 + 6);
			else
				new_beacon.power_ = *(int8_t *)((u_char *)rtaphdr + 16 + 6);
		}
		// essid
		attr = get_tags_from_beacon(beaconhdr, beacon_len, 0, &attr_len);
		if (attr_len > 0)
			memcpy(new_beacon.essid_, attr, attr_len);
		// RSN IE -> WPA2
		attr = get_tags_from_beacon(beaconhdr, beacon_len, 48, &attr_len);
		if (attr)
		{
			if (!memcmp(attr + 2, "\x00\x0F\xAC", 3))
			{
				new_beacon.encrypt_ |= BeaconHdr::ENC::WPA2;
				new_beacon.cipher_ |= *(uint8_t *)(attr + 5);
				// skip pairwise cipher
				int pair_cnt = (*(uint16_t *)(attr + 6));
				attr = attr + 8 + 4 * pair_cnt;
				// check AKM
				int akm_cnt = *(uint16_t *)(attr);
				attr = attr + 2;
				// DumpHex(attr, 4 * akm_cnt);
				for (int i = 0; i < akm_cnt; i++)
				{
					if (!memcmp(attr, "\x00\x0F\xAC", 3))
						new_beacon.auth_ |= *(uint8_t *)(attr + 3);
					attr = attr + 4;
				}
			}
		}
		// WPA IE -> WPA
		attr = get_tags_from_beacon(beaconhdr, beacon_len, 221, &attr_len);
		if (attr)
		{
			if (!memcmp(attr + 2, "\x00\0x50\xF2\x01\x01\x00", 7))
				new_beacon.encrypt_ |= BeaconHdr::ENC::WPA;
		}

		// Channel
		attr = get_tags_from_beacon(beaconhdr, beacon_len, 3, &attr_len);
		if (attr)
		{
			if (attr_len == 1)
				new_beacon.channel_ = *(uint8_t *)attr;
		}
		// insert beacon
		pthread_mutex_lock(&mutex);
		beacon_map.insert(std::pair<Mac, t_beacon_info>(bssid, new_beacon));
		pthread_mutex_unlock(&mutex);
	}
}

void	print_beacon()
{
	for (auto it = beacon_map.begin(); it != beacon_map.end(); it++)
	{
		// bssid
		printf(" %s   ", std::string(it->second.bssid_).data());
		// power
		printf("%4d   ", (int)it->second.power_);
		// beacon count
		printf("%6d   ", it->second.beacon_cnt_);
		// channel
		printf("%3d   ", it->second.channel_);
		// ENC
		switch (it->second.encrypt_)
		{
			case BeaconHdr::ENC::WPA_WPA2:
				printf("WPA/WPA2  ");
				break;
			case BeaconHdr::ENC::WPA:
				printf("     WPA  ");
				break;
			case BeaconHdr::ENC::WPA2:
				printf("    WPA2  ");
				break;
			default:
				printf("     OPN  ");
				break;
		}
		// cipher
		switch (it->second.cipher_)
		{
			case BeaconHdr::CIPHER::CCMP:
				printf("     CCMP  ");
				break;
			case BeaconHdr::CIPHER::TKIP:
				printf("     TKIP  ");
				break;
			case BeaconHdr::CIPHER::WEP_40:
				printf("    WEP40  ");
				break;
			case BeaconHdr::CIPHER::WEP_104:
				printf("   WEP104  ");
				break;
			default:
				printf("          ");
				break;
		}
		// auth
		switch (it->second.auth_)
		{
			case BeaconHdr::AKM::PSK:
				printf("     PSK  ");
				break;
			case BeaconHdr::AKM::DOT_1X:
				printf("  802.1X  ");
				break;
			default:
				printf("          ");
				break;
		}
		// ESSID
		printf("%s\n", it->second.essid_);
	}
}

void	print_data()
{
	for (auto it = data_map.begin(); it != data_map.end(); it++)
	{
		// bssid
		if (it->second.bssid_.isBroadcast())
			printf(" (not associated)   ");
		else
			printf(" %s   ", std::string(it->second.bssid_).data());
		// station
		printf("%s   ", std::string(it->second.station_).data());
		// power
		printf("%4d   ", (int)it->second.power_);
		// rate
		printf("%.1f   ", (float)(it->second.rate_ / 2.0));
		// frames
		printf("%6d   ", it->second.frames_);
		// prob
		printf("%s\n", it->second.probs_);
	}
}

void	update_screen(int sig)
{
	// clear screen
	printf("\033[2J");
	// move cursor to top left
	printf("\033[H");
	// print header
	print_header();
	// print beacon
	print_beacon();
	printf("\n\n");
	print_header2();
	// print prob_req
	print_data();

	ualarm(500000, 500000);
}

int	main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "syntax : %s <interface>\nsample : airodump mon0\n", argv[0]);
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

	// update screen every 0.5 sec
	signal(SIGALRM, update_screen);
	ualarm(500000, 500000);

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
		// check packet is not beacon or probe request
		if (isBeacon((u_char *)packet, header->len))
			update_beacon((u_char *)packet, header->len);
		else if (isProbReq((u_char *)packet, header->len))
			update_probreq((u_char *)packet, header->len);
		else if (isQosData((u_char *)packet, header->len))
			update_qosdata((u_char *)packet, header->len);
		else
			continue;
		// print_beacon();
		// printf("update...\n");
	}
	pcap_close(handle);
	pthread_mutex_destroy(&mutex);
	pthread_mutex_destroy(&mutex2);

	return (0);
}