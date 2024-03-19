#ifndef AIRODUMP_H
# define AIRODUMP_H

# include <stdio.h>
# include <time.h>
# include <string.h>
# include <pcap.h>
# include <map>
# include <signal.h>
# include "radiotaphdr.h"
# include "mac.h"
# include "dot11hdr.h"
# include "beaconhdr.h"
# include <pthread.h>

# define MAX_BEACON	100

typedef struct s_beacon_info
{
	Mac		bssid_;
	int8_t	power_;
	int		beacon_cnt_;
	int		data_cnt_;
	int		channel_;
	int		encrypt_;
	int		cipher_;
	int		akm_;
	int		auth_;
	char	essid_[32];

}	t_beacon_info;

typedef struct s_data_info
{
	Mac		bssid_;
	Mac		station_;
	int8_t	power_;
	int8_t	rate_;
	int		frames_;
	char	probs_[32];
}	t_data_info;

#endif