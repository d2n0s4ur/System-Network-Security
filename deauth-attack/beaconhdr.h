#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct BeaconHdr final {
	// fixed
	u_int64_t	timestamp_;
	u_int16_t	beacon_interval_;
	u_int16_t	capability_info_;

	// variable

	u_int64_t	timestamp() const { return timestamp_; }
	u_int16_t	beacon_interval() const { return ntohs(beacon_interval_); }


	// tag numbers
	enum TAG {
		SSID = 0,
		SUPPORTED_RATES = 1,
		DSSS_PARAMETER_SET = 2,
		DS_PARAMETER_SET = 3,
		CF_PARAMETER_SET = 4,
		TIM = 5,
		IBSS_PARAMETER_SET = 6,
		COUNTRY = 7,
		POWER_CONSTRAINT = 32,
		IBSS_DFS = 41,
		EXTENDED_SUPPORTED_RATES = 50,
		RSN_IE = 48,
		QOS_CAPABILITY = 46,
		HT_CAPABILITY = 45,
		HT_OPERATION = 61,
		EXTENDED_CAPABILITY = 127,
		VENDOR_SPECIFIC = 221,
	};

	// enc
	enum ENC {
		WPA = 0x01,
		WPA2 = 0x02,
		WPA_WPA2 = 0x03,

	};

	// cipher
	enum CIPHER {
		CCMP = 0x04,
		TKIP = 0x02,
		WEP_40 = 0x01,
		WEP_104 = 0x05,
	};

	// akm
	enum AKM {
		DOT_1X = 0x01,
		PSK = 0x02	
	};
};
typedef BeaconHdr *PBeaconHdr;

#pragma pack(pop)