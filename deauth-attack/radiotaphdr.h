#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct RadioTapHdr final {
	u_int8_t	version_;
	u_int8_t	pad_;
	u_int16_t	len_;
	u_int32_t	present_;
	u_int8_t	data_rate_;
	u_int8_t	zero_;
	u_int16_t	tx_flag_;

	enum PRESENT {
		DBM_ANTENNA_SIGNAL = 0x20,
		EXT = 0x80000000,
		RATE = 0x4,
		TX_FLAG = 0x8000,
	};
};
typedef RadioTapHdr *PRadioTapHdr;
#pragma pack(pop)

#pragma pack(push, 1)
struct ExtendedRadioTapHdr final {
	u_int8_t	version_;
	u_int8_t	pad_;
	u_int16_t	len_;
	u_int32_t	present_1_;
	u_int32_t	present_2_;
	u_int8_t	flag_;
	u_int8_t	data_rate_;
	u_int16_t	channel_freq_;
	u_int16_t	channel_flags_;
	u_int8_t	antenna_sig_;
	u_int8_t	zero_;
	u_int16_t	rx_flag_;
	u_int8_t	antenna_;
	u_int8_t	zero_2_;

	enum PRESENT_1 {
		TIMESTAMP = 0x1,
		FLAGS = 0x2,
		RATE = 0x4,
		CHANNEL = 0x8,
		FHSS = 0x10,
		DBM_ANTENNA_SIGNAL = 0x20,
		DBM_ANTENNA_NOISE = 0x40,
		LOCK_QUALITY = 0x80,
		TX_ATTENUATION = 0x100,
		DB_TX_ATTENUATION = 0x200,
		DBM_TX_POWER = 0x400,
		ANTENNA = 0x800,
		DB_ANTENNA_SIGNAL = 0x1000,
		DB_ANTENNA_NOISE = 0x2000,
		RX_FLAGS = 0x4000,
		TX_FLAGS = 0x8000,
		RTS_RETRIES = 0x10000,
		DATA_RETRIES = 0x20000,
	};
	enum PRESENT_2 {
		EXT = 0x80000000,
	};
};
typedef ExtendedRadioTapHdr *PExtendedRadioTapHdr;
#pragma pack(pop)