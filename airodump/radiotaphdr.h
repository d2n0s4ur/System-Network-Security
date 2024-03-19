#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct RadioTapHdr final {
	u_int8_t	version_;
	u_int8_t	pad_;
	u_int16_t	len_;
	u_int32_t	present_;

	enum PRESENT {
		DBM_ANTENNA_SIGNAL = 0x20,
		EXT = 0x80000000,
		RATE = 0x4,
	};
};

typedef RadioTapHdr *PRadioTapHdr;

#pragma pack(pop)